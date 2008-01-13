/* misc.c
 *        Copyright (C) 2002, 2003 Timo Schulz
 *        Copyright (C) 1998-2002, 2007 Free Software Foundation, Inc.
 *
 * This file is part of OpenCDK.
 *
 * The OpenCDK library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"


u32
_cdk_buftou32 (const byte *buf)
{
  u32 u;
  
  if (!buf)
    return 0;
  u  = buf[0] << 24;
  u |= buf[1] << 16;
  u |= buf[2] <<  8;
  u |= buf[3];
  return u;
}


void
_cdk_u32tobuf (u32 u, byte *buf)
{
  if (!buf)
    return;
  buf[0] = u >> 24;
  buf[1] = u >> 16;
  buf[2] = u >>  8;
  buf[3] = u      ;
}


static const char *
parse_version_number (const char *s, int *number)
{
  int val = 0;
  
  if (*s == '0' && isdigit (s[1]))
    return NULL;
  /* leading zeros are not allowed */
  for (; isdigit(*s); s++)
    {
      val *= 10;
      val += *s - '0';     
    }
  *number = val;
  return val < 0? NULL : s;
}


static const char *
parse_version_string (const char * s, int * major, int * minor, int * micro)
{
  s = parse_version_number( s, major );
  if( !s || *s != '.' )
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number(s, micro);
  if (!s)
    return NULL;
  return s; /* patchlevel */
}


/**
 * cdk_check_version:
 * @req_version: The requested version
 *
 * Check that the the version of the library is at minimum the requested
 * one and return the version string; return NULL if the condition is
 * not satisfied.  If a NULL is passed to this function, no check is done,
 *but the version string is simply returned.
 **/
const char *
cdk_check_version (const char *req_version)
{
  const char *ver = VERSION;
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;
  
  if (!req_version)
    return ver;
  my_plvl = parse_version_string (ver, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;
  /* very strange our own version is bogus */
  rq_plvl = parse_version_string (req_version, &rq_major, &rq_minor,
				  &rq_micro);
  if (!rq_plvl)
    return NULL;  /* req version string is invalid */
  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro
	  && strcmp (my_plvl, rq_plvl) >= 0))
    return ver;
  return NULL;
}


/**
 * cdk_strlist_free:
 * @sl: the string list
 * 
 * Release the string list object.
 **/
void
cdk_strlist_free (cdk_strlist_t sl)
{
  cdk_strlist_t sl2;
  
  for(; sl; sl = sl2)
    {
      sl2 = sl->next;
      cdk_free (sl);
    }
}


/**
 * cdk_strlist_add:
 * @list: destination string list
 * @string: the string to add
 * 
 * Add the given list to the string list.
 **/
cdk_strlist_t
cdk_strlist_add (cdk_strlist_t *list, const char *string)
{
  cdk_strlist_t sl;
  
  if (!string)
    return NULL;
  
  sl = cdk_calloc (1, sizeof *sl + strlen (string) + 1);
  if (!sl)
    return NULL;
  strcpy (sl->d, string);
  sl->next = *list;
  *list = sl;
  return sl;
}


/**
 * cdk_strlist_next:
 * @root: the opaque string list.
 * @r_str: optional argument to store the string data.
 * 
 * Return the next string list node from @root. The optional
 * argument @r_str return the data of the current (!) node.
 **/
cdk_strlist_t
cdk_strlist_next (cdk_strlist_t root, const char **r_str)
{
  cdk_strlist_t node;

  if (root && r_str)
    *r_str = root->d;
  for (node = root->next; node; node = node->next)
    return node;

  return NULL;
}


const char*
_cdk_memistr (const char *buf, size_t buflen, const char *sub)
{
  const byte *t, *s;
  size_t n;
  
  for (t = (byte*)buf, n = buflen, s = (byte*)sub ; n ; t++, n--) 
    {
      if (toupper (*t) == toupper (*s)) 
	{
	  for (buf = t++, buflen = n--, s++;
	       n && toupper (*t) == toupper ((byte)*s); t++, s++, n--)
	    ;
	  if (!*s)
	    return buf;
	  t = (byte*)buf;
	  n = buflen;
	  s = (byte*)sub;   
        }
    }
  
  return NULL;
}


/* Map the gcrypt error to a valid opencdk error constant. */
cdk_error_t
_cdk_map_gcry_error (gcry_error_t err)
{
  /* FIXME: We need to catch them all. */
  switch (gpg_err_code (err))
    {
    case GPG_ERR_NO_ERROR: return CDK_Success;
    case GPG_ERR_INV_VALUE: return CDK_Inv_Value;
    case GPG_ERR_GENERAL: return CDK_General_Error;
    case GPG_ERR_INV_PACKET: return CDK_Inv_Packet;
    case GPG_ERR_TOO_SHORT: return CDK_Too_Short;
    case GPG_ERR_TOO_LARGE: return CDK_Inv_Value;
    case GPG_ERR_NO_PUBKEY:
    case GPG_ERR_NO_SECKEY: return CDK_Error_No_Key;
    case GPG_ERR_BAD_SIGNATURE: return CDK_Bad_Sig;
    case GPG_ERR_NO_DATA: return CDK_No_Data;
    default:
      break;
    }
  
  return (cdk_error_t)err;
}


/* Remove all trailing white spaces from the string. */
void
_cdk_trim_string (char *s, int canon)
{
  while (s && *s &&
	 (s[strlen (s)-1] == '\t' ||
	  s[strlen (s)-1] == '\r' ||
	  s[strlen (s)-1] == '\n' ||
	  s[strlen (s)-1] == ' '))
    s[strlen (s) -1] = '\0';
  if (canon)
    strcat (s, "\r\n");
}


int
_cdk_check_args (int overwrite, const char *in, const char *out)
{
  struct stat stbuf;
  
  if (!in || !out)
    return CDK_Inv_Value;
  if (strlen (in) == strlen (out) && strcmp (in, out) == 0)
    return CDK_Inv_Mode;
  if (!overwrite && !stat (out, &stbuf))
    return CDK_Inv_Mode;
  return 0;
}

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>

FILE *
my_tmpfile (void)
{
  /* Because the tmpfile() version of wine is not really useful,
     we implement our own version to avoid problems with 'make check'. */
  static const char *letters = "abcdefghijklmnopqrstuvwxyz";
  char buf[512], rnd[24];
  FILE *fp;
  int fd, i;
  
  gcry_create_nonce (rnd, DIM (rnd));
  for (i=0; i < DIM (rnd)-1; i++)
    {
      char c = letters[(unsigned char)rnd[i] % 26];
      rnd[i] = c;
    }
  rnd[DIM (rnd)-1]=0;
  if (!GetTempPath (464, buf))
    return NULL;
  strcat (buf, "_cdk_");
  strcat (buf, rnd);
  
  /* We need to make sure the file will be deleted when it is closed. */
  fd = _open (buf, _O_CREAT | _O_EXCL | _O_TEMPORARY |
	      _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
  if (fd == -1)
    return NULL;
  fp = fdopen (fd, "w+b");
  if (fp != NULL)
    return fp;
  _close (fd);
  return NULL;
}
#else
FILE*
my_tmpfile (void)
{
  return tmpfile ();
}
#endif
