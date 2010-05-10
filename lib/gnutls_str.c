/*
 * Copyright (C) 2002, 2004, 2005, 2007, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_str.h>
#include <stdarg.h>

/* These function are like strcat, strcpy. They only
 * do bound checking (they shouldn't cause buffer overruns),
 * and they always produce null terminated strings.
 *
 * They should be used only with null terminated strings.
 */
void
_gnutls_str_cat (char *dest, size_t dest_tot_size, const char *src)
{
  size_t str_size = strlen (src);
  size_t dest_size = strlen (dest);

  if (dest_tot_size - dest_size > str_size)
    {
      strcat (dest, src);
    }
  else
    {
      if (dest_tot_size - dest_size > 0)
	{
	  strncat (dest, src, (dest_tot_size - dest_size) - 1);
	  dest[dest_tot_size - 1] = 0;
	}
    }
}

void
_gnutls_str_cpy (char *dest, size_t dest_tot_size, const char *src)
{
  size_t str_size = strlen (src);

  if (dest_tot_size > str_size)
    {
      strcpy (dest, src);
    }
  else
    {
      if (dest_tot_size > 0)
	{
	  strncpy (dest, src, (dest_tot_size) - 1);
	  dest[dest_tot_size - 1] = 0;
	}
    }
}

void
_gnutls_mem_cpy (char *dest, size_t dest_tot_size, const char *src,
		 size_t src_size)
{

  if (dest_tot_size >= src_size)
    {
      memcpy (dest, src, src_size);
    }
  else
    {
      if (dest_tot_size > 0)
	{
	  memcpy (dest, src, dest_tot_size);
	}
    }
}

void
_gnutls_string_init (gnutls_string * str,
		     gnutls_alloc_function alloc_func,
		     gnutls_realloc_function realloc_func,
		     gnutls_free_function free_func)
{
  str->data = str->allocd = NULL;
  str->max_length = 0;
  str->length = 0;

  str->alloc_func = alloc_func;
  str->free_func = free_func;
  str->realloc_func = realloc_func;
}

void
_gnutls_string_clear (gnutls_string * str)
{
  if (str == NULL || str->allocd == NULL)
    return;
  str->free_func (str->allocd);

  str->data = str->allocd = NULL;
  str->max_length = 0;
  str->length = 0;
}

#define MIN_CHUNK 256

int
_gnutls_string_append_data (gnutls_string * dest, const void *data,
			    size_t data_size)
{
  size_t tot_len = data_size + dest->length;

  if (dest->max_length >= tot_len)
    {
      size_t unused = MEMSUB (dest->data, dest->allocd);

      if (dest->max_length - unused <= tot_len)
	{
	  if (dest->length && dest->data)
	    memmove (dest->allocd, dest->data, dest->length);

	  dest->data = dest->allocd;
	}
      memmove (&dest->data[dest->length], data, data_size);
      dest->length = tot_len;

      return tot_len;
    }
  else
    {
      size_t unused = MEMSUB (dest->data, dest->allocd);
      size_t new_len =
	MAX (data_size, MIN_CHUNK) + MAX (dest->max_length, MIN_CHUNK);

      dest->allocd = dest->realloc_func (dest->allocd, new_len);
      if (dest->allocd == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}
      dest->max_length = new_len;
      dest->data = dest->allocd + unused;

      if (dest->length && dest->data)
	memmove (dest->allocd, dest->data, dest->length);
      dest->data = dest->allocd;

      memcpy (&dest->data[dest->length], data, data_size);
      dest->length = tot_len;

      return tot_len;
    }
}

int
_gnutls_string_resize (gnutls_string * dest, size_t new_size)
{
  if (dest->max_length >= new_size)
    {
      size_t unused = MEMSUB (dest->data, dest->allocd);
      if (dest->max_length - unused <= new_size)
	{
	  if (dest->length && dest->data)
	    memmove (dest->allocd, dest->data, dest->length);
	  dest->data = dest->allocd;
	}

      return 0;
    }
  else
    {
      size_t unused = MEMSUB (dest->data, dest->allocd);
      size_t alloc_len =
	MAX (new_size, MIN_CHUNK) + MAX (dest->max_length, MIN_CHUNK);

      dest->allocd = dest->realloc_func (dest->allocd, alloc_len);
      if (dest->allocd == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}
      dest->max_length = alloc_len;
      dest->data = dest->allocd + unused;

      if (dest->length && dest->data)
	memmove (dest->allocd, dest->data, dest->length);
      dest->data = dest->allocd;

      return 0;
    }
}

int
_gnutls_string_append_str (gnutls_string * dest, const char *src)
{
  return _gnutls_string_append_data (dest, src, strlen (src));
}

/* returns data from a string in a constant buffer.
 * The data will NOT be valid if buffer is released or
 * data are appended in the buffer.
 */
void
_gnutls_string_get_datum (gnutls_string * str, gnutls_datum_t * data,
			  size_t req_size)
{

  if (str->length == 0)
    {
      data->data = NULL;
      data->size = 0;
      return;
    }

  if (req_size > str->length)
    req_size = str->length;

  data->data = str->data;
  data->size = req_size;

  str->data += req_size;
  str->length -= req_size;

  /* if string becomes empty start from begining */
  if (str->length == 0)
    {
      str->data = str->allocd;
    }

  return;
}

/* returns data from a string in a constant buffer.
 */
void
_gnutls_string_get_data (gnutls_string * str, void *data, size_t * req_size)
{
  gnutls_datum_t tdata;

  _gnutls_string_get_datum (str, &tdata, *req_size);

  *req_size = tdata.size;
  memcpy (data, tdata.data, tdata.size);

  return;
}

int
_gnutls_string_append_printf (gnutls_string * dest, const char *fmt, ...)
{
  va_list args;
  int len;
  char *str;

  va_start (args, fmt);
  len = vasprintf (&str, fmt, args);
  va_end (args);

  if (len < 0 || !str)
    return -1;

  len = _gnutls_string_append_str (dest, str);

  free (str);

  return len;
}

static int _gnutls_string_insert_data(gnutls_string * dest, int pos, const void* str, size_t str_size)
{
        size_t orig_length = dest->length;
        int ret;

        ret = _gnutls_string_resize(dest, dest->length+str_size); /* resize to make space */
        if (ret < 0)
                return ret;

        memmove(&dest->data[pos+str_size], &dest->data[pos], orig_length-pos);

        memcpy(&dest->data[pos], str, str_size);
        dest->length += str_size;

        return 0;
}

static void _gnutls_string_delete_data(gnutls_string * dest, int pos, size_t str_size)
{
        memmove(&dest->data[pos], &dest->data[pos+str_size], dest->length-pos-str_size);

        dest->length -= str_size;

        return;
}


int _gnutls_string_escape(gnutls_string * dest, const char *const invalid_chars)
{
        static const char *x = "0123456789ABCDEF";
        int rv = -1;
        char t[5];
        int pos = 0;

        /*_PKCS11H_ASSERT (target!=NULL); Not required*/

        while (pos < dest->length) {

                if (dest->data[pos] == '\\' || strchr(invalid_chars, dest->data[pos])
                    || !isgraph(dest->data[pos])) {

                        t[0] = '%';
                        t[1] = x[(dest->data[pos] & 0xf0) >> 4];
                        t[2] = x[(dest->data[pos] & 0x0f) >> 0];

                        _gnutls_string_delete_data(dest, pos, 1);

                        if (_gnutls_string_insert_data(dest, pos, t, 3) < 0) {
                                        rv = -1;
                                        goto cleanup;
                        }

                }
                pos++;
        }

        rv = 0;

    cleanup:

        return rv;
}

int _gnutls_string_unescape(gnutls_string * dest)
{
        int rv = -1;
        int pos = 0;

        /*_PKCS11H_ASSERT (target!=NULL); Not required*/

        while (pos < dest->length) {
                if (dest->data[pos] == '%') {
                        char b[3];
                        unsigned u;
                        char x;
                        b[0] = dest->data[pos+1];
                        b[1] = dest->data[pos+2];
                        b[2] = '\x0';

                        sscanf(b, "%08x", &u);
                        x = u & 0xff;
                        _gnutls_string_delete_data(dest, pos, 3);
                        _gnutls_string_insert_data(dest, pos, &x, 1);
                }
                pos++;
        }

        rv = 0;

    cleanup:

        return rv;
}


/* Converts the given string (old) to hex. A buffer must be provided
 * to hold the new hex string. The new string will be null terminated.
 * If the buffer does not have enough space to hold the string, a
 * truncated hex string is returned (always null terminated).
 */
char *
_gnutls_bin2hex (const void *_old, size_t oldlen,
		 char *buffer, size_t buffer_size, const char *separator)
{
  unsigned int i, j;
  const opaque *old = _old;
  int init = 0;
  int step = 2;
  const char empty[] = "";
  
  if (separator != NULL && separator[0] != 0)
    step = 3;
  else
    separator = empty;

  i = j = 0;
  sprintf (&buffer[j], "%.2x", old[i]);
  j+=2;
  i++;

  for (; i < oldlen && j + step < buffer_size; j += step)
    {
      sprintf (&buffer[j], "%s%.2x", separator, old[i]);
      i++;
    }
  buffer[j] = '\0';

  return buffer;
}

/**
 * gnutls_hex2bin:
 * @hex_data: string with data in hex format
 * @hex_size: size of hex data
 * @bin_data: output array with binary data
 * @bin_size: when calling *@bin_size should hold size of @bin_data,
 *            on return will hold actual size of @bin_data.
 *
 * Convert a buffer with hex data to binary data.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
 *
 * Since: 2.4.0
 **/
int
gnutls_hex2bin (const char *hex_data,
		size_t hex_size, char *bin_data, size_t * bin_size)
{
  return _gnutls_hex2bin (hex_data, (int) hex_size, bin_data, bin_size);
}

int
_gnutls_hex2bin (const opaque * hex_data, int hex_size, opaque * bin_data,
		 size_t * bin_size)
{
  int i, j;
  opaque hex2_data[3];
  unsigned long val;

  hex2_data[2] = 0;

  for (i = j = 0; i < hex_size;)
    {
        if (!isxdigit(hex_data[i])) /* skip non-hex such as the ':' in 00:FF */
          {
            i++;
            continue;
          }

        if (j > *bin_size) {
            gnutls_assert();
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }

        hex2_data[0] = hex_data[i];
        hex2_data[1] = hex_data[i + 1];
        i+=2;

        val = strtoul ((char *) hex2_data, NULL, 16);
        if (val == ULONG_MAX) {
            gnutls_assert ();
            return GNUTLS_E_PARSING_ERROR;
        }
        bin_data[j] = val;
        j++;
    }
  *bin_size = j;

  return 0;
}


/* compare hostname against certificate, taking account of wildcards
 * return 1 on success or 0 on error
 *
 * note: certnamesize is required as X509 certs can contain embedded NULs in
 * the strings such as CN or subjectAltName
 */
int
_gnutls_hostname_compare (const char *certname,
			  size_t certnamesize, const char *hostname)
{
  /* find the first different character */
  for (; *certname && *hostname && toupper (*certname) == toupper (*hostname);
       certname++, hostname++, certnamesize--)
    ;

  /* the strings are the same */
  if (certnamesize == 0 && *hostname == '\0')
    return 1;

  if (*certname == '*')
    {
      /* a wildcard certificate */

      certname++;
      certnamesize--;

      while (1)
	{
	  /* Use a recursive call to allow multiple wildcards */
	  if (_gnutls_hostname_compare (certname, certnamesize, hostname))
	    return 1;

	  /* wildcards are only allowed to match a single domain
	     component or component fragment */
	  if (*hostname == '\0' || *hostname == '.')
	    break;
	  hostname++;
	}

      return 0;
    }

  return 0;
}
