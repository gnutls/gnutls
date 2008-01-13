/* hash.c - Hash filters
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
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
#include <assert.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"

static cdk_error_t
hash_encode (void *opaque, FILE *in, FILE *out)
{
  md_filter_t *mfx = opaque;
  byte buf[BUFSIZE];
  gcry_error_t err;
  int nread;
  
  if (!mfx)
    return CDK_Inv_Value;
  
  _cdk_log_debug ("hash filter: encode algo=%d\n", mfx->digest_algo);
  
  if (!mfx->md)
    {
      err = gcry_md_open (&mfx->md, mfx->digest_algo, 0);
      if (err)
	return map_gcry_error (err);
    }
  
  while (!feof (in))
    {
      nread = fread (buf, 1, BUFSIZE, in);
      if (!nread)
	break;
      gcry_md_write (mfx->md, buf, nread);
    }
  
  wipemem (buf, sizeof (buf));
  return 0;
}

cdk_error_t
_cdk_filter_hash (void *opaque, int ctl, FILE *in, FILE *out)
{
  if (ctl == STREAMCTL_READ)
    return hash_encode (opaque, in, out);
  else if (ctl == STREAMCTL_FREE)
    {
      md_filter_t *mfx = opaque;
      if (mfx) 
	{
	  _cdk_log_debug ("free hash filter\n");
	  gcry_md_close (mfx->md);
	  mfx->md = NULL;
	  return 0;
        }   
    }
  return CDK_Inv_Mode;
}
