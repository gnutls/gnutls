/*
 * Copyright (C) 2001, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *               
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *                               
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_extensions.h>
#include <gnutls_extra.h>
#include <gnutls_algorithms.h>
#ifdef USE_LZO
# ifdef USE_MINILZO
#  include "minilzo/minilzo.h"
# elif HAVE_LZO_LZO1X_H
#  include <lzo/lzo1x.h>
# elif HAVE_LZO1X_H
#  include <lzo1x.h>
# endif
#endif


/* the number of the compression algorithms available in the compression
 * structure.
 */
extern int _gnutls_comp_algorithms_size;

/* Functions in gnutls that have not been initialized.
 */
#ifdef USE_LZO
typedef int (*LZO_FUNC) ();
extern LZO_FUNC _gnutls_lzo1x_decompress_safe;
extern LZO_FUNC _gnutls_lzo1x_1_compress;

extern gnutls_compression_entry _gnutls_compression_algorithms[];

static int
_gnutls_add_lzo_comp (void)
{
  int i;

  /* find the last element */
  for (i = 0; i < _gnutls_comp_algorithms_size; i++)
    {
      if (_gnutls_compression_algorithms[i].name == NULL)
	break;
    }

  if (_gnutls_compression_algorithms[i].name == NULL
      && (i < _gnutls_comp_algorithms_size - 1))
    {
      _gnutls_compression_algorithms[i].name = "GNUTLS_COMP_LZO";
      _gnutls_compression_algorithms[i].id = GNUTLS_COMP_LZO;
      _gnutls_compression_algorithms[i].num = 0xf2;

      _gnutls_compression_algorithms[i + 1].name = 0;

      /* Now enable the lzo functions: */
      _gnutls_lzo1x_decompress_safe = lzo1x_decompress_safe;
      _gnutls_lzo1x_1_compress = lzo1x_1_compress;

      return 0;			/* ok */
    }


  return GNUTLS_E_MEMORY_ERROR;
}
#endif

static int _gnutls_init_extra = 0;

/**
  * gnutls_global_init_extra - This function initializes the global state of gnutls-extra 
  *
  * This function initializes the global state of gnutls-extra library
  * to defaults.  Returns zero on success.
  *
  * Note that gnutls_global_init() has to be called before this
  * function.  If this function is not called then the gnutls-extra
  * library will not be usable.
  *
  **/
int
gnutls_global_init_extra (void)
{
  int ret;

  /* If the version of libgnutls != version of
   * libextra, then do not initialize the library.
   * This is because it may break things.
   */
  if (strcmp (gnutls_check_version (NULL), VERSION) != 0)
    {
      return GNUTLS_E_LIBRARY_VERSION_MISMATCH;
    }

  _gnutls_init_extra++;

  if (_gnutls_init_extra != 1)
    {
      return 0;
    }

  /* Initialize the LZO library
   */
#ifdef USE_LZO
  if (lzo_init () != LZO_E_OK)
    {
      return GNUTLS_E_LZO_INIT_FAILED;
    }

  /* Add the LZO compression method in the list of compression
   * methods.
   */
  ret = _gnutls_add_lzo_comp ();
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
#endif

  return 0;
}

#include <strverscmp.h>

/**
 * gnutls_extra_check_version - This function checks the library's version
 * @req_version: the version to check
 *
 * Check that the version of the gnutls-extra library is at minimum
 * the requested one and return the version string; return NULL if the
 * condition is not satisfied.  If a NULL is passed to this function,
 * no check is done, but the version string is simply returned.
 *
 **/
const char *
gnutls_extra_check_version (const char *req_version)
{
  if (!req_version || strverscmp (req_version, VERSION) <= 0)
    return VERSION;

  return NULL;
}
