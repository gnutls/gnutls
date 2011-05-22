/*
 * Copyright (C) 2001, 2004, 2005, 2007, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS-EXTRA.
 *
 * GnuTLS-extra is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * GnuTLS-extra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_extensions.h>
#include <algorithms.h>
#include <gnutls/extra.h>

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif

static int _gnutls_init_extra = 0;

/**
 * gnutls_global_init_extra:
 *
 * This function initializes the global state of gnutls-extra library
 * to defaults.
 *
 * Note that gnutls_global_init() has to be called before this
 * function.  If this function is not called then the gnutls-extra
 * library will not be usable.
 *
 * This function is not thread safe, see the discussion for
 * gnutls_global_init() on how to deal with that.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (zero) is returned,
 *   otherwise an error code is returned.
 **/
int
gnutls_global_init_extra (void)
{
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
    return 0;

#ifdef HAVE_GCRYPT
#ifdef gcry_fips_mode_active
  /* Libgcrypt manual says that gcry_version_check must be called
     before calling gcry_fips_mode_active. */
  gcry_check_version (NULL);
  if (gcry_fips_mode_active ())
    {
      int ret;

      ret = gnutls_register_md5_handler ();
      if (ret)
        fprintf (stderr, "gnutls_register_md5_handler: %s\n",
                 gnutls_strerror (ret));
    }
#endif
#endif

  return 0;
}

/**
 * gnutls_extra_check_version:
 * @req_version: version string to compare with, or %NULL.
 *
 * Check GnuTLS Extra Library version.
 *
 * See %GNUTLS_EXTRA_VERSION for a suitable @req_version string.
 *
 * Return value: Check that the version of the library is at
 *   minimum the one given as a string in @req_version and return the
 *   actual version string of the library; return %NULL if the
 *   condition is not met.  If %NULL is passed to this function no
 *   check is done and only the version string is returned.
 **/
const char *
gnutls_extra_check_version (const char *req_version)
{
  if (!req_version || strverscmp (req_version, VERSION) <= 0)
    return VERSION;

  return NULL;
}
