/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#include <gnutls/pkcs11.h>
#include <gnutls/x509.h>

#include "utils.h"

void
doit (void)
{
  int ret;
  gnutls_x509_crt_t *ca_list;
  unsigned int ncas, i;

  ret = gnutls_global_init ();
  if (ret < 0)
    fail ("gnutls_global_init failed %d\n", ret);

  ret = gnutls_pkcs11_get_ca_certificates (&ca_list, &ncas);
  if (ret < 0)
    fail ("Error getting CAs from PKCS#11: %d\n", ret);
  else
    {
      for (i = 0; i < ncas; i++)
	{
	  gnutls_datum_t out;

	  success ("Certificate %d - ", i);

	  ret = gnutls_x509_crt_print (ca_list[i], GNUTLS_X509_CRT_FULL, &out);
	  if (ret < 0)
	    fail ("gnutls_x509_crt_print: %d\n", ret);

	  fwrite (out.data, 1, out.size, stdout);

	  gnutls_free (out.data);

	  gnutls_x509_crt_deinit (ca_list[i]);
	}

      gnutls_free (ca_list);
    }

  gnutls_global_deinit ();
}
