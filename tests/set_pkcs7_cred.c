/*
 * Copyright (C) 2006, 2007, 2008  Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include "utils.h"

static char p7crts[] =
  "-----BEGIN PKCS7-----\n"
  "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\n"
  "9CWR6g==\n"
  "-----END PKCS7-----\n";

/* Test import of PKCS#7 certificate chains, reported by Christian
   Grothoff <christian@grothoff.org> in
   <https://gnunet.org/mantis/view.php?id=1417> and
   <https://gnunet.org/mantis/view.php?id=1418>. */

void
doit (void)
{
  int rc;
  gnutls_certificate_credentials_t crt;
  gnutls_datum_t p7crtsdatum = { p7crts, strlen (p7crts) };

  rc = gnutls_global_init ();
  if (rc)
    {
      fail ("gnutls_global_init rc %d: %s\n", rc, gnutls_strerror (rc));
      return;
    }

  rc = gnutls_certificate_allocate_credentials (&crt);
  if (rc)
    {
      fail ("gnutls_certificate_allocate_credentials rc %d: %s\n",
	    rc, gnutls_strerror (rc));
      return;
    }

  rc = gnutls_certificate_set_x509_key_mem (crt, &p7crtsdatum, NULL,
					    GNUTLS_X509_FMT_PEM);
  if (rc != 2)
    {
      fail ("gnutls_certificate_set_x509_crt_mem num %d\n", rc);
      return;
    }

  success ("gnutls_certificate_set_x509_key_mem on a pkcs7 struct OK (%d)\n",
	   rc);

  gnutls_certificate_free_credentials (crt);

  gnutls_global_deinit ();
}
