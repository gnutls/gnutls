/*
 * Copyright (C) 2014 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

void doit(void)
{
	int ret;
	gnutls_certificate_credentials_t xcred;
	const char *keyfile = "./certs/ecc256.pem";
	const char *certfile = "does-not-exist.pem";

	global_init();
	ret = gnutls_certificate_allocate_credentials(&xcred);

	/* this will fail */
	ret = gnutls_certificate_set_x509_key_file(xcred, certfile, keyfile,
						   GNUTLS_X509_FMT_PEM);
	if (ret != GNUTLS_E_FILE_ERROR)
		fail("set_x509_key_file failed: %s\n", gnutls_strerror(ret));

	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
}
