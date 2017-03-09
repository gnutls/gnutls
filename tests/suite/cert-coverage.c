/*
 * Copyright (C) 2016-2017 Red Hat, Inc.
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
#include "config.h"
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

#include "utils.h"

/* This program will load certificates from CERT_DIR and try to print
 * them if they can be imported. The purpose of the certs is to increase
 * coverage in error paths.
 */

#define CERT_DIR "certs-coverage"

static int getnextcert(DIR **dirp, gnutls_datum_t *der)
{
	struct dirent *d;
	char path[256];
	char cert_dir[256];
	const char *src;
	int ret;

	src = getenv("srcdir");
	if (src == NULL)
		src = ".";

	snprintf(cert_dir, sizeof(cert_dir), "%s/%s", src, CERT_DIR);

	if (*dirp == NULL) {
		*dirp = opendir(cert_dir);
		if (*dirp == NULL)
			return -1;
	}

	do {
		d = readdir(*dirp);
		if (d != NULL
#ifdef _DIRENT_HAVE_D_TYPE
			&& d->d_type == DT_REG
#endif
			) {
			snprintf(path, sizeof(path), "%s/%s", cert_dir, d->d_name);

			success("Loading %s\n", path);
			ret = gnutls_load_file(path, der);
			if (ret < 0) {
				return -1;
			}

			return 0;
		}
	} while(d != NULL);

	closedir(*dirp);
	return -1; /* finished */
}

void doit(void)
{
	int ret;
	gnutls_x509_crt_t cert;
	gnutls_datum_t der;
	DIR *dirp = NULL;

	ret = global_init();
	if (ret < 0)
		fail("init %d\n", ret);

	while (getnextcert(&dirp, &der)==0) {
		ret = gnutls_x509_crt_init(&cert);
		if (ret < 0)
			fail("crt_init %d\n", ret);

		ret = gnutls_x509_crt_import(cert, &der, GNUTLS_X509_FMT_DER);

		if (ret == 0) {
			/* attempt to fully decode */
			gnutls_datum_t out;
			ret = gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &out);
			if (ret < 0) {
				fail("print: %s\n", gnutls_strerror(ret));
			}
			gnutls_free(out.data);
		}

		gnutls_x509_crt_deinit(cert);
		gnutls_free(der.data);
		der.data = NULL;
		der.size = 0;
	}

	gnutls_global_deinit();
}
