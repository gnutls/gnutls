/*
 * Copyright (C) 2016 Red Hat, Inc.
 * Copyright 2016 Alex Gaynor, Google Inc.
 *
 * Author: Nikos Mavrogiannopoulos, Alex Gaynor
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
#include <stdint.h>
#include <limits.h>
#include <dirent.h>

#include "utils.h"

#define true 1

/* This program will load certificates from CERT_DIR and try to print
 * them. If CERT_DIR/certname.err is available, it should contain the
 * error code that gnutls_x509_crt_import() should return.
 */

#define CERT_DIR "client-interesting"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int getnext(DIR **dirp, gnutls_datum_t *der)
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
			if (strstr(d->d_name, ".raw") == 0)
				continue;
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

#include "../devel/fuzz/gnutls_client_fuzzer.cc"

void doit(void)
{
	int ret;
	gnutls_datum_t raw;
	DIR *dirp = NULL;

	ret = global_init();
	if (ret < 0)
		fail("init %d\n", ret);

	while (getnext(&dirp, &raw)==0) {
		LLVMFuzzerTestOneInput(raw.data, raw.size);
		gnutls_free(raw.data);
		raw.data = NULL;
		raw.size = 0;
	}

	gnutls_global_deinit();
}
