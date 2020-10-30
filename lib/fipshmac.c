/*
 * Copyright (C) 2020 Red Hat
 *
 * Author: Ondrej Moris
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "config.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HMAC_SIZE 32
#define HMAC_ALGO GNUTLS_MAC_SHA256

int main(int argc, char *argv[]) {
	gnutls_datum_t data = { NULL, 0 };
	gnutls_datum_t hex = { NULL, 0 };
	uint8_t buffer[HMAC_SIZE];
	gnutls_datum_t hmac = { buffer, sizeof(buffer) };
	int status = EXIT_FAILURE;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		goto error;
	}

	ret = gnutls_load_file(argv[1], &data);
	if (ret < 0) {
		fprintf(stderr, "Could not load %s: %s\n", argv[1],
			gnutls_strerror(ret));
		goto error;
	}

	GNUTLS_FIPS140_SET_LAX_MODE();

	ret = gnutls_hmac_fast(HMAC_ALGO, FIPS_KEY, sizeof(FIPS_KEY)-1,
			       data.data, data.size, buffer);
	if (ret < 0) {
		fprintf(stderr, "Could not calculate MAC on %s: %s\n", argv[1],
			gnutls_strerror(ret));
		goto error;
	}

	GNUTLS_FIPS140_SET_STRICT_MODE();

	ret = gnutls_hex_encode2(&hmac, &hex);
	if (ret < 0) {
		fprintf(stderr, "Could not encode MAC value: %s\n",
			gnutls_strerror(ret));
		goto error;
	}

	printf("%s\n", hex.data);

	status = EXIT_SUCCESS;

 error:
	gnutls_free(data.data);
	gnutls_free(hex.data);

	return status;
}
