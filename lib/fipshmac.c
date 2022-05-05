/*
 * Copyright (C) 2020-2022 Red Hat, Inc.
 *
 * Authors: Ondrej Moris, Zoltan Fridrich
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
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "dirname.h"
#include "errors.h"

#define FORMAT_VERSION 1
#define HMAC_SIZE 32
#define HMAC_ALGO GNUTLS_MAC_SHA256
#define HMAC_STR_SIZE (2 * HMAC_SIZE + 1)

static int get_path(const char *lib, const char *symbol, char *path, size_t path_size)
{
	int ret;
	void *dl, *sym;
	Dl_info info;

	dl = dlopen(lib, RTLD_LAZY);
	if (dl == NULL)
		return gnutls_assert_val(GNUTLS_E_FILE_ERROR);

	sym = dlsym(dl, symbol);
	if (sym == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_FILE_ERROR);
		goto cleanup;
	}

	ret = dladdr(sym, &info);
	if (ret == 0) {
		ret = gnutls_assert_val(GNUTLS_E_FILE_ERROR);
		goto cleanup;
	}

	ret = snprintf(path, path_size, "%s", info.dli_fname);
	if ((size_t)ret >= path_size) {
		ret = gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);
		goto cleanup;
	}

	ret = 0;
cleanup:
	dlclose(dl);
	return ret;
}

static int get_hmac(const char *path, char *hmac, size_t hmac_size)
{
	int ret;
	size_t size;
	uint8_t buffer[HMAC_SIZE];
	gnutls_datum_t hex = { buffer, sizeof(buffer) };
	gnutls_datum_t data = { NULL, 0 };

	ret = gnutls_load_file(path, &data);
	if (ret < 0)
		return gnutls_assert_val(ret);

	GNUTLS_FIPS140_SET_LAX_MODE();
	ret = gnutls_hmac_fast(HMAC_ALGO, FIPS_KEY, sizeof(FIPS_KEY) - 1,
                               data.data, data.size, buffer);
	GNUTLS_FIPS140_SET_STRICT_MODE();

	gnutls_free(data.data);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size = hmac_size;
	ret = gnutls_hex_encode(&hex, hmac, &size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

static int print_lib_path(const char *path)
{
	int ret;
	char hmac[HMAC_STR_SIZE];

	ret = get_hmac(path, hmac, sizeof(hmac));
	if (ret < 0) {
		fprintf(stderr, "Could not calculate HMAC for %s: %s\n",
                        last_component(path), gnutls_strerror(ret));
		return ret;
	}

	printf("[%s]\n", last_component(path));
	printf("path = %s\n", path);
	printf("hmac = %s\n", hmac);

	return 0;
}

static int print_lib_dl(const char *lib, const char *sym)
{
	int ret;
	char path[GNUTLS_PATH_MAX];

	ret = get_path(lib, sym, path, sizeof(path));
	if (ret < 0) {
		fprintf(stderr, "Could not get lib path for %s: %s\n",
                        lib, gnutls_strerror(ret));
		return ret;
	}

	return print_lib_path(path);
}

int main(int argc, char **argv)
{
	int ret;

	if (argc != 1 && argc != 2) {
		fprintf(stderr, "Usage: %s [gnutls_so_path]\n", last_component(argv[0]));
		return EXIT_FAILURE;
	}

	printf("[global]\n");
	printf("format-version = %d\n", FORMAT_VERSION);

	if (argc == 2)
		ret = print_lib_path(argv[1]);
	else
		ret = print_lib_dl(GNUTLS_LIBRARY_SONAME, "gnutls_global_init");
	if (ret < 0)
		return EXIT_FAILURE;

	ret = print_lib_dl(NETTLE_LIBRARY_SONAME, "nettle_aes_set_encrypt_key");
	if (ret < 0)
		return EXIT_FAILURE;
	
	ret = print_lib_dl(HOGWEED_LIBRARY_SONAME, "nettle_mpz_sizeinbase_256_u");
	if (ret < 0)
		return EXIT_FAILURE;
	
	ret = print_lib_dl(GMP_LIBRARY_SONAME, "__gmpz_init");
	if (ret < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
