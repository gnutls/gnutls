/*
 * Copyright (C) 2020 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

/* Parts copied from other tests */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include <gnutls/ct.h>

#include "utils.h"

static char cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIE3jCCA8agAwIBAgISBEtVhuk7RxyWV1/xsIgmnuSHMA0GCSqGSIb3DQEBCwUA\n"
	"MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n"
	"EwJSMzAeFw0yMzA4MjgxMzE0MTJaFw0yMzExMjYxMzE0MTFaMBMxETAPBgNVBAMT\n"
	"CGFjbHUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDygo7VN\n"
	"BmXtFwzTO4lckRg9T+cDRpqa9uiDZO/u9tAaqTjDLmrVTWvyzm/cLfbUg7g7Lzmw\n"
	"WWUDGNvL6GyncSSwbBrjcMwhN1YHO4EiZIFNWxFE70zwz0kEB60C8fBZFuRT2Txl\n"
	"1f/RYYqu3AE2+GzT6QNzW0u+YPriVuQSAsZ9WdiTzbcQ15kkr9/csB4KUqyxIxSL\n"
	"g92nBxiWZFDYCb3KTIPtJV2nHR7jqNHRSUZcZCEywC0LzTTvjNYXsQvDLz+uVWT/\n"
	"GIxw1KnV5hQOE/ereXW5F/S6Q6TkT4zXIroCC5vmpAbTjXAdcEts5wDKIzaXwXFA\n"
	"vI1zjIYJnTnFPQIDAQABo4ICCzCCAgcwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\n"
	"MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS/\n"
	"bQv3RR5MPS83Dx9V0n9N5DzinTAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+d\n"
	"ixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxl\n"
	"bmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzATBgNV\n"
	"HREEDDAKgghhY2x1Lm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATCCAQUGCisGAQQB\n"
	"1nkCBAIEgfYEgfMA8QB3AHoyjFTYty22IOo44FIe6YQWcDIThU070ivBOlejUutS\n"
	"AAABijx+uFwAAAQDAEgwRgIhAOLm96SxEpWZY5jpLnKA4CxX4cNs2YXOucmR5cEJ\n"
	"jCjMAiEA1kTDJhU34JI8ZlpSg3GG3Bc8CW+QNFrIKF3QaOjWuKoAdgDoPtDaPvUG\n"
	"NTLnVyi8iWvJA9PL0RFr7Otp4Xd9bQa9bgAAAYo8frh8AAAEAwBHMEUCIH41H+jo\n"
	"SGBXoSr0NyFFyxawuEJ+RJcdaebbBQ2BOj4hAiEAsIZWvii6SV28vIY28cVt05I8\n"
	"FEcPEzKJXamQHXdFE30wDQYJKoZIhvcNAQELBQADggEBAKERGihYJJhGalo70L5C\n"
	"sG9zziVPwkB6sn9XrIQgz0HEoXcSNWmUXA61IjqKiV90esdcfuJHt4uHBhvLjBgg\n"
	"3W5h1wDJTOKXjZf5vyTHQbTdUg3wFewv0zLY3zpYPUdh0WQzJNDiipl8eDLdpS7u\n"
	"vuTNwePhQrzBAlKh1ZsJNnyNp78Eyg90v9x4CW49CCIBxw0JfFVqlplt72U8Am2+\n"
	"bhpBFq40/ye9DUUtMkJiAS2NIm8aAviWAUAQq/wJ3sgpwlT9aw9RWaRxUcKnl6yk\n"
	"vnSSb2e/wk5Cnj7di1xIOmdwfSMGwQ5az6+LaFHBb4jzDB+S1QkSy5B4zYwMSm8t\n"
	"hhU=\n"
	"-----END CERTIFICATE-----\n";

static char issuer_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\n"
	"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
	"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\n"
	"WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\n"
	"RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
	"AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\n"
	"R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\n"
	"sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\n"
	"NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\n"
	"Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n"
	"/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\n"
	"AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\n"
	"Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\n"
	"FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\n"
	"AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\n"
	"Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\n"
	"gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\n"
	"PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\n"
	"ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\n"
	"CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\n"
	"lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\n"
	"avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\n"
	"yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\n"
	"yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\n"
	"hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\n"
	"HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\n"
	"MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\n"
	"nLRbwHOoq7hHwg==\n"
	"-----END CERTIFICATE-----\n";

static void verify_scts(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
			gnutls_x509_ct_scts_t x509_cert_scts,
			gnutls_ct_logs_t ct_logs_store)
{
	int retval;
	char *log_name;
	time_t timestamp;
	gnutls_datum_t log_id, sig;
	gnutls_sign_algorithm_t sigalg;
	gnutls_ct_sct_t sct;

	retval = gnutls_x509_ct_sct_get(x509_cert_scts, 1,
					&timestamp, &log_id, &sigalg, &sig);
	if (retval == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		fail("gnutls_x509_ct_sct_get: GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE");
	if (retval < 0)
		fail("gnutls_x509_ct_sct_get failed");

	retval = gnutls_ct_sct_init(&sct,
				    &log_id, sigalg, &sig, timestamp);
	if (retval < 0)
		fail("gnutls_ct_sct_init failed");

	retval = gnutls_ct_verify(sct, cert, issuer, ct_logs_store, &log_name);
	if (retval == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		fail("gnutls_ct_verify: GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE");
	if (retval < 0)
		fail("gnutls_ct_verify failed");
	if (strcmp(log_name, "argon2023"))
		fail("Unexpected log name");
}

static gnutls_x509_ct_scts_t read_scts_from_certificate(const gnutls_datum_t *ext)
{
	int ret;
	gnutls_x509_ct_scts_t scts;

	ret = gnutls_x509_ext_ct_scts_init(&scts);
	if (ret < 0)
		fail("gnutls_x509_ext_ct_scts_init");

	ret = gnutls_x509_ext_ct_import_scts(ext, scts, 0);
	if (ret < 0)
		fail("gnutls_x509_ext_ct_import_scts");

	return scts;
}

static gnutls_ct_logs_t initialize_logs_store(void)
{
	int retval;
	gnutls_ct_logs_t logs_store;
	gnutls_ct_log_t log;
	const char *name = "argon2023";
	const char *b64key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==";
	const gnutls_datum_t key = {
		.size = strlen(b64key),
		.data = b64key
	};

	if ((retval = gnutls_ct_logs_init(&logs_store)) < 0) {
		return NULL;
	}

	if ((retval = gnutls_ct_log_init(&log, name, &key, GNUTLS_CT_KEY_AS_BASE64)) < 0) {
		gnutls_ct_logs_deinit(logs_store);
		return NULL;
	}

	if ((retval = gnutls_ct_add_log(logs_store, log)) < 0) {
		gnutls_ct_logs_deinit(logs_store);
		return NULL;
	}

	return logs_store;
}

#define MAX_DATA_SIZE 1024

void doit(void)
{
	int ret;
	size_t oidlen;
	char oid[MAX_DATA_SIZE];
	gnutls_x509_crt_t cert, issuer;
	gnutls_x509_ct_scts_t x509_scts;
	gnutls_datum_t ext, xpem;
	gnutls_ct_logs_t logs_store;

	global_init();
	if (debug)
		gnutls_global_set_log_level(5);

	gnutls_x509_crt_init(&cert);
	gnutls_x509_crt_init(&issuer);

	xpem.data = (void *) cert_pem;
	xpem.size = sizeof(cert_pem) - 1;
	ret = gnutls_x509_crt_import(cert, &xpem, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("gnutls_x509_crt_import");

	xpem.data = (void *) issuer_pem;
	xpem.size = sizeof(issuer_pem) - 1;
	ret = gnutls_x509_crt_import(issuer, &xpem, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("gnutls_x509_crt_import");

	for (unsigned i = 0;; i++) {
		oidlen = MAX_DATA_SIZE;

		ret = gnutls_x509_crt_get_extension_oid(cert, i, oid, &oidlen);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (ret < 0)
			fail("gnutls_x509_crt_get_extension_oid");

		if (strcmp(oid, GNUTLS_X509EXT_OID_CT_SCT_V1) == 0) {
			ret = gnutls_x509_crt_get_extension_data2(cert, i,
								  &ext);
			if (ret < 0)
				fail("gnutls_x509_crt_get_extension_data2");
			x509_scts = read_scts_from_certificate(&ext);
			gnutls_free(ext.data);
			break;
		}
	}

	if (x509_scts == NULL)
		fail("SCT extension not found\n");

	if ((logs_store = initialize_logs_store()) == NULL)
		fail("Logs store could not be initialized");

	verify_scts(cert, issuer, x509_scts, logs_store);

	gnutls_x509_ext_ct_scts_deinit(x509_scts);
	gnutls_x509_crt_deinit(cert);
	gnutls_x509_crt_deinit(issuer);

	gnutls_global_deinit();
	if (debug)
		success("success");
}
