/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <defines.h>
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <cert_b64.h>
#include <auth_x509.h>

/* FIXME: this function is a mess 
 */
int gnutls_read_certs(X509PKI_SERVER_CREDENTIALS * res, char *CERTFILE,
		      char *KEYFILE)
{
	FILE *fd1, *fd2;
	char x[100 * 1024];
	int siz;
	opaque *b64;

	fd1 = fopen(CERTFILE, "r");
	if (fd1 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	fd2 = fopen(KEYFILE, "r");
	if (fd2 == NULL) {
		fclose(fd1);
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	siz = fread(x, 1, sizeof(x), fd1);
	siz = _gnutls_fbase64_decode(x, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	res->cert_list = (gnutls_datum**) gnutls_malloc(1*sizeof(gnutls_datum*));
	if (res->cert_list == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->cert_list[0] = (gnutls_datum*) gnutls_malloc(1*sizeof(gnutls_datum));
	if (res->cert_list[0] == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->cert_list_length = (int*) gnutls_malloc(1*sizeof(int*));
	if (res->cert_list_length == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->ncerts = 1;

	res->cert_list_length[0] = 1;

	res->cert_list[0][0].data = b64;
	res->cert_list[0][0].size = siz;

	fclose(fd1);




/* second file */

	siz = fread(x, 1, sizeof(x), fd2);
	siz = _gnutls_fbase64_decode(x, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	res->pkey = gnutls_malloc(1*sizeof(gnutls_datum));
	if (res->pkey == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->pkey[0].data = b64;
	res->pkey[0].size = siz;

	fclose(fd2);

	return 0;
}
