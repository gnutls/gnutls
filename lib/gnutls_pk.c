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

/* This file contains function for RSA/DSA etc. 
 */

#include <gnutls_int.h>
#include <gnutls_gcry.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_random.h>
#include <gnutls_datum.h>
#include "debug.h"

/* Do PKCS-1 RSA encryption. 
 * pkey is the public key and n the modulus.
 */

int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext, gnutls_datum plaintext,
		      MPI pkey, MPI n, int btype)
{
	int k, psize, i, ret;
	MPI m, res;
	opaque *edata, *ps;
	MPI *_pkey[2];

	k = gcry_mpi_get_nbits(n) / 8;

	if (plaintext.size > k - 11) {
		gnutls_assert();
		return GNUTLS_E_PK_ENCRYPTION_FAILED;
	}

	edata = gnutls_malloc(k);
	if (edata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* EB = 00||BT||PS||00||D 
	 * (use block type 'btype')
	 */

	edata[0] = 0;
	edata[1] = btype;
	psize = k - 3 - plaintext.size;

	ps = &edata[2];
	_gnutls_get_random(ps, psize, GNUTLS_WEAK_RANDOM);
	for (i = 0; i < psize; i++) {
		if (ps[i] == 0)
			ps[i] = 0xff;
	}
	ps[psize] = 0;
	memcpy(&ps[psize + 1], plaintext.data, plaintext.size);

	if (gcry_mpi_scan(&m, GCRYMPI_FMT_USG, edata, &k) != 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	gnutls_free(edata);

	_pkey[0] = &n;
	_pkey[1] = &pkey;
	ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, m, _pkey);
	_gnutls_mpi_release(&m);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &psize, res);

	ciphertext->data = gnutls_malloc(psize);
	if (ciphertext->data == NULL) {
		gnutls_assert();
		gcry_mpi_release(res);
		return GNUTLS_E_MEMORY_ERROR;
	}
	gcry_mpi_print(GCRYMPI_FMT_USG, ciphertext->data, &psize, res);
	ciphertext->size = psize;

	gcry_mpi_release(res);

	return 0;
}


/* Do PKCS-1 RSA decryption. 
 * pkey is the private key and n the modulus.
 */

int _gnutls_pkcs1_rsa_decrypt(gnutls_datum * plaintext, gnutls_datum ciphertext,
		      MPI pkey, MPI n, int btype)
{
	int k, esize, i, ret;
	MPI c, res;
	opaque *edata;
	MPI *_pkey[2];

	k = gcry_mpi_get_nbits(n) / 8;
	esize = ciphertext.size;

	if (esize!=k) {
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}
	
	if (gcry_mpi_scan(&c, GCRYMPI_FMT_USG, ciphertext.data, &esize) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	_pkey[0] = &n;
	_pkey[1] = &pkey;

	ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, c, _pkey);
	gcry_mpi_release(c);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &esize, res);
	edata = gnutls_malloc(esize+1);
	if (edata == NULL) {
		gnutls_assert();
		gcry_mpi_release(res);
		return GNUTLS_E_MEMORY_ERROR;
	}
	gcry_mpi_print(GCRYMPI_FMT_USG, &edata[1], &esize, res);

	gcry_mpi_release(res);

	/* EB = 00||BT||PS||00||D 
	 * (use block type 'btype')
	 */

	edata[0] = 0;
	esize++;

	if (edata[0] != 0 || edata[1] != btype) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_DECRYPTION_FAILED;
	}

	ret = GNUTLS_E_DECRYPTION_FAILED;
	for (i=2;i<esize;i++) {
		if (edata[i]==0) { 
			ret = 0;
			break;
		}
	}
	i++;
	
	if (ret < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	
	if (gnutls_sset_datum( plaintext, &edata[i], esize - i) < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	gnutls_free(edata);

	return 0;
}

/* this is taken from gnupg 
 */

/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int _gnutls_pk_encrypt(int algo, MPI * resarr, MPI data, MPI **pkey)
{
	GCRY_SEXP s_ciph, s_data, s_pkey;
	int rc;

	/* make a sexp from pkey */
	if (algo == GCRY_PK_RSA) {
		rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(rsa(n%m)(e%m)))",
				     *pkey[0], *pkey[1]);
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* put the data into a simple list */
	if (gcry_sexp_build(&s_data, NULL, "%m", data)) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
		
	} else {		/* add better error handling or make gnupg use S-Exp directly */
		GCRY_SEXP list = gcry_sexp_find_token(s_ciph, "a", 0);
		if (list == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_ciph);
			return GNUTLS_E_UNKNOWN_ERROR;
		}

		resarr[0] = gcry_sexp_nth_mpi(list, 1, 0);
		gcry_sexp_release(list);

		if (resarr[0] == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_ciph);
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}

	gcry_sexp_release(s_ciph);
	return rc;
}
