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
#include <gnutls_global.h>
#include <x509_der.h>
#include "debug.h"

static int _gnutls_pk_sign(int algo, MPI* data, MPI hash, MPI * pkey);
static int _gnutls_pk_verify(int algo, MPI hash, MPI* data, MPI *pkey);


/* Do PKCS-1 RSA encryption. 
 * params is modulus, public exp.
 */
int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext,
			      gnutls_datum plaintext, MPI* params,
			      int btype)
{
	int k, psize, i, ret, pad;
	MPI m, res;
	opaque *edata, *ps;
	MPI tmp_params[RSA_PARAMS];

	k = gcry_mpi_get_nbits(params[0]) / 8;

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
	switch (btype) {
	case 2:
		/* using public key */
		tmp_params[0] = params[0];
		tmp_params[1] = params[1];
		
		if ( (ret=_gnutls_get_random(ps, psize, GNUTLS_WEAK_RANDOM)) < 0) {
			gnutls_assert();
			return ret;
		}
		for (i = 0; i < psize; i++) {
			if (ps[i] == 0)
				ps[i] = 0xff;
		}
		break;
	case 1:
		/* using private key */
		tmp_params[0] = params[0];
		tmp_params[1] = params[2];
		
		for (i = 0; i < psize; i++)
			ps[i] = 0xff;
		break;
#ifdef ALLOW_BLOCK_0
	case 0:
		for (i = 0; i < psize; i++) {
			ps[i] = 0x00;
		}
		break;
#endif
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	ps[psize] = 0;
	memcpy(&ps[psize + 1], plaintext.data, plaintext.size);

	if (_gnutls_mpi_scan(&m, edata, &k) != 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	gnutls_free(edata);

	ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, m, tmp_params);
	_gnutls_mpi_release(&m);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_mpi_print(NULL, &psize, res);
	if (psize < k) {
		/* padding psize */
		pad = k - psize;
		psize = k;
	} else if (psize==k) {
		pad = 0;
	} else { /* psize > k !!! */
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ciphertext->data = gnutls_malloc(psize);
	if (ciphertext->data == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&res);
		return GNUTLS_E_MEMORY_ERROR;
	}
	_gnutls_mpi_print( &ciphertext->data[pad], &psize, res);
	for (i=0;i<pad;i++) ciphertext->data[i] = 0;

	ciphertext->size = k;

	_gnutls_mpi_release(&res);

	return 0;
}


/* Do PKCS-1 RSA decryption. 
 * params is modulus, public exp., private key
 * Can decrypt block type 1 and type 2 packets.
 */
int _gnutls_pkcs1_rsa_decrypt(gnutls_sdatum * plaintext,
			      gnutls_datum ciphertext, MPI* params,
			      int btype)
{
	int k, esize, i, ret;
	MPI c, res;
	opaque *edata;

	k = gcry_mpi_get_nbits(params[0]) / 8;
	esize = ciphertext.size;

	if (esize != k) {
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}

	if (_gnutls_mpi_scan(&c, ciphertext.data, &esize) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, c, params);
	_gnutls_mpi_release(&c);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_mpi_print(NULL, &esize, res);
	edata = gnutls_malloc(esize + 1);
	if (edata == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&res);
		return GNUTLS_E_MEMORY_ERROR;
	}
	_gnutls_mpi_print(&edata[1], &esize, res);

	_gnutls_mpi_release(&res);

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
	switch (btype) {
	case 2:
		for (i = 2; i < esize; i++) {
			if (edata[i] == 0) {
				ret = 0;
				break;
			}
		}
		break;
	case 1:
		for (i = 2; i < esize; i++) {
			if (edata[i] == 0 && i > 2) {
				ret = 0;
				break;
			}
			if (edata[i] != 0xff) {
				ret = GNUTLS_E_PKCS1_WRONG_PAD;
				break;
			}
		}
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
	i++;

	if (ret < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_DECRYPTION_FAILED;
	}

	if (gnutls_sset_datum(plaintext, &edata[i], esize - i) < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MEMORY_ERROR;
	}

	gnutls_free(edata);

	return 0;
}


int _gnutls_rsa_verify( const gnutls_datum* vdata, const gnutls_datum *ciphertext, 
	MPI *params, int btype) {

	gnutls_datum plain;
	int ret;

	/* decrypt signature */
	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &plain, *ciphertext, params, btype)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	if (plain.size != vdata->size) {
		gnutls_assert();
		gnutls_sfree_datum( &plain);
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	if ( memcmp(plain.data, vdata->data, plain.size)!=0) {
		gnutls_assert();
		gnutls_sfree_datum( &plain);
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	gnutls_sfree_datum( &plain);

	return 0; /* ok */
}

/* encodes the Dss-Sig-Value structure
 */
static int encode_ber_rs( gnutls_datum* sig_value, MPI r, MPI s) {
node_asn* sig;
int result;
opaque str[MAX_PARAMETER_SIZE];
int len = sizeof(str);
int tot_len = 0;

	if ((result=asn1_create_structure( _gnutls_get_gnutls_asn(), "GNUTLS.DSASignatureValue", 
		&sig, "sig"))!=ASN_OK) {
		gnutls_assert();
		return result;
	}

	if ( _gnutls_mpi_print_lz( str, &len, r) < 0) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	tot_len += len;
	
	result = asn1_write_value( sig, "sig.r", str, len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return result;
	}

	len = sizeof(str) - 1;
	if ( _gnutls_mpi_print_lz( str, &len, s) < 0) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	tot_len += len;

	result = asn1_write_value( sig, "sig.s", str, len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return result;
	}

	sig_value->size = tot_len + 100;
	sig_value->data = gnutls_malloc( sig_value->size);
	if (sig_value->data==NULL) {
		gnutls_assert();
		asn1_delete_structure(sig);
	}

	result = asn1_create_der( sig, "sig", sig_value->data, &sig_value->size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return result;
	}

	asn1_delete_structure(sig);
		
	return 0;
}


/* Do DSA signature calculation. params is p, q, g, y, x in that order.
 */
int _gnutls_dsa_sign(gnutls_datum * signature, const gnutls_datum *hash,
		     MPI * params)
{
	MPI rs[2], mdata;
	int k, ret;

	k = hash->size;
	if (k!=20) { /* SHA only */
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	if (_gnutls_mpi_scan(&mdata, hash->data, &k) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret = _gnutls_pk_sign(GCRY_PK_DSA, rs, mdata, params);
	/* res now holds r,s */
	_gnutls_mpi_release(&mdata);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (encode_ber_rs( signature, rs[0], rs[1])!=0) {
		gnutls_assert();
		_gnutls_mpi_release(&rs[0]);
		_gnutls_mpi_release(&rs[1]);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* free r,s */
	_gnutls_mpi_release(&rs[0]);
	_gnutls_mpi_release(&rs[1]);

	return 0;
}

/* decodes the Dss-Sig-Value structure
 */
static int decode_ber_rs( const gnutls_datum* sig_value, MPI* r, MPI* s) {
node_asn* sig;
int result;
opaque str[MAX_PARAMETER_SIZE];


	if ((result=asn1_create_structure( _gnutls_get_gnutls_asn(), "GNUTLS.DSASignatureValue", &sig, "sig"))!=ASN_OK) {
		gnutls_assert();
		return result;
	}

	result = asn1_get_der( sig, sig_value->data, sig_value->size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return result;
	}
	
	result =
	    _gnutls_x509_read_int( sig, "sig.r", str, sizeof(str)-1, r);
	if (result < 0) {
		gnutls_assert();
		asn1_delete_structure(sig);
		return result;
	}

	result =
	    _gnutls_x509_read_int( sig, "sig.s", str, sizeof(str)-1, s);
	if (result < 0) {
		gnutls_assert();
		_gnutls_mpi_release( s);
		asn1_delete_structure(sig);
		return result;
	}

	asn1_delete_structure(sig);
		
	return 0;
}

/* params is p, q, g, y in that order
 */
int _gnutls_dsa_verify( const gnutls_datum* vdata, const gnutls_datum *sig_value, 
	MPI * params) {

	MPI mdata;
	int ret, k;
	MPI rs[2];

	if (vdata->size != 20) { /* sha-1 only */
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	if (decode_ber_rs( sig_value, &rs[0], &rs[1])!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	k = vdata->size;
	if (_gnutls_mpi_scan(&mdata, vdata->data, &k) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* decrypt signature */
	if ( (ret=_gnutls_pk_verify( GCRY_PK_DSA, mdata, rs, params)) < 0) {
	    _gnutls_mpi_release(&mdata);
	     gnutls_assert();
	     return ret;
	}
	_gnutls_mpi_release(&mdata);

	return 0; /* ok */
}


/* this is taken from gnupg 
 */

/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int _gnutls_pk_encrypt(int algo, MPI * resarr, MPI data, MPI * pkey)
{
	GCRY_SEXP s_ciph, s_data, s_pkey;
	int rc;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_RSA:
		rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(rsa(n%m)(e%m)))",
				     pkey[0], pkey[1]);
		break;

	default:
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
		gcry_sexp_release(s_pkey);
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_ENCRYPTION_FAILED;

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
			return GNUTLS_E_INTERNAL_ERROR;
		}
	}

	gcry_sexp_release(s_ciph);
	return rc;
}

/* in case of DSA puts into data, r,s
 */
static 
int _gnutls_pk_sign(int algo, MPI* data, MPI hash, MPI * pkey)
{
	GCRY_SEXP s_hash, s_key, s_sig;
	int rc;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_DSA:
		rc = gcry_sexp_build(&s_key, NULL,
				     "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
				     pkey[0], pkey[1], pkey[2],
				     pkey[3], pkey[4]);
		break;

	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* put the data into a simple list */
	if (gcry_sexp_build(&s_hash, NULL, "%m", hash)) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_sign(&s_sig, s_hash, s_key);
	gcry_sexp_release(s_hash);
	gcry_sexp_release(s_key);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;

	} else {
		GCRY_SEXP list = gcry_sexp_find_token( s_sig, "r" , 0);
		if (list == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_sig);
			return GNUTLS_E_INTERNAL_ERROR;
		}

		data[0] = gcry_sexp_nth_mpi( list, 1, 0 );
		gcry_sexp_release (list);
		
		list = gcry_sexp_find_token( s_sig, "s" , 0);
		if (list == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_sig);
			return GNUTLS_E_INTERNAL_ERROR;
		}

		data[1] = gcry_sexp_nth_mpi( list, 1, 0 );
		gcry_sexp_release (list);

	}

	gcry_sexp_release(s_sig);
	return 0;
}


static int _gnutls_pk_verify(int algo, MPI hash, MPI* data, MPI *pkey)
{
	GCRY_SEXP s_sig, s_hash, s_pkey;
	int rc;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_DSA:
		rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
				     pkey[0], pkey[1], pkey[2], pkey[3]);
		break;

	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* put the data into a simple list */
	if (gcry_sexp_build(&s_hash, NULL, "%m", hash)) {
		gnutls_assert();
		gcry_sexp_release(s_pkey);
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	switch (algo) {
	case GCRY_PK_DSA:
		rc = gcry_sexp_build(&s_sig, NULL,
				     "(sig-val(dsa(r%m)(s%m)))",
				     data[0], data[1]);
		break;

	default:
		gnutls_assert();
		gcry_sexp_release(s_pkey);
		gcry_sexp_release(s_hash);
		return GNUTLS_E_INTERNAL_ERROR;
	}

	if (rc != 0) {
		gnutls_assert();
		gcry_sexp_release(s_pkey);
		gcry_sexp_release(s_hash);
		return GNUTLS_E_INTERNAL_ERROR;
	}

	rc = gcry_pk_verify( s_sig, s_hash, s_pkey );
	
	gcry_sexp_release(s_sig);
	gcry_sexp_release(s_hash);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	return 0;
}
