/*
 *  Copyright (C) 2001,2002,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/* This file contains the functions needed for RSA/DSA public key
 * encryption and signatures. 
 */

#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_random.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_num.h>
#include "debug.h"
#include <x509/mpi.h>

static int _gnutls_pk_encrypt(int algo, GNUTLS_MPI * resarr, GNUTLS_MPI data, GNUTLS_MPI * pkey, int pkey_len);
static int _gnutls_pk_sign(int algo, GNUTLS_MPI* data, GNUTLS_MPI hash, GNUTLS_MPI * pkey, int);
static int _gnutls_pk_verify(int algo, GNUTLS_MPI hash, GNUTLS_MPI* data, GNUTLS_MPI *pkey, int);
static int _gnutls_pk_decrypt(int algo, GNUTLS_MPI * resarr, GNUTLS_MPI data, GNUTLS_MPI * pkey, int);


/* Do PKCS-1 RSA encryption. 
 * params is modulus, public exp.
 */
int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext,
			      const gnutls_datum *plaintext, GNUTLS_MPI* params,
			      uint params_len,
			      uint btype)
{
	unsigned int i, pad;
	int ret;
	GNUTLS_MPI m, res;
	opaque *edata, *ps;
	size_t k, psize;
	size_t mod_bits;

	mod_bits = _gnutls_mpi_get_nbits(params[0]);	
	k = mod_bits / 8;
	if ( mod_bits % 8 != 0) k++;

	if (plaintext->size > k - 11) {
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
	psize = k - 3 - plaintext->size;

	ps = &edata[2];
	switch (btype) {
	case 2:
		/* using public key */
		if (params_len < RSA_PUBLIC_PARAMS) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		
		if ( (ret=_gnutls_get_random(ps, psize, GNUTLS_STRONG_RANDOM)) < 0) {
			gnutls_assert();
			return ret;
		}
		for (i = 0; i < psize; i++) {
			opaque rnd[3];

			/* Read three random bytes that will be
			 * used to replace the zeros.
			 */
			if ( (ret=_gnutls_get_random( rnd, 3, GNUTLS_STRONG_RANDOM)) < 0) {
				gnutls_assert();
				return ret;
			}
			/* use non zero values for 
			 * the first two.
			 */
			if (rnd[0]==0) rnd[0] = 0xaf;
			if (rnd[1]==0) rnd[1] = 0xae;

			if (ps[i] == 0) {
				/* If the first one is zero then set it to rnd[0].
				 * If the second one is zero then set it to rnd[1].
				 * Otherwise add (mod 256) the two previous ones plus rnd[3], or use
				 * rnd[1] if the value == 0.
				 */
				if (i<2) ps[i] = rnd[i];
				else ps[i] = GMAX( rnd[3] + ps[i-1] + ps[i-2], rnd[1]);
			}
		}
		break;
	case 1:
		/* using private key */

		if (params_len < RSA_PRIVATE_PARAMS) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		
		for (i = 0; i < psize; i++)
			ps[i] = 0xff;
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ps[psize] = 0;
	memcpy(&ps[psize + 1], plaintext->data, plaintext->size);

	if (_gnutls_mpi_scan(&m, edata, &k) != 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	gnutls_free(edata);

	if (btype==2) /* encrypt */
		ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, m, params, params_len);
	else /* sign */
		ret = _gnutls_pk_sign(GCRY_PK_RSA, &res, m, params, params_len);

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
		/* This is an impossible situation */
		gnutls_assert();
		_gnutls_mpi_release(&res);
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
int _gnutls_pkcs1_rsa_decrypt(gnutls_datum * plaintext,
			      gnutls_datum ciphertext, GNUTLS_MPI* params, uint params_len,
			      uint btype)
{
	uint k, i;
	int ret;
	GNUTLS_MPI c, res;
	opaque *edata;
	size_t esize, mod_bits;

	mod_bits = _gnutls_mpi_get_nbits(params[0]);	
	k = mod_bits / 8;
	if ( mod_bits % 8 != 0) k++;

	esize = ciphertext.size;

	if (esize != k) {
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}

	if (_gnutls_mpi_scan(&c, ciphertext.data, &esize) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* we can use btype to see if the private key is
	 * available.
	 */
	if (btype==2)
		ret = _gnutls_pk_decrypt(GCRY_PK_RSA, &res, c, params, params_len);
	else {
		ret = _gnutls_pk_encrypt(GCRY_PK_RSA, &res, c, params, params_len);
	}
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
		return GNUTLS_E_INTERNAL_ERROR;
	}
	i++;

	if (ret < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_DECRYPTION_FAILED;
	}

	if (_gnutls_sset_datum(plaintext, &edata[i], esize - i) < 0) {
		gnutls_assert();
		gnutls_free(edata);
		return GNUTLS_E_MEMORY_ERROR;
	}

	gnutls_free(edata);

	return 0;
}


int _gnutls_rsa_verify( const gnutls_datum* vdata, const gnutls_datum *ciphertext, 
	GNUTLS_MPI *params, int params_len, int btype) {

	gnutls_datum plain;
	int ret;

	/* decrypt signature */
	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &plain, *ciphertext, params, params_len, btype)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	if (plain.size != vdata->size) {
		gnutls_assert();
		_gnutls_free_datum( &plain);
		return GNUTLS_E_PK_SIG_VERIFY_FAILED;
	}

	if ( memcmp(plain.data, vdata->data, plain.size)!=0) {
		gnutls_assert();
		_gnutls_free_datum( &plain);
		return GNUTLS_E_PK_SIG_VERIFY_FAILED;
	}

	_gnutls_free_datum( &plain);

	return 0; /* ok */
}

/* encodes the Dss-Sig-Value structure
 */
static int encode_ber_rs( gnutls_datum* sig_value, GNUTLS_MPI r, GNUTLS_MPI s) {
ASN1_TYPE sig;
int result, tot_len;

	if ((result=asn1_create_element( _gnutls_get_gnutls_asn(), "GNUTLS.DSASignatureValue", 
		&sig))!=ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_write_int( sig, "r", r, 1);
	if ( result < 0) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return result;
	}

	result = _gnutls_x509_write_int( sig, "s", s, 1);
	if (result < 0) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return result;
	}

	tot_len = 0;
	result = asn1_der_coding( sig, "", NULL, &tot_len, NULL);
	if (result != ASN1_MEM_ERROR) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return _gnutls_asn2err(result);
	}

	sig_value->size = tot_len;
	sig_value->data = gnutls_malloc( sig_value->size);
	if (sig_value->data==NULL) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_der_coding( sig, "", sig_value->data, &sig_value->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return _gnutls_asn2err(result);
	}

	asn1_delete_structure(&sig);
		
	return 0;
}


/* Do DSA signature calculation. params is p, q, g, y, x in that order.
 */
int _gnutls_dsa_sign(gnutls_datum * signature, const gnutls_datum *hash,
		     GNUTLS_MPI * params, uint params_len)
{
	GNUTLS_MPI rs[2], mdata;
	int ret;
	size_t k;

	k = hash->size;
	if (k!=20) { /* SHA only */
		gnutls_assert();
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	if (_gnutls_mpi_scan(&mdata, hash->data, &k) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret = _gnutls_pk_sign(GCRY_PK_DSA, rs, mdata, params, params_len);
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
static int decode_ber_rs( const gnutls_datum* sig_value, GNUTLS_MPI* r, GNUTLS_MPI* s) {
ASN1_TYPE sig;
int result;

	if ((result=asn1_create_element( _gnutls_get_gnutls_asn(), "GNUTLS.DSASignatureValue", &sig))!=ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding( &sig, sig_value->data, sig_value->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return _gnutls_asn2err(result);
	}
	
	result =
	    _gnutls_x509_read_int( sig, "r", r);
	if (result < 0) {
		gnutls_assert();
		asn1_delete_structure(&sig);
		return result;
	}

	result =
	    _gnutls_x509_read_int( sig, "s", s);
	if (result < 0) {
		gnutls_assert();
		_gnutls_mpi_release( s);
		asn1_delete_structure(&sig);
		return result;
	}

	asn1_delete_structure(&sig);
		
	return 0;
}

/* params is p, q, g, y in that order
 */
int _gnutls_dsa_verify( const gnutls_datum* vdata, const gnutls_datum *sig_value, 
	GNUTLS_MPI * params, int params_len) {

	GNUTLS_MPI mdata;
	int ret;
	size_t k;
	GNUTLS_MPI rs[2];

	if (vdata->size != 20) { /* sha-1 only */
		gnutls_assert();
		return GNUTLS_E_PK_SIG_VERIFY_FAILED;
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
	if ( (ret=_gnutls_pk_verify( GCRY_PK_DSA, mdata, rs, params, 
		params_len)) < 0) {
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
static int _gnutls_pk_encrypt(int algo, GNUTLS_MPI * resarr, GNUTLS_MPI data, GNUTLS_MPI * pkey, int pkey_len)
{
	gcry_sexp_t s_ciph, s_data, s_pkey;
	int rc=-1;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_RSA:
		if (pkey_len >= 2)
			rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(rsa(n%m)(e%m)))",
				     pkey[0], pkey[1]);
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
	if (gcry_sexp_build(&s_data, NULL, "%m", data)) {
		gnutls_assert();
		gcry_sexp_release(s_pkey);
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_ENCRYPTION_FAILED;

	} else {		/* add better error handling or make gnupg use S-Exp directly */
		gcry_sexp_t list = gcry_sexp_find_token(s_ciph, "a", 0);
		if (list == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_ciph);
			return GNUTLS_E_INTERNAL_ERROR;
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

static 
int _gnutls_pk_decrypt(int algo, GNUTLS_MPI * resarr, GNUTLS_MPI data, GNUTLS_MPI * pkey, int pkey_len)
{
	gcry_sexp_t s_plain, s_data, s_pkey;
	int rc=-1;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_RSA:
		if (pkey_len >=6)
			rc = gcry_sexp_build(&s_pkey, NULL,
				     "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
				     pkey[0], pkey[1], pkey[2], pkey[3], pkey[4], pkey[5]);

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
	if (gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", data)) {
		gnutls_assert();
		gcry_sexp_release(s_pkey);
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_decrypt(&s_plain, s_data, s_pkey);
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;

	} else { /* add better error handling or make gnupg use S-Exp directly */
		resarr[0] = gcry_sexp_nth_mpi(s_plain, 0, 0);

		if (resarr[0] == NULL) {
			gnutls_assert();
			gcry_sexp_release(s_plain);
			return GNUTLS_E_INTERNAL_ERROR;
		}
	}

	gcry_sexp_release(s_plain);
	return rc;
}


/* in case of DSA puts into data, r,s
 */
static 
int _gnutls_pk_sign(int algo, GNUTLS_MPI* data, GNUTLS_MPI hash, GNUTLS_MPI * pkey, int pkey_len)
{
	gcry_sexp_t s_hash, s_key, s_sig;
	int rc=-1;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_DSA:
		if (pkey_len >= 5)
			rc = gcry_sexp_build(&s_key, NULL,
				     "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
				     pkey[0], pkey[1], pkey[2],
				     pkey[3], pkey[4]);
		else {
			gnutls_assert(); 
		}

		break;
	case GCRY_PK_RSA:
		if (pkey_len >=6)
			rc = gcry_sexp_build(&s_key, NULL,
				     "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
				     pkey[0], pkey[1], pkey[2], pkey[3], pkey[4], pkey[5]);
		else {
			gnutls_assert();
		}
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
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_sign(&s_sig, s_hash, s_key);
	gcry_sexp_release(s_hash);
	gcry_sexp_release(s_key);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGN_FAILED;

	} else {
		gcry_sexp_t list;
		
		if (algo==GCRY_PK_DSA) {
			list = gcry_sexp_find_token( s_sig, "r" , 0);
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
		} else { /* GCRY_PK_RSA */
			list = gcry_sexp_find_token( s_sig, "s" , 0);
			if (list == NULL) {
				gnutls_assert();
				gcry_sexp_release(s_sig);
				return GNUTLS_E_INTERNAL_ERROR;
			}

			data[0] = gcry_sexp_nth_mpi( list, 1, 0 );
			gcry_sexp_release (list);
		}
	}

	gcry_sexp_release(s_sig);
	return 0;
}


static int _gnutls_pk_verify(int algo, GNUTLS_MPI hash, GNUTLS_MPI* data, GNUTLS_MPI *pkey, int pkey_len)
{
	gcry_sexp_t s_sig, s_hash, s_pkey;
	int rc=-1;

	/* make a sexp from pkey */
	switch (algo) {
	case GCRY_PK_DSA:
		if (pkey_len >= 4)
			rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
				     pkey[0], pkey[1], pkey[2], pkey[3]);
		break;
	case GCRY_PK_RSA:
		if (pkey_len >= 2)
			rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(rsa(n%m)(e%m)))",
				     pkey[0], pkey[1]);
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
		return GNUTLS_E_INTERNAL_ERROR;
	}

	switch (algo) {
	case GCRY_PK_DSA:
		rc = gcry_sexp_build(&s_sig, NULL,
				     "(sig-val(dsa(r%m)(s%m)))",
				     data[0], data[1]);
		break;
	case GCRY_PK_RSA:
		rc = gcry_sexp_build(&s_sig, NULL,
				     "(sig-val(rsa(s%m)))",
				     data[0]);
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

	rc = gcry_pk_verify( s_sig, s_hash, s_pkey);
	
	gcry_sexp_release(s_sig);
	gcry_sexp_release(s_hash);
	gcry_sexp_release(s_pkey);

	if (rc != 0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIG_VERIFY_FAILED;
	}

	return 0;
}
