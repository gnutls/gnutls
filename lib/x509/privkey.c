/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>
#include <extensions.h>
#include <gnutls_privkey.h>

/**
  * gnutls_x509_privkey_init - This function initializes a gnutls_crl structure
  * @key: The structure to be initialized
  *
  * This function will initialize an private key structure. 
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_privkey_init(gnutls_x509_privkey * key)
{
	*key = gnutls_calloc( 1, sizeof(gnutls_x509_privkey_int));

	if (*key) {
		(*key)->pk_algorithm = GNUTLS_PK_UNKNOWN;
		return 0;		/* success */
	}

	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_privkey_deinit - This function deinitializes memory used by a gnutls_x509_privkey structure
  * @key: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_x509_privkey_deinit(gnutls_x509_privkey key)
{
int i;

	for (i = 0; i < key->params_size; i++) {
		_gnutls_mpi_release( &key->params[i]);
	}

	gnutls_free(key);
}

/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
static ASN1_TYPE decode_pkcs1_rsa_key( const gnutls_datum *raw_key, 
	gnutls_x509_privkey pkey) 
{
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	ASN1_TYPE pkey_asn;

	if ((result =
	     asn1_create_element(_gnutls_get_gnutls_asn(),
				   "GNUTLS.RSAPrivateKey", &pkey_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		return NULL;
	}

	if ((sizeof(pkey->params) / sizeof(GNUTLS_MPI)) < RSA_PRIVATE_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the GNUTLS_MPIs in params */
		return NULL;
	}

	result = asn1_der_decoding(&pkey_asn, raw_key->data, raw_key->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "modulus",
					    str, sizeof(str) - 1,
					    &pkey->params[0])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result =
	     _gnutls_x509_read_int(pkey_asn, "publicExponent", str,
				   sizeof(str) - 1,
				   &pkey->params[1])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result =
	     _gnutls_x509_read_int(pkey_asn, "privateExponent", str,
				   sizeof(str) - 1,
				   &pkey->params[2])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "prime1",
					    str, sizeof(str) - 1,
					    &pkey->params[3])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "prime2",
					    str, sizeof(str) - 1,
					    &pkey->params[4])) < 0) {
		gnutls_assert();
		goto error;
	}

#if 1
	/* Calculate the coefficient. This is because the gcrypt
	 * library is uses the p,q in the reverse order.
	 */
	pkey->params[5] =
	    _gnutls_mpi_snew(_gnutls_mpi_get_nbits(pkey->params[0]));

	if (pkey->params[5] == NULL) {
		gnutls_assert();
		goto error;
	}

	_gnutls_mpi_invm(pkey->params[5], pkey->params[3], pkey->params[4]);
	/*				p, q */
#else
	if ( (result=_gnutls_x509_read_int( pkey_asn, "coefficient",
		str, sizeof(str)-1, &pkey->params[5])) < 0) {
		gnutls_assert();
		goto error;
	}
#endif
	pkey->params_size = 6;

	return pkey_asn;

	error:
		asn1_delete_structure(&pkey_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		_gnutls_mpi_release(&pkey->params[4]);
		_gnutls_mpi_release(&pkey->params[5]);
		return NULL;

}

static ASN1_TYPE decode_dsa_key( const gnutls_datum* raw_key,
	gnutls_x509_privkey pkey) 
{
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	ASN1_TYPE dsa_asn;

	if ((result =
	     asn1_create_element(_gnutls_get_gnutls_asn(),
				   "GNUTLS.DSAPrivateKey", &dsa_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		return NULL;
	}

	if ((sizeof(pkey->params) / sizeof(GNUTLS_MPI)) < DSA_PRIVATE_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the GNUTLS_MPIs in params */
		return NULL;
	}

	result = asn1_der_decoding(&dsa_asn, raw_key->data, raw_key->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "p",
					    str, sizeof(str) - 1,
					    &pkey->params[0])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "q",
					    str, sizeof(str) - 1,
					    &pkey->params[1])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "g",
					    str, sizeof(str) - 1,
					    &pkey->params[2])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "Y",
					    str, sizeof(str) - 1,
					    &pkey->params[3])) < 0) {
		gnutls_assert();
		goto error;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "priv",
					    str, sizeof(str) - 1,
					    &pkey->params[4])) < 0) {
		gnutls_assert();
		goto error;
	}
	pkey->params_size = 5;

	return dsa_asn;

	error:
		asn1_delete_structure(&dsa_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		_gnutls_mpi_release(&pkey->params[4]);
		return NULL;

}


#define PEM_KEY_DSA "DSA PRIVATE"
#define PEM_KEY_RSA "RSA PRIVATE"

/**
  * gnutls_x509_privkey_import - This function will import a DER or PEM encoded Certificate
  * @key: The structure to store the parsed key
  * @data: The DER or PEM encoded certificate.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded Certificate
  * to the native gnutls_x509_privkey format. The output will be stored in 'key'.
  *
  * If the Certificate is PEM encoded it should have a header of "X509 CERTIFICATE", or
  * "CERTIFICATE" and must be a null terminated string.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_privkey_import(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	key->pk_algorithm = GNUTLS_PK_UNKNOWN;

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		/* Try the first header */
		result = _gnutls_fbase64_decode(PEM_KEY_RSA, data->data, data->size,
			&out);
		key->pk_algorithm = GNUTLS_PK_RSA;

		if (result <= 0) {
			/* try for the second header */
			result = _gnutls_fbase64_decode(PEM_KEY_DSA, data->data, data->size,
				&out);
			key->pk_algorithm = GNUTLS_PK_DSA;

			if (result <= 0) {
				if (result==0) result = GNUTLS_E_INTERNAL_ERROR;
				gnutls_assert();
				return result;
			}
		}
		
		_data.data = out;
		_data.size = result;
		
		need_free = 1;
	}

	if (key->pk_algorithm == GNUTLS_PK_RSA) {
		key->key = decode_pkcs1_rsa_key( &_data, key);
		if (key->key == NULL) {
			gnutls_assert();
			result = GNUTLS_E_ASN1_DER_ERROR;
			goto cleanup;
		}
	} else if (key->pk_algorithm == GNUTLS_PK_DSA) {
		key->key = decode_dsa_key( &_data, key);
		if (key->key == NULL) {
			gnutls_assert();
			result = GNUTLS_E_ASN1_DER_ERROR;
			goto cleanup;
		}
	} else {
		/* Try decoding with both, and accept the one that 
		 * succeeds.
		 */
		key->pk_algorithm = GNUTLS_PK_DSA;
		key->key = decode_dsa_key( &_data, key);

		if (key->key == NULL) {
			key->pk_algorithm = GNUTLS_PK_RSA;
			key->key = decode_pkcs1_rsa_key( &_data, key);
			if (key->key == NULL) {
				gnutls_assert();
				result = GNUTLS_E_ASN1_DER_ERROR;
				goto cleanup;
			}
		}
	}

	if (need_free) _gnutls_free_datum( &_data);

	/* The key has now been decoded.
	 */

	return 0;

      cleanup:
      	key->pk_algorithm = GNUTLS_PK_UNKNOWN;
	if (need_free) _gnutls_free_datum( &_data);
	return result;
}



/**
  * gnutls_x509_privkey_get_pk_algorithm - This function returns the key's PublicKey algorithm
  * @cert: should contain a gnutls_x509_privkey structure
  *
  * This function will return the public key algorithm of a private
  * key.
  *
  * Returns a member of the gnutls_pk_algorithm enumeration on success,
  * or a negative value on error.
  *
  **/
int gnutls_x509_privkey_get_pk_algorithm( gnutls_x509_privkey key)
{
        return key->pk_algorithm;
}
