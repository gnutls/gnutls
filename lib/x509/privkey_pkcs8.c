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
#include <gnutls_rsa_export.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>
#include <pkcs5.h>
#include <privkey.h>
#include <extensions.h>
#include <mpi.h>
#include <gnutls_algorithms.h>

struct pbkdf2_params {
	opaque salt[32];
	int salt_size;
	int iter_count;
	int key_size;
};

struct pbe_enc_params {
	opaque iv[8];
	int iv_size;
};

static int read_pbkdf2_params( ASN1_TYPE pbes2_asn, const gnutls_datum* der, 
	struct pbkdf2_params* params);
static int read_pbe_enc_params( ASN1_TYPE pbes2_asn, const gnutls_datum* der, 
	struct pbe_enc_params* params);
static int decrypt_data( ASN1_TYPE pkcs8_asn, char* password,
	const struct pbkdf2_params* kdf_params, const struct pbe_enc_params *enc_params, 
	gnutls_datum* decrypted_data);
static ASN1_TYPE decode_private_key_info( const gnutls_datum* der, gnutls_x509_privkey pkey);

#define PEM_PKCS8 "ENCRYPTED PRIVATE KEY"

/**
  * gnutls_x509_privkey_export_pkcs8 - This function will export the private key to PKCS8 format
  * @key: Holds the key
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a private key PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the private key to a PKCS8 structure.
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN ENCRYPTED PRIVATE KEY".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_x509_privkey_export( gnutls_x509_privkey key,
	gnutls_x509_crt_fmt format, unsigned char* output_data, int* output_data_size)
{
// NOT YET READY
	return _gnutls_x509_export_int( key->key, format, PEM_PKCS8, *output_data_size,
		output_data, output_data_size);
}


#define PBES2_OID "1.2.840.113549.1.5.13"
#define PBKDF2_OID "1.2.840.113549.1.5.12"
#define DES_EDE3_CBC_OID "1.2.840.113549.3.7"

/* oid_pbeWithSHAAnd3_KeyTripleDES_CBC */
#define PBE_3DES_SHA1_OID "1.2.840.113549.1.12.1.3"

/* Converts a PKCS#8 key to
 * an internal structure (gnutls_private_key)
 */
static ASN1_TYPE decode_pkcs8_key( const gnutls_datum *raw_key, 
	char* password, gnutls_x509_privkey pkey)
{
	int result, len;
	opaque enc_oid[64];
	gnutls_datum tmp;
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY, pkcs8_asn = ASN1_TYPE_EMPTY;
	ASN1_TYPE ret_asn;
	int params_start, params_end, params_len;
	struct pbkdf2_params kdf_params;
	struct pbe_enc_params enc_params;


	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.EncryptedPrivateKeyInfo", &pkcs8_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	result = asn1_der_decoding(&pkcs8_asn, raw_key->data, raw_key->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	/* Check the encryption schema OID
	 */
	len = sizeof(enc_oid);
	result = asn1_read_value( pkcs8_asn, "encryptionAlgorithm.algorithm", enc_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	/* we only support PBES2 
	 */
	if (strcmp( enc_oid, PBES2_OID) != 0) {
		gnutls_assert();
		_gnutls_x509_log( "PKCS #8 encryption schema OID '%s' is unsupported.\n", enc_oid);
		goto error;
	}

	/* Get the DER encoding of the parameters.
	 */
	result = asn1_der_decoding_startEnd( pkcs8_asn, raw_key->data, raw_key->size,
		"encryptionAlgorithm.parameters", &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}
	params_len = params_end - params_start + 1;

	/* Now check the key derivation and the encryption
	 * functions.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.pkcs-5-PBES2-params", &pbes2_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		return NULL;
	}

	/* Decode the parameters.
	 */
	result = asn1_der_decoding(&pbes2_asn, &raw_key->data[params_start], params_len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	tmp.data = &raw_key->data[params_start];
	tmp.size = params_len;

	result = read_pbkdf2_params( pbes2_asn, &tmp, &kdf_params);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = read_pbe_enc_params( pbes2_asn, &tmp, &enc_params);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}
	
	asn1_delete_structure( &pbes2_asn);


	/* Parameters have been decoded. Now
	 * decrypt the EncryptedData.
	 */
	result = decrypt_data( pkcs8_asn, password, &kdf_params, &enc_params, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	asn1_delete_structure(&pkcs8_asn);

	ret_asn = decode_private_key_info( &tmp, pkey);
	_gnutls_free_datum( &tmp);

	return ret_asn;

	error:
		asn1_delete_structure(&pbes2_asn);
		asn1_delete_structure(&pkcs8_asn);
		return NULL;
}

static ASN1_TYPE decode_private_key_info( const gnutls_datum* der, gnutls_x509_privkey pkey)
{
	int result, len;
	opaque oid[64], *data = NULL;
	gnutls_datum tmp;
	ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;
	ASN1_TYPE ret_asn;
	int data_size;


	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.PrivateKeyInfo", &pkcs8_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	result = asn1_der_decoding(&pkcs8_asn, der->data, der->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	/* Check the private key algorithm OID
	 */
	len = sizeof(oid);
	result = asn1_read_value( pkcs8_asn, "privateKeyAlgorithm.algorithm", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	/* we only support RSA private keys.
	 */
	if (strcmp( oid, PKIX1_RSA_OID) != 0) {
		gnutls_assert();
		_gnutls_x509_log( "PKCS #8 private key OID '%s' is unsupported.\n", oid);
		goto error;
	}

	/* Get the DER encoding of the actual private key.
	 */
	data_size = 0;
	result = asn1_read_value( pkcs8_asn, "privateKey", NULL, &data_size);
	if (result != ASN1_MEM_ERROR) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	data = gnutls_alloca( data_size);
	if (data == NULL) {
		gnutls_assert();
		result = GNUTLS_E_MEMORY_ERROR;
		goto error;
	}

	result = asn1_read_value( pkcs8_asn, "privateKey", data, &data_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	asn1_delete_structure( &pkcs8_asn);
	
	tmp.data = data;
	tmp.size = data_size;
	
	pkey->pk_algorithm = GNUTLS_PK_RSA;

	ret_asn = _gnutls_privkey_decode_pkcs1_rsa_key( &tmp, pkey);
	if (ret_asn==NULL) {
		gnutls_assert();
	}
	
	return ret_asn;

	error:
		asn1_delete_structure( &pkcs8_asn);
		if (data != NULL) { gnutls_afree(data); }
		return NULL;

}

/**
  * gnutls_x509_privkey_import_pkcs8 - This function will import a DER or PEM PKCS8 encoded key
  * @key: The structure to store the parsed key
  * @data: The DER or PEM encoded certificate.
  * @format: One of DER or PEM
  * @pass: the password to decode
  *
  * This function will convert the given DER or PEM encoded PKCS8 2.0 encrypted key
  * to the native gnutls_x509_privkey format. The output will be stored in 'key'.
  *
  * If the Certificate is PEM encoded it should have a header of "ENCRYPTED PRIVATE KEY".
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_privkey_import_pkcs8(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format, char * pass)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	key->pk_algorithm = GNUTLS_PK_UNKNOWN;

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		/* Try the first header */
		result = _gnutls_fbase64_decode(PEM_PKCS8, data->data, data->size,
			&out);

		if (result <= 0) {
			if (result==0) result = GNUTLS_E_INTERNAL_ERROR;
			gnutls_assert();
			return result;
		}
		
		_data.data = out;
		_data.size = result;
		
		need_free = 1;
	}


	key->key = decode_pkcs8_key( &_data, pass, key);
	if (key->key == NULL) {
		gnutls_assert();
		result = GNUTLS_E_ASN1_DER_ERROR;
		goto cleanup;
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

/* Reads the PBKDF2 parameters.
 */
static int read_pbkdf2_params( ASN1_TYPE pbes2_asn, const gnutls_datum* der, 
	struct pbkdf2_params* params)
{
int params_start, params_end;
int params_len, len, result;
ASN1_TYPE pbkdf2_asn = ASN1_TYPE_EMPTY;
char oid[64];

	memset( params, 0, sizeof(params));

	/* Check the key derivation algorithm
	 */
	len = sizeof(oid);
	result = asn1_read_value( pbes2_asn, "keyDerivationFunc.algorithm", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	
	if (strcmp( oid, PBKDF2_OID) != 0) {
		gnutls_assert();
		_gnutls_x509_log( "PKCS #8 key derivation OID '%s' is unsupported.\n", oid);
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding_startEnd( pbes2_asn, der->data, der->size,
		"keyDerivationFunc.parameters", &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	params_len = params_end - params_start + 1;

	/* Now check the key derivation and the encryption
	 * functions.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.pkcs-5-PBKDF2-params", &pbkdf2_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	
	result = asn1_der_decoding(&pbkdf2_asn, &der->data[params_start], params_len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the salt */
	params->salt_size = sizeof(params->salt);
	result = asn1_read_value( pbkdf2_asn, "salt.specified", params->salt, &params->salt_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the iteration count 
	 */
	len = sizeof(oid);
	result = _gnutls_x509_read_ui( pbkdf2_asn, "iterationCount", oid, len, &params->iter_count);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}


	/* read the keylength, if it is set.
	 */
	len = sizeof(oid);

	result = _gnutls_x509_read_ui( pbkdf2_asn, "keyLength", oid, len, &params->key_size);
	if (result < 0) {
		params->key_size = 0;
	}
	
	/* We don't read the PRF. We only use the default.
	 */

	return 0;

	error:
		asn1_delete_structure( &pbkdf2_asn);
		return result;

}

static int read_pbe_enc_params( ASN1_TYPE pbes2_asn, const gnutls_datum* der, 
	struct pbe_enc_params* params)
{
int params_start, params_end;
int params_len, len, result;
ASN1_TYPE pbe_asn = ASN1_TYPE_EMPTY;
char oid[64];

	memset( params, 0, sizeof(params));

	/* Check the encryption algorithm
	 */
	len = sizeof(oid);
	result = asn1_read_value( pbes2_asn, "encryptionScheme.algorithm", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}
	
	if (strcmp( oid, DES_EDE3_CBC_OID) != 0) {
		gnutls_assert();
		_gnutls_x509_log( "PKCS #8 encryption OID '%s' is unsupported.\n", oid);
		goto error;
	}

	result = asn1_der_decoding_startEnd( pbes2_asn, der->data, der->size,
		"encryptionScheme.parameters", &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	params_len = params_end - params_start + 1;

	/* Now check the encryption parameters.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.pkcs-5-des-EDE3-CBC-params", &pbe_asn
				   )) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	
	result = asn1_der_decoding(&pbe_asn, &der->data[params_start], params_len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the salt */
	params->iv_size = sizeof(params->iv);
	result = asn1_read_value( pbe_asn, "", params->iv, &params->iv_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	return 0;

	error:
		asn1_delete_structure( &pbe_asn);
		return result;

}

static int decrypt_data( ASN1_TYPE pkcs8_asn,  char* password,
	const struct pbkdf2_params *kdf_params, const struct pbe_enc_params *enc_params, 
	gnutls_datum* decrypted_data)
{
int result;
int data_size;
opaque* data, *key;
gnutls_datum dkey, div;
GNUTLS_CIPHER_HANDLE ch = NULL;
int key_size;

	data_size = 0;
	result = asn1_read_value( pkcs8_asn, "encryptedData", NULL, &data_size);
	if (result != ASN1_MEM_ERROR) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	data = gnutls_malloc( data_size);
	if (data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_read_value( pkcs8_asn, "encryptedData", data, &data_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	if (kdf_params->key_size == 0) {
		key_size = gnutls_cipher_get_key_size( GNUTLS_CIPHER_3DES_CBC);
	} else key_size = kdf_params->key_size;

	key = gnutls_alloca( key_size);
	if ( key == NULL) {
		gnutls_assert();
		result = GNUTLS_E_MEMORY_ERROR;
		goto error;
	}

	/* generate the key
	 */
	result = _gnutls_pkcs5_pbkdf2( PKCS5_PRF_SHA1, password, strlen(password),
		kdf_params->salt, kdf_params->salt_size, kdf_params->iter_count,
		key_size, key);
	
	if (result != PKCS5_OK) {
		gnutls_assert();
		result = GNUTLS_E_DECRYPTION_FAILED;
		goto error;
	}

	/* do the decryption.
	 */
	dkey.data = key;
	dkey.size = key_size;
	
	div.data = (opaque*) enc_params->iv;
	div.size = enc_params->iv_size;
	ch = _gnutls_cipher_init( GNUTLS_CIPHER_3DES_CBC, dkey, div);

	gnutls_afree( key);

	if (ch == NULL) {
		gnutls_assert();
		result = GNUTLS_E_DECRYPTION_FAILED;
		goto error;
	}
	
	result = _gnutls_cipher_decrypt( ch, data, data_size);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	decrypted_data->data = data;
	decrypted_data->size = data_size - data[data_size-1];

	_gnutls_cipher_deinit( ch);

	return 0;

	error:
		gnutls_free(data);
		if (ch!=NULL)
			_gnutls_cipher_deinit( ch);
		return result;
}
