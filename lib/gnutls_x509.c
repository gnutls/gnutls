/*
 *  Copyright (C) 2002,2003 Nikos Mavroyanopoulos
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
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <gnutls_sig.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_str.h>
#include <debug.h>
#include <x509_b64.h>
#include <gnutls_privkey.h>
#include <gnutls_x509.h>
#include "x509/common.h"
#include "x509/x509.h"
#include "x509/verify.h"
#include "x509/compat.h"
#include "x509/mpi.h"
#include "x509/pkcs7.h"

/*
 * some x509 certificate parsing functions.
 */

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) { \
	if (peer_certificate_list[x]) \
		gnutls_x509_crt_deinit(peer_certificate_list[x]); \
	} \
	gnutls_free( peer_certificate_list)

/*-
  * _gnutls_x509_cert_verify_peers - This function returns the peer's certificate status
  * @session: is a gnutls session
  *
  * This function will try to verify the peer's certificate and return it's status (TRUSTED, REVOKED etc.). 
  * The return value (status) should be one of the gnutls_certificate_status enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_E_NO_CERTIFICATE_FOUND if no certificate was sent.
  *
  -*/
int _gnutls_x509_cert_verify_peers(gnutls_session session)
{
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;
	unsigned int verify;
	gnutls_x509_crt *peer_certificate_list;
	int peer_certificate_list_size, i, x, ret;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(session);
	if (info == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	cred = _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CREDENTIALS;
	}

	if (info->raw_certificate_list == NULL || info->ncerts == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = info->ncerts;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_x509_crt));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		ret = gnutls_x509_crt_init( &peer_certificate_list[i]);
		if (ret < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			return ret;
		}
		
		ret =
		     gnutls_x509_crt_import(peer_certificate_list[i],
					     &info->
					     raw_certificate_list[i], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			return ret;
		}
	}

	/* Verify certificate 
	 */
	ret =
	    gnutls_x509_crt_list_verify(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->x509_ca_list, cred->x509_ncas, 
				      cred->x509_crl_list, cred->x509_ncrls, 0, &verify);

	CLEAR_CERTS;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return verify;
}

/*
 * Read certificates and private keys, from files, memory etc.
 */

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int _gnutls_check_key_cert_match( gnutls_certificate_credentials res) 
{
int pk = res->cert_list[res->ncerts-1][0].subject_pk_algorithm;
	
	if (res->pkey[res->ncerts-1].pk_algorithm != (unsigned int)pk) {
		gnutls_assert();
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}
	return 0;
}

#define MAX_FILE_SIZE 100*1024

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncerts + 1;

	*cert_list =
	    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
					   i *
					   sizeof(gnutls_cert));

	if ( *cert_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = _gnutls_x509_cert2gnutls_cert( 
		&cert_list[0][i - 1], &tmp, 0);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncerts = i;

	return 1; /* one certificate parsed */
}

#define CERT_PEM 1

/* Reads a PKCS7 base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure.
 * returns the number of certificate parsed
 */
static int parse_pkcs7_cert_mem( gnutls_cert** cert_list, int* ncerts, const
	char *input_cert, int input_cert_size, int flags)
{
	int i, j, count;
	gnutls_datum tmp, tmp2;
	int ret;
	opaque pcert[MAX_X509_CERT_SIZE];
	int pcert_size;
	gnutls_pkcs7 pkcs7;
	
	ret = gnutls_pkcs7_init( &pkcs7);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	if (flags & CERT_PEM)
		ret = gnutls_pkcs7_import( pkcs7, &tmp, GNUTLS_X509_FMT_PEM);
	else
		ret = gnutls_pkcs7_import( pkcs7, &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		/* if we failed to read the structure,
		 * then just try to decode a plain DER
		 * certificate.
		 */
		gnutls_assert();
		gnutls_pkcs7_deinit(pkcs7);
		return parse_der_cert_mem( cert_list, ncerts,
			input_cert, input_cert_size);
	}

	i = *ncerts + 1;

	/* tmp now contains the decoded certificate list */
	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = gnutls_pkcs7_get_certificate_count( pkcs7);

	if (ret < 0) {
		gnutls_assert();
		gnutls_pkcs7_deinit(pkcs7);
		return ret;
	}
	count = ret;
	
	j = count - 1;
	do {
		pcert_size = sizeof(pcert);
		ret = gnutls_pkcs7_get_certificate( pkcs7, j, pcert, &pcert_size);
		j--;

		/* if the current certificate is too long, just ignore
		 * it. */
		if (ret==GNUTLS_E_MEMORY_ERROR) {
			count--;
			continue;
		}
		
		if (ret >= 0) {
			*cert_list =
			    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
					   i * sizeof(gnutls_cert));

			if ( *cert_list == NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}

			tmp2.data = pcert;
			tmp2.size = pcert_size;

			ret = _gnutls_x509_cert2gnutls_cert( 
				&cert_list[0][i - 1], &tmp2, 0);

			if ( ret < 0) {
				gnutls_assert();
				gnutls_pkcs7_deinit(pkcs7);
				return ret;
			}
	
			i++;
		}

	} while (ret >= 0 && j >= 0);

	*ncerts = i - 1;

	gnutls_pkcs7_deinit(pkcs7);
	return count;
}


/* Reads a base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure. Returns the number of certificate parsed.
 */
static int parse_pem_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int siz, siz2, i;
	const char *ptr;
	opaque *ptr2;
	gnutls_datum tmp;
	int ret, count;

	if ( (ptr = strstr( input_cert, PEM_PKCS7_SEP)) != NULL) 
	{
		siz = strlen( ptr);

		ret = parse_pkcs7_cert_mem( cert_list, ncerts, ptr,
			siz, CERT_PEM);

		return ret;
	}

	/* move to the certificate
	 */
	ptr = strstr( input_cert, PEM_CERT_SEP);
	if (ptr == NULL) ptr = strstr( input_cert, PEM_CERT_SEP2);

	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}
	siz = strlen( ptr);

	i = *ncerts + 1;
	count = 0;

	do {

		siz2 = _gnutls_fbase64_decode(NULL, ptr, siz, &ptr2);
		siz -= siz2;

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_BASE64_DECODING_ERROR;
		}

		*cert_list =
		    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
						   i *
						   sizeof(gnutls_cert));

		if ( *cert_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = ptr2;
		tmp.size = siz2;

		ret = _gnutls_x509_cert2gnutls_cert( 
			&cert_list[0][i - 1], &tmp, 0);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */
		ptr = strstr(ptr, PEM_CERT_SEP);
		if (ptr == NULL) ptr = strstr( input_cert, PEM_CERT_SEP2);

		i++;
		count++;

	} while ( ptr != NULL);

	*ncerts = i - 1;

	return count;
}



/* Reads a DER or PEM certificate from memory
 */
static 
int read_cert_mem(gnutls_certificate_credentials res, const char *cert, int cert_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->cert_list = gnutls_realloc_fast( res->cert_list, 
		(1+ res->ncerts)*sizeof(gnutls_cert*));
	if ( res->cert_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list_length = gnutls_realloc_fast( res->cert_list_length,
		(1+ res->ncerts)*sizeof(int));
	if (res->cert_list_length==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list[res->ncerts] = NULL; /* for realloc */
	res->cert_list_length[res->ncerts] = 0;

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_pkcs7_cert_mem( &res->cert_list[res->ncerts], 
			&res->cert_list_length[res->ncerts], cert, cert_size, 0);
	else
		ret = parse_pem_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}



/* This will check if the given DER key is a PKCS-1 RSA key.
 * Returns 0 if the key is an RSA one.
 */
int _gnutls_der_check_if_rsa_key(const gnutls_datum * key_struct)
{
	ASN1_TYPE c2;
	int result;

	if (key_struct->size == 0 || key_struct->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if ((result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPrivateKey", &c2
	       )) != ASN1_SUCCESS) 
	{
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, key_struct->data, key_struct->size, NULL);
	asn1_delete_structure(&c2);

	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
	
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/* This will check if the given DER key is an openssl formated DSA key.
 * Returns 0 if the key is a DSA one.
 */
int _gnutls_der_check_if_dsa_key(const gnutls_datum * key_struct)
{
	ASN1_TYPE c2;
	int result;

	if (key_struct->size == 0 || key_struct->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if ((result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPrivateKey", &c2
	       )) != ASN1_SUCCESS) 
	{
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, key_struct->data, key_struct->size, NULL);
	asn1_delete_structure(&c2);

	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
	
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}




/* Reads a PEM encoded PKCS-1 RSA private key from memory
 * 2002-01-26: Added ability to read DSA keys.
 * type indicates the certificate format.
 */
static int read_key_mem(gnutls_certificate_credentials res, const char *key, int key_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;
	opaque *b64 = NULL;
	gnutls_datum tmp;
	gnutls_pk_algorithm pk;

	/* allocate space for the pkey list
	 */
	res->pkey = gnutls_realloc_fast( res->pkey, (res->ncerts+1)*sizeof(gnutls_private_key));
	if (res->pkey==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* read PKCS-1 private key */

	if (type==GNUTLS_X509_FMT_DER) { /* DER */
		int cv;
		
		tmp.data = (opaque*)key;
		tmp.size = key_size;

		/* The only way to distinguish the keys
		 * is to count the sequence of integers.
		 */
		pk = GNUTLS_PK_UNKNOWN;
		cv = _gnutls_der_check_if_rsa_key( &tmp);
		if (cv==0)
			pk = GNUTLS_PK_RSA;
		else {
		   cv = _gnutls_der_check_if_dsa_key( &tmp);
		   if (cv == 0) pk = GNUTLS_PK_DSA;
	        }

	} else { /* PEM */

		/* If we find the "DSA PRIVATE" string in the
		 * pem encoded certificate then it's a DSA key.
		 */
		if (strstr( key, "DSA PRIVATE")!=NULL) {
			pk = GNUTLS_PK_DSA;
			key = strstr( key, PEM_KEY_DSA_SEP);
			if (key == NULL) {
				gnutls_assert();
				return GNUTLS_E_BASE64_DECODING_ERROR;
			}			key_size = strlen( key);
		} else {
			pk = GNUTLS_PK_RSA;
			key = strstr( key, PEM_KEY_RSA_SEP);
			if (key == NULL) {
				gnutls_assert();
				return GNUTLS_E_BASE64_DECODING_ERROR;
			}
			key_size = strlen( key);
		}
			

		ret = _gnutls_fbase64_decode( NULL, key, key_size, &b64);

		if (ret < 0) {
			gnutls_assert();
			return GNUTLS_E_BASE64_DECODING_ERROR;
		}

		tmp.data = b64;
		tmp.size = ret;
	}

	switch (pk) { /* decode the key */
		case GNUTLS_PK_RSA:
			if ((ret =
			     _gnutls_PKCS1key2gnutlsKey(&res->pkey[res->ncerts],
						tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;
		case GNUTLS_PK_DSA:
			if ((ret =
			     _gnutls_DSAkey2gnutlsKey(&res->pkey[res->ncerts],
							tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;
		default:
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_INTERNAL_ERROR;
	}

	/* this doesn't hurt in the DER case, since
	 * b64 is NULL
	 */
	gnutls_free(b64);
	
	return 0;
}


/* Reads a certificate file
 */
static int read_cert_file(gnutls_certificate_credentials res, const char *certfile,
	gnutls_x509_crt_fmt type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(certfile, "rb");
	if (fd1 == NULL)
		return GNUTLS_E_FILE_ERROR;

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return read_cert_mem( res, x, siz, type);

}



/* Reads PKCS-1 RSA private key file or a DSA file (in the format openssl
 * stores it).
 */
static int read_key_file(gnutls_certificate_credentials res, const char *keyfile,
	gnutls_x509_crt_fmt type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd2;

	fd2 = fopen(keyfile, "rb");
	if (fd2 == NULL)
		return GNUTLS_E_FILE_ERROR;

	siz = fread(x, 1, sizeof(x)-1, fd2);
	fclose(fd2);

	x[siz] = 0;

	return read_key_mem( res, x, siz, type);
}

/**
  * gnutls_certificate_set_x509_key_mem - Used to set keys in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CERT: contains a certificate list (path) for the specified private key
  * @KEY: is the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently are supported: RSA PKCS-1 encoded private keys, 
  * DSA private keys.
  *
  * DSA private keys are encoded the OpenSSL way, which is an ASN.1
  * DER sequence of 6 INTEGERs - version, p, q, g, pub, priv.
  *
  * Note that the keyUsage (2.5.29.15) PKIX extension in X.509 certificates 
  * is supported. This means that certificates intended for signing cannot
  * be used for ciphersuites that require encryption.
  *
  * If the certificate and the private key are given in PEM encoding
  * then the strings that hold their values must be null terminated.
  *
  **/
int gnutls_certificate_set_x509_key_mem(gnutls_certificate_credentials res, const gnutls_datum* CERT,
			   const gnutls_datum* KEY, gnutls_x509_crt_fmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_mem( res, KEY->data, KEY->size, type)) < 0)
		return ret;

	if ((ret = read_cert_mem( res, CERT->data, CERT->size, type)) < 0)
		return ret;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
  * gnutls_certificate_set_x509_key_file - Used to set keys in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CERTFILE: is a file that containing the certificate list (path) for
  * the specified private key, in PKCS7 format, or a list of certificates
  * @KEYFILE: is a file that contains the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently only PKCS-1 encoded RSA and DSA private keys are accepted by
  * this function.
  *
  **/
int gnutls_certificate_set_x509_key_file(gnutls_certificate_credentials res, const char *CERTFILE,
			   const char *KEYFILE, gnutls_x509_crt_fmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_file(res, KEYFILE, type)) < 0)
		return ret;

	if ((ret = read_cert_file(res, CERTFILE, type)) < 0)
		return ret;

	res->ncerts++;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

static int generate_rdn_seq( gnutls_certificate_credentials res) 
{
gnutls_const_datum tmp;
gnutls_datum _tmp;
int ret;
uint size, i;
opaque *pdata;

	/* Generate the RDN sequence 
	 * This will be sent to clients when a certificate
	 * request message is sent.
	 */

	/* FIXME: in case of a client it is not needed
	 * to do that. This would save time and memory.
	 * However we don't have that information available
	 * here.
	 */

	size = 0;
	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_x509_crt_get_raw_issuer_dn( 
			res->x509_ca_list[i], &tmp)) < 0) {
			gnutls_assert();
			return ret;
		}
		size += (2 + tmp.size);
	}

	if (res->x509_rdn_sequence.data != NULL)
		gnutls_free( res->x509_rdn_sequence.data);

	res->x509_rdn_sequence.data = gnutls_malloc(size);
	if (res->x509_rdn_sequence.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	res->x509_rdn_sequence.size = size;

	pdata = res->x509_rdn_sequence.data;

	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_x509_crt_get_raw_issuer_dn( 
			res->x509_ca_list[i], &tmp)) < 0) {
			gnutls_free(res->x509_rdn_sequence.data);
			res->x509_rdn_sequence.size = 0;
			res->x509_rdn_sequence.data = NULL;
			gnutls_assert();
			return ret;
		}

		_tmp.data = (char*) tmp.data;
		_tmp.size = tmp.size;
		_gnutls_write_datum16(pdata, _tmp);
		pdata += (2 + tmp.size);
	}

	return 0;
}




/* Returns 0 if it's ok to use the gnutls_kx_algorithm with this 
 * certificate (uses the KeyUsage field). 
 */
int _gnutls_check_key_usage( const gnutls_cert* cert,
				    gnutls_kx_algorithm alg)
{
	unsigned int keyUsage = 0;
	int encipher_type;

	if ( cert==NULL) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* FIXME: check here */
	if (_gnutls_map_kx_get_cred(alg, 1) == GNUTLS_CRD_CERTIFICATE ||
		_gnutls_map_kx_get_cred(alg, 0) == GNUTLS_CRD_CERTIFICATE) 
	{

		keyUsage = cert->keyUsage;

		encipher_type = _gnutls_kx_encipher_type( alg);
		
		if (keyUsage != 0 && encipher_type != CIPHER_IGN) {
			/* If keyUsage has been set in the certificate
			 */

			if ( encipher_type == CIPHER_ENCRYPT) {
				/* If the key exchange method requires an encipher
				 * type algorithm, and key's usage does not permit
				 * encipherment, then fail.
				 */
				if (!(keyUsage & KEY_KEY_ENCIPHERMENT))
					return
					    GNUTLS_E_KEY_USAGE_VIOLATION;
			}

			if ( encipher_type == CIPHER_SIGN) { 
				/* The same as above, but for sign only keys
				 */
				if (!(keyUsage & KEY_DIGITAL_SIGNATURE))
					return
					    GNUTLS_E_KEY_USAGE_VIOLATION;
			}
		}
	}
	return 0;
}



static int parse_pem_ca_mem( gnutls_x509_crt** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int siz, i;
	const char *ptr;
	gnutls_datum tmp;
	int ret, count;

	/* move to the certificate
	 */
	ptr = strstr( input_cert, PEM_CERT_SEP);
	if (ptr == NULL) ptr = strstr( input_cert, PEM_CERT_SEP2);

	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}
	siz = strlen( ptr);

	i = *ncerts + 1;
	count = 0;

	do {

		*cert_list =
		    (gnutls_x509_crt *) gnutls_realloc_fast( *cert_list,
						   i *
						   sizeof(gnutls_x509_crt));

		if ( *cert_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		ret = gnutls_x509_crt_init( &cert_list[0][i - 1]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		tmp.data = (char*)ptr;
		tmp.size = siz;
	
		ret =
		     gnutls_x509_crt_import(
				     cert_list[0][i - 1],
				     &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */
		ptr = strstr(ptr, PEM_CERT_SEP);
		if (ptr == NULL) ptr = strstr( input_cert, PEM_CERT_SEP2);

		i++;
		count++;

	} while ( ptr != NULL);

	*ncerts = i - 1;

	return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_ca_mem( gnutls_x509_crt** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncerts + 1;

	*cert_list =
	    (gnutls_x509_crt *) gnutls_realloc_fast( *cert_list,
					   i *
					   sizeof(gnutls_x509_crt));

	if ( *cert_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = gnutls_x509_crt_init( &cert_list[0][i - 1]);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
		
	ret =
	     gnutls_x509_crt_import(
			     cert_list[0][i - 1],
			     &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncerts = i;

	return 1; /* one certificate parsed */
}

/**
  * gnutls_certificate_set_x509_trust_mem - Used to add trusted CAs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CA: is a list of trusted CAs or a DER certificate
  * @type: is DER or PEM
  *
  * This function adds the trusted CAs in order to verify client
  * certificates. This function may be called multiple times.
  *
  **/
int gnutls_certificate_set_x509_trust_mem(gnutls_certificate_credentials res, 
	const gnutls_datum *CA, gnutls_x509_crt_fmt type)
{
	int ret, ret2;

	if (type==GNUTLS_X509_FMT_DER)
		return parse_der_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			CA->data, CA->size);
	else
		return parse_pem_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			CA->data, CA->size);

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

/**
  * gnutls_certificate_set_x509_trust_file - Used to add trusted CAs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CAFILE: is a file containing the list of trusted CAs (DER or PEM list)
  * @type: is PEM or DER
  *
  * This function sets the trusted CAs in order to verify client
  * certificates. This function may be called multiple times, and the
  * given certificates will be appended to the trusted certificate list.
  * Returns the number of certificate processed.
  *
  **/
int gnutls_certificate_set_x509_trust_file(gnutls_certificate_credentials res, 
		const char *CAFILE, gnutls_x509_crt_fmt type)
{
	int ret, ret2;
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	/* FIXME: does not work on long files
	 */
	fd1 = fopen(CAFILE, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			x, siz);
	else
		ret = parse_pem_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			x, siz);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

static int parse_pem_crl_mem( gnutls_x509_crl** crl_list, int* ncrls, 
	const char *input_crl, int input_crl_size)
{
	int siz, i;
	const char *ptr;
	gnutls_datum tmp;
	int ret, count;

	/* move to the certificate
	 */
	ptr = strstr( input_crl, PEM_CRL_SEP);
	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}

	siz = strlen( ptr);

	i = *ncrls + 1;
	count = 0;

	do {

		*crl_list =
		    (gnutls_x509_crl *) gnutls_realloc_fast( *crl_list,
						   i *
						   sizeof(gnutls_x509_crl));

		if ( *crl_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		ret = gnutls_x509_crl_init( &crl_list[0][i - 1]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		tmp.data = (char*)ptr;
		tmp.size = siz;
	
		ret =
		     gnutls_x509_crl_import(
				     crl_list[0][i - 1],
				     &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */
		ptr = strstr(ptr, PEM_CRL_SEP);
		i++;
		count++;

	} while ( ptr != NULL);

	*ncrls = i - 1;

	return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_crl_mem( gnutls_x509_crl** crl_list, int* ncrls, 
	const char *input_crl, int input_crl_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncrls + 1;

	*crl_list =
	    (gnutls_x509_crl *) gnutls_realloc_fast( *crl_list,
					   i *
					   sizeof(gnutls_x509_crl));

	if ( *crl_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*)input_crl;
	tmp.size = input_crl_size;

	ret = gnutls_x509_crl_init( &crl_list[0][i - 1]);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
		
	ret =
	     gnutls_x509_crl_import(
			     crl_list[0][i - 1],
			     &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncrls = i;

	return 1; /* one certificate parsed */
}


/* Reads a DER or PEM CRL from memory
 */
static 
int read_crl_mem(gnutls_certificate_credentials res, const char *crl, int crl_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->x509_crl_list = gnutls_realloc_fast( res->x509_crl_list, 
		(1+ res->x509_ncrls)*sizeof(gnutls_x509_crl));
	if ( res->x509_crl_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_crl_mem( &res->x509_crl_list, 
			&res->x509_ncrls, crl, crl_size);
	else
		ret = parse_pem_crl_mem( &res->x509_crl_list, 
			&res->x509_ncrls, crl, crl_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/**
  * gnutls_certificate_set_x509_crl_mem - Used to add CRLs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CRL: is a list of trusted CRLs. They should have been verified before.
  * @type: is DER or PEM
  *
  * This function adds the trusted CRLs in order to verify client or server
  * certificates. This function may be called multiple times.
  *
  **/
int gnutls_certificate_set_x509_crl_mem(gnutls_certificate_credentials res, 
	const gnutls_datum *CRL, gnutls_x509_crt_fmt type)
{
	int ret;

	if ((ret = read_crl_mem(res, CRL->data, CRL->size, type)) < 0)
		return ret;

	return ret;
}

/**
  * gnutls_certificate_set_x509_crl_file - Used to add CRLs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @crlfile: is a file containing the list of verified CRLs (DER or PEM list)
  * @type: is PEM or DER
  *
  * This function sets the trusted CRLs in order to verify client or server
  * certificates. This function may be called multiple times, and the
  * given CRLs will be appended to the crl list.
  * Returns the number of certificate processed.
  *
  **/
int gnutls_certificate_set_x509_crl_file(gnutls_certificate_credentials res, 
		const char *crlfile, gnutls_x509_crt_fmt type)
{
	int ret;
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	/* FIXME: does not work on long files
	 */
	fd1 = fopen(crlfile, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_crl_mem( &res->x509_crl_list, &res->x509_ncrls,
			x, siz);
	else
		ret = parse_pem_crl_mem( &res->x509_crl_list, &res->x509_ncrls,
			x, siz);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}
