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
#include <x509_verify.h>
#include <gnutls_sig.h>
#include <x509_extensions.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_str.h>
#include <debug.h>
#include <x509_b64.h>
#include <gnutls_privkey.h>
#include <gnutls_x509.h>
#include "x509/common.h"

/*
 * some x509 certificate parsing functions.
 */

int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct);


static int _IREAD(ASN1_TYPE rasn, char* name, const char *OID, 
	gnutls_x509_dn *dn)
{
	int result, len;
	char str[1024];
	char* res = NULL;
	int res_size = -1;
	
	if (strcmp( OID, "2 5 4 6") == 0) {
		res = dn->country;
		res_size = sizeof(dn->country);
	} else 	if (strcmp( OID, "2 5 4 10") == 0) {
		res = dn->organization;
		res_size = sizeof(dn->organization);
	} else 	if (strcmp( OID, "2 5 4 11") == 0) {
		res = dn->organizational_unit_name;
		res_size = sizeof(dn->organizational_unit_name);
	} else 	if (strcmp( OID, "2 5 4 3") == 0) {
		res = dn->common_name;
		res_size = sizeof(dn->common_name);
	} else 	if (strcmp( OID, "2 5 4 7") == 0) {
		res = dn->locality_name;
		res_size = sizeof(dn->locality_name);
	} else 	if (strcmp( OID, "2 5 4 8") == 0) {
		res = dn->state_or_province_name;
		res_size = sizeof(dn->state_or_province_name);
	} else 	if (strcmp( OID, "1 2 840 113549 1 9 1") == 0) {
		res = dn->email;
		res_size = sizeof(dn->email);
	}

	if (res==NULL || res_size < 0) return 1;

	len = sizeof(str) -1;
	/* Read the DER value of the 'value' part of the
	 * AttributeTypeAndValue.
	 */
	if ((result =
	     asn1_read_value(rasn, name, str, &len)) != ASN1_SUCCESS) {
		return 1;
	}
	
	result = _gnutls_x509_oid_data2string( OID, str, len, res, &res_size);
	if (result < 0) return 1;
	else return 0;
}


/* This function will attempt to read a Name
 * ASN.1 structure. (Taken from Fabio's samples!)
 *
 * FIXME: These functions need carefull auditing
 * (they're complex enough)
 * --nmav
 */
int _gnutls_x509_get_name_type(ASN1_TYPE rasn, const char *root, gnutls_x509_dn * dn)
{
	int k, k2, result, len;
	char name[128], str[1024], name2[128], counter[MAX_INT_DIGITS],
	    name3[128];

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), root); 
		_gnutls_str_cat(name, sizeof(name), ".rdnSequence.?"); 
		_gnutls_int2str(k, counter);
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;

		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */
		if (result == ASN1_ELEMENT_NOT_FOUND)
			break;
		if (result != ASN1_VALUE_NOT_FOUND) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		k2 = 0;
		do {
			k2++;

			_gnutls_str_cpy(name2, sizeof(name2), name); 
			_gnutls_str_cat(name2, sizeof(name2), ".?"); 
			_gnutls_int2str(k2, counter);
			_gnutls_str_cat(name2, sizeof(name2), counter); 

			len = sizeof(str) - 1;
			result = asn1_read_value(rasn, name2, str, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			if (result != ASN1_VALUE_NOT_FOUND) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".type"); 

			len = sizeof(str) - 1;
			/* read OID */
			result = asn1_read_value(rasn, name3, str, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".value");

			if (result == ASN1_SUCCESS) {
				result = _IREAD(rasn, name3, str, dn);
				if (result < 0) {
					return result;
				}
				
				if (result==1) continue;
			}
		} while (1);
	} while (1);

	if (result == ASN1_ELEMENT_NOT_FOUND)
		return 0;
	else
		return _gnutls_asn2err(result);
}

int _gnutls_x509_get_version(ASN1_TYPE c2, const char *root)
{
	opaque gversion[5];
	char name[1024];
	int len, result;

	_gnutls_str_cpy(name, sizeof(name), root);
	_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.version"); 

	len = sizeof(gversion) - 1;
	if ((result = asn1_read_value(c2, name, gversion, &len)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	return (int) gversion[0] + 1;
}


#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x])

/*-
  * _gnutls_x509_cert_verify_peers - This function returns the peer's certificate status
  * @session: is a gnutls session
  *
  * This function will try to verify the peer's certificate and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one of the gnutls_certificate_status enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_E_NO_CERTIFICATE_FOUND if no certificate was sent.
  *
  -*/
int _gnutls_x509_cert_verify_peers(gnutls_session session)
{
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;
	int verify;
	gnutls_cert *peer_certificate_list;
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
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     info->
					     raw_certificate_list[i], 0)) <
		    0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    _gnutls_x509_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->x509_ca_list, cred->x509_ncas, NULL, 0);

	CLEAR_CERTS;
	gnutls_free(peer_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return verify;
	}


	return verify;
}

#define CLEAR_CERTS_CA for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(peer_certificate_list[x]); \
		for(x=0;x<ca_certificate_list_size;x++) _gnutls_free_cert(ca_certificate_list[x])
/**
  * gnutls_x509_verify_certificate - This function verifies given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: not used
  * @CRL_list_length: not used
  *
  * This function will try to verify the given certificate list and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd. Note that expiration and activation dates are not checked 
  * by this function, you should check them using the appropriate functions.
  *
  * This function understands the basicConstraints (2 5 29 19) PKIX extension.
  * This means that only a certificate authority can sign a certificate.
  *
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. 
  *
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd.
  *
  * GNUTLS_CERT_NOT_TRUSTED\: the peer's certificate is not trusted.
  *
  * GNUTLS_CERT_INVALID\: the certificate chain is broken.
  *
  * GNUTLS_CERT_REVOKED\: the certificate has been revoked
  *  (not implemented yet).
  *
  * GNUTLS_CERT_CORRUPTED\: the certificate is corrupted.
  *
  * A negative error code is returned in case of an error.
  * GNUTLS_E_NO_CERTIFICATE_FOUND is returned to indicate that
  * no certificate was sent by the peer.
  *  
  *
  **/
int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length)
{
	int verify;
	gnutls_cert *peer_certificate_list;
	gnutls_cert *ca_certificate_list;
	int peer_certificate_list_size, i, x, ret, ca_certificate_list_size;

	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = cert_list_length;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ca_certificate_list_size = CA_list_length;
	ca_certificate_list =
	    gnutls_calloc(1,
			  ca_certificate_list_size *
			  sizeof(gnutls_cert));
	if (ca_certificate_list == NULL) {
		gnutls_assert();
		gnutls_free( peer_certificate_list);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* convert certA_list to gnutls_cert* list
	 */
	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     cert_list[i], 0)) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* convert CA_list to gnutls_cert* list
	 */
	for (i = 0; i < ca_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&ca_certificate_list[i],
					     CA_list[i], 0)) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    _gnutls_x509_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      ca_certificate_list, ca_certificate_list_size, NULL, 0);

	CLEAR_CERTS_CA;
	gnutls_free( peer_certificate_list);
	gnutls_free( ca_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return verify;
	}

	return verify;
}

/*
 * Read certificates and private keys, from files, memory etc.
 */

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int _gnutls_check_key_cert_match( gnutls_certificate_credentials res) {
	
	if (res->pkey[res->ncerts-1].pk_algorithm != res->cert_list[res->ncerts-1][0].subject_pk_algorithm) {
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

	if ((ret =
	     _gnutls_x509_cert2gnutls_cert(
				     &cert_list[0][i - 1],
				     tmp, 0)) < 0) {
		gnutls_assert();
		return ret;
	}

	*ncerts = i;

	return 1; /* one certificate parsed */
}


/* Reads a PKCS7 base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure.
 * returns the number of certificate parsed
 */
static int parse_pkcs7_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int i, j, count;
	gnutls_datum tmp, tmp2;
	int ret;
	opaque pcert[MAX_X509_CERT_SIZE];
	int pcert_size;

	i = *ncerts + 1;

	/* tmp now contains the decoded certificate list */
	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	count = gnutls_x509_pkcs7_extract_certificate_count( &tmp);

	if (count <= 0) {
		gnutls_assert();
		/* if we failed to read the count,
		 * then just try to decode a plain DER
		 * certificate.
		 */
		return parse_der_cert_mem( cert_list, ncerts,
			input_cert, input_cert_size);
	}
	
	j = count - 1;
	do {
		pcert_size = sizeof(pcert);
		ret = gnutls_x509_pkcs7_extract_certificate( &tmp, j, pcert, &pcert_size);
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

			if ((ret =
			     _gnutls_x509_cert2gnutls_cert(
						     &cert_list[0][i - 1],
						     tmp2, 0)) < 0) {
				gnutls_assert();
				return ret;
			}
			
			i++;
		}

	} while (ret >= 0 && j >= 0);
	
	*ncerts = i - 1;

	return count;
}


/* Reads a base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure. Returns the number of certificate parsed.
 */
static int parse_pem_cert_mem( gnutls_cert** cert_list, int* ncerts, 
	const char *input_cert, int input_cert_size)
{
	int siz, i, siz2;
	opaque *b64;
	const char *ptr;
	gnutls_datum tmp;
	int ret, count;

	if ( (ptr = strstr( input_cert, PEM_PKCS7_SEP)) != NULL) 
	{
		siz = strlen( ptr);

		siz2 = _gnutls_fbase64_decode( NULL, ptr, siz, &b64);

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_BASE64_DECODING_ERROR;
		}

		ret = parse_pkcs7_cert_mem( cert_list, ncerts, b64,
			siz2);

		gnutls_free(b64);
		
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
		siz2 = _gnutls_fbase64_decode(NULL, ptr, siz, &b64);
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
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = b64;
		tmp.size = siz2;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(
					     &cert_list[0][i - 1],
					     tmp, 0)) < 0) {
			gnutls_free(b64);
			gnutls_assert();
			return ret;
		}
		gnutls_free(b64);

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
static int read_cert_mem(gnutls_certificate_credentials res, const char *cert, int cert_size, 
	gnutls_x509_certificate_format type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->cert_list = gnutls_realloc_fast( res->cert_list, (1+ res->ncerts)*sizeof(gnutls_cert*));
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
		ret = parse_pkcs7_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);
	else
		ret = parse_pem_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/* Reads a base64 encoded CA list from memory 
 * This is to be called once.
 */
static int read_ca_mem(gnutls_certificate_credentials res, const char *ca, int ca_size,
	gnutls_x509_certificate_format type)
{

	if (type==GNUTLS_X509_FMT_DER)
		return parse_der_cert_mem( &res->x509_ca_list, &res->x509_ncas,
			ca, ca_size);
	else
		return parse_pem_cert_mem( &res->x509_ca_list, &res->x509_ncas,
			ca, ca_size);

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

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPrivateKey", &c2, 
	       "rsakey")) != ASN1_SUCCESS) 
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

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPrivateKey", &c2, 
	       "rsakey")) != ASN1_SUCCESS) 
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
	gnutls_x509_certificate_format type)
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
	gnutls_x509_certificate_format type)
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

/* Reads a base64 encoded CA file (file contains multiple certificate
 * authorities). This is to be called once.
 */
static int read_ca_file(gnutls_certificate_credentials res, const char *cafile, 
	gnutls_x509_certificate_format type)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(cafile, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return read_ca_mem( res, x, siz, type);
}


/* Reads PKCS-1 RSA private key file or a DSA file (in the format openssl
 * stores it).
 */
static int read_key_file(gnutls_certificate_credentials res, const char *keyfile,
	gnutls_x509_certificate_format type)
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
  * Note that the keyUsage (2 5 29 15) PKIX extension in X.509 certificates 
  * is supported. This means that certificates intended for signing cannot
  * be used for ciphersuites that require encryption.
  *
  * If the certificate and the private key are given in PEM encoding
  * then the strings that hold their values must be null terminated.
  *
  **/
int gnutls_certificate_set_x509_key_mem(gnutls_certificate_credentials res, const gnutls_datum* CERT,
			   const gnutls_datum* KEY, gnutls_x509_certificate_format type)
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
			   const char *KEYFILE, gnutls_x509_certificate_format type)
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

static int generate_rdn_seq( gnutls_certificate_credentials res) {
gnutls_datum tmp;
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
		if ((ret = _gnutls_find_dn(&tmp, &res->x509_ca_list[i])) < 0) {
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
		if ((ret = _gnutls_find_dn(&tmp, &res->x509_ca_list[i])) < 0) {
			gnutls_free(res->x509_rdn_sequence.data);
			res->x509_rdn_sequence.size = 0;
			res->x509_rdn_sequence.data = NULL;
			gnutls_assert();
			return ret;
		}
		_gnutls_write_datum16(pdata, tmp);
		pdata += (2 + tmp.size);
	}

	return 0;
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
	const gnutls_datum *CA, gnutls_x509_certificate_format type)
{
	int ret, ret2;

	if ((ret = read_ca_mem(res, CA->data, CA->size, type)) < 0)
		return ret;

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
		const char *CAFILE, gnutls_x509_certificate_format type)
{
	int ret, ret2;

	if ((ret = read_ca_file(res, CAFILE, type)) < 0)
		return ret;

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk;

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk,
	     "rsa_public_key")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}


	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.modulus", 
		str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.publicExponent", 
		str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&params[0]);
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}


/* reads p,q and g 
 * from the certificate 
 * params[0-2]
 */
static int _read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk;

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.Dss-Parms", &spk,
	     "dsa_parms")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}

	/* FIXME: If the parameters are not included in the certificate
	 * then the issuer's parameters should be used.
	 */

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.p", str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read q */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.q", str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		_gnutls_mpi_release(&params[0]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read g */
	
	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.g", str, sizeof(str)-1, &params[2])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		_gnutls_mpi_release(&params[0]);
		_gnutls_mpi_release(&params[1]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}

/* reads DSA's Y
 * from the certificate 
 * params[3]
 */
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk;

	if ( (result=_gnutls_asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey", &spk,
	     "dsa_public_key")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_public_key", str, sizeof(str)-1, &params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}


/* Extracts DSA and RSA parameters from a certificate.
 */
static 
int _gnutls_extract_x509_cert_mpi_params( const char* ALGO_OID, gnutls_cert * gCert,
	ASN1_TYPE c2, const char* name, char* tmpstr, int tmpstr_size) {
int len, result;
char name1[128];

	_gnutls_str_cpy( name1, sizeof(name1), name);
	_gnutls_str_cat( name1, sizeof(name1), ".tbsCertificate.subjectPublicKeyInfo.subjectPublicKey");

	len = tmpstr_size - 1;
	result =
	    asn1_read_value
	    (c2, name1, tmpstr, &len);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	gCert->subject_pk_algorithm = _gnutls_x509_oid2pk_algorithm( ALGO_OID);
	
	switch( gCert->subject_pk_algorithm) {
	case GNUTLS_PK_RSA:
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		if ((sizeof(gCert->params) / sizeof(GNUTLS_MPI)) < RSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the GNUTLS_MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _gnutls_x509_read_rsa_params(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		gCert->params_size = RSA_PUBLIC_PARAMS;
		
		return 0;
		break;
	case GNUTLS_PK_DSA:
		/* params[0] is p,
		 * params[1] is q,
		 * params[2] is q,
		 * params[3] is pub.
		 */

		if ((sizeof(gCert->params) / sizeof(GNUTLS_MPI)) < DSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the GNUTLS_MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _gnutls_x509_read_dsa_pubkey(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}

		/* Now read the parameters
		 */
		_gnutls_str_cpy( name1, sizeof(name1), name);
		_gnutls_str_cat( name1, sizeof(name1), ".tbsCertificate.subjectPublicKeyInfo.algorithm.parameters");

		len = tmpstr_size - 1;
		result =
		    asn1_read_value(c2, name1, tmpstr, &len);

		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		if ((result =
		     _read_dsa_params(tmpstr, len, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		gCert->params_size = DSA_PUBLIC_PARAMS;
		
		return 0;
		break;

	default:
		/* other types like DH
		 * currently not supported
		 */
		gnutls_assert();
		_gnutls_log("X509 certificate: Found algorithm: %s\n", ALGO_OID);

		gCert->subject_pk_algorithm = GNUTLS_PK_UNKNOWN;

		return GNUTLS_E_X509_CERTIFICATE_ERROR;
	}
}



#define X509_SIG_SIZE 1024

/* This function will convert a der certificate, to a format
 * (structure) that gnutls can understand and use. Actually the
 * important thing on this function is that it extracts the 
 * certificate's (public key) parameters.
 *
 * The noext flag is used to complete the handshake even if the
 * extensions found in the certificate are unsupported and critical. 
 * The critical extensions will be catched by the verification functions.
 */
int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert,
	ConvFlags fast /* if non zero do not parse the whole certificate */)
{
	int result = 0;
	ASN1_TYPE c2;
	opaque str[MAX_X509_CERT_SIZE];
	char oid[128];
	int len = sizeof(str);

	memset(gCert, 0, sizeof(gnutls_cert));

	gCert->cert_type = GNUTLS_CRT_X509;

	if ( !(fast & CERT_NO_COPY)) {
		if (_gnutls_set_datum(&gCert->raw, derCert.data, derCert.size) < 0) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
	} else
		/* now we have 0 or a bitwise or of things to decode */
		fast ^= CERT_NO_COPY;


	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &c2,
	     "cert"))
	    != ASN1_SUCCESS) {
		gnutls_assert();
		_gnutls_free_datum( &gCert->raw);
		return _gnutls_asn2err(result);
	}

	if (fast & CERT_ONLY_EXTENSIONS) {
		result = asn1_der_decoding_element( &c2, "cert.tbsCertificate.extensions",
			derCert.data, derCert.size, NULL);

		if (result != ASN1_SUCCESS) {
			/* couldn't decode DER */
	
			_gnutls_log("X509 certificate: Decoding error %d\n", result);
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return _gnutls_asn2err(result);
		}
	}

	if (fast & CERT_ONLY_PUBKEY) {
		result = asn1_der_decoding_element( &c2, "cert.tbsCertificate.subjectPublicKeyInfo",
			derCert.data, derCert.size, NULL);

		if (result != ASN1_SUCCESS) {
			/* couldn't decode DER */
	
			_gnutls_log("X509 certificate: Decoding error %d\n", result);
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return _gnutls_asn2err(result);
		}
	}
	
	if (fast==0) {
		result = asn1_der_decoding(&c2, derCert.data, derCert.size, 
			NULL);

		if (result != ASN1_SUCCESS) {
			/* couldn't decode DER */
			_gnutls_log("X509 certificate: Decoding error %d\n", result);

			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return _gnutls_asn2err(result);
		}
	}

	
	if (fast==0) { /* decode all */
		len = gCert->signature.size = X509_SIG_SIZE;
		gCert->signature.data = gnutls_malloc( gCert->signature.size);
		if (gCert->signature.data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		result =
		    asn1_read_value
		    (c2, "cert.signature", gCert->signature.data, &len);

		if ((len % 8) != 0) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			_gnutls_free_datum( &gCert->signature);
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
		}
	
		len /= 8;		/* convert to bytes */
		gCert->signature.size = len; /* put the actual sig size */

		gCert->expiration_time =
		    _gnutls_x509_get_time(c2, "cert.tbsCertificate.validity.notAfter");
		gCert->activation_time =
		    _gnutls_x509_get_time(c2, "cert.tbsCertificate.validity.notBefore");

		gCert->version = _gnutls_x509_get_version(c2, "cert");
		if (gCert->version < 0) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return GNUTLS_E_ASN1_GENERIC_ERROR;  
		}
	}

	if (fast & CERT_ONLY_PUBKEY || fast == 0) {
		len = sizeof(oid) - 1;
		result =
		    asn1_read_value
		    (c2,
		     "cert.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
		     oid, &len);

		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return _gnutls_asn2err(result);
		}

		if ( (result=_gnutls_extract_x509_cert_mpi_params( oid, gCert, c2, "cert", str, sizeof(str))) < 0) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return result;
		}
	}

	if (fast & CERT_ONLY_EXTENSIONS || fast == 0) {
		if ((result =
		     _gnutls_get_ext_type(c2,
					  "cert.tbsCertificate.extensions",
					  gCert, fast)) < 0) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			_gnutls_free_datum( &gCert->raw);
			return result;
		}

	}

	asn1_delete_structure(&c2);

	return 0;

}

/* Returns 0 if it's ok to use the gnutls_kx_algorithm with this 
 * certificate (uses the KeyUsage field). 
 */
int _gnutls_check_x509_key_usage( const gnutls_cert * cert,
				    gnutls_kx_algorithm alg)
{
	uint16 keyUsage;
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


