/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
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

/* Functions that relate to the X.509 extension parsing.
 */

#include <gnutls_int.h>
#include <libtasn1.h>
#include <gnutls_num.h>
#include <gnutls_cert.h>
#include <gnutls_errors.h>
#include <gnutls_global.h>
#include "debug.h"
#include <gnutls_str.h>
#include <gnutls_x509.h>

/* This file contains code to parse the X.509 certificate
 * extensions. Not all the PKIX extensions are supported.
 */

/* Here we only extract the KeyUsage field
 */
static int _extract_keyUsage(uint16 *keyUsage, opaque * extnValue,
			     int extnValueLen)
{
	ASN1_TYPE ext;
	char str[10];
	int len, result;

	keyUsage[0] = 0;

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.KeyUsage", &ext,
	     "ku")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&ext, extnValue, extnValueLen, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "ku", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}

	keyUsage[0] = str[0];

	asn1_delete_structure(&ext);

	return 0;
}

static int _extract_basicConstraints(int *CA, opaque * extnValue,
				     int extnValueLen)
{
	ASN1_TYPE ext;
	char str[128];
	int len, result;

	*CA = 0;

	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.BasicConstraints", &ext,
	     "bc")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&ext, extnValue, extnValueLen, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "bc.cA", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}

	asn1_delete_structure(&ext);

	if (strcmp(str, "TRUE") == 0)
		*CA = 1;
	else
		*CA = 0;


	return 0;
}


/*
 * If no_critical_ext is non zero, then unsupported critical extensions
 * do not lead into a fatal error.
 */
static int _parse_extension(gnutls_cert * cert, char *extnID,
			    char *critical, char *extnValue,
			    int extnValueLen, int no_critical_ext)
{

	if (strcmp(extnID, "2 5 29 14") == 0) {	/* subject Key ID */
		/* we don't use it */
		return 0;
	}

	if (strcmp(extnID, "2 5 29 15") == 0) {	/* Key Usage */
		return _extract_keyUsage(&cert->keyUsage, extnValue, extnValueLen);
	}

	if (strcmp(extnID, "2 5 29 19") == 0) {	/* Basic Constraints */
		/* actually checks if a certificate belongs to
		 * a Certificate Authority.
		 */
		return _extract_basicConstraints(&cert->CA, extnValue,
						 extnValueLen);
	}

	_gnutls_x509_log("X509_EXT: CERT[%s]: Unsupported Extension: %s, %s\n",
		    GET_CN(cert->raw), extnID, critical);

	if (strcmp(critical, "TRUE") == 0 && no_critical_ext == 0) {
		gnutls_assert();
		return GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION;
	}
	return 0;

}

/* This function will attempt to parse Extensions in
 * an X509v3 certificate
 *
 * If no_critical_ext is non zero, then unsupported critical extensions
 * do not lead into a fatal error.
 */
int _gnutls_get_ext_type(ASN1_TYPE rasn, const char *root, gnutls_cert * cert,
	int no_critical_ext)
{
	int k, result, len;
	char name[128], name2[128], counter[MAX_INT_DIGITS];
	char str[1024];
	char critical[10];
	char extnID[128];
	char extnValue[256];

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), root);
		_gnutls_str_cat(name, sizeof(name), ".?"); 
		_gnutls_int2str(k, counter);
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;
		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */

		if (result == ASN1_ELEMENT_NOT_FOUND)
			break;

		do {

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnID");

			len = sizeof(extnID) - 1;
			result =
			    asn1_read_value(rasn, name2, extnID, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".critical"); 

			len = sizeof(critical) - 1;
			result =
			    asn1_read_value(rasn, name2, critical, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnValue"); 

			len = sizeof(extnValue) - 1;
			result =
			    asn1_read_value(rasn, name2, extnValue, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else {
				if (result == ASN1_MEM_ERROR
				    && strcmp(critical, "FALSE") == 0) {

					_gnutls_x509_log
					    ("X509_EXT: Cannot parse extension: %s. Too small buffer.",
					     extnID);

					continue;
				}
				if (result != ASN1_SUCCESS) {
					gnutls_assert();
					return _gnutls_asn2err(result);
				}
			}

			/* Handle Extension */
			if ((result =
			     _parse_extension(cert, extnID, critical,
					      extnValue, len, no_critical_ext)) < 0) {
				gnutls_assert();
				return result;
			}


		} while (0);
	} while (1);

	if (result == ASN1_ELEMENT_NOT_FOUND)
		return 0;
	else
		return _gnutls_asn2err(result);
}

/* This function will attempt to return the requested extension found in
 * the given X509v3 certificate. The return value is allocated and stored into
 * ret.
 */
int _gnutls_get_extension( const gnutls_datum * cert, const char* extension_id, gnutls_datum* ret)
{
	int k, result, len;
	char name[128], name2[128], counter[MAX_INT_DIGITS];
	char str[1024];
	char critical[10];
	char extnID[128];
	char extnValue[256];
	ASN1_TYPE rasn;

	ret->data = NULL;
	ret->size = 0;
	
	if ((result=_gnutls_asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.Certificate", &rasn,
	     "certificate2"))
	    != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding(&rasn, cert->data, cert->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */

		_gnutls_x509_log("X509_EXT: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(&rasn);
		return _gnutls_asn2err(result);
	}

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), "certificate2.tbsCertificate.extensions.?"); 
		_gnutls_int2str(k, counter); 
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;
		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */

		if (result == ASN1_ELEMENT_NOT_FOUND) {
			gnutls_assert();
			break;
		}

		do {

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnID"); 

			len = sizeof(extnID) - 1;
			result =
			    asn1_read_value(rasn, name2, extnID, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND) {
				gnutls_assert();
				break;
			} else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".critical"); 

			len = sizeof(critical) - 1;
			result =
			    asn1_read_value(rasn, name2, critical, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND) {
				gnutls_assert();
				break;
			} else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				asn1_delete_structure(&rasn);
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnValue"); 

			len = sizeof(extnValue) - 1;
			result =
			    asn1_read_value(rasn, name2, extnValue, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else {
				if (result == ASN1_MEM_ERROR
				    && strcmp(critical, "FALSE") == 0) {

					_gnutls_x509_log
					    ("X509_EXT: Cannot parse extension: %s. Too small buffer.",
					     extnID);

					continue;
				}
				if (result != ASN1_SUCCESS) {
					gnutls_assert();
					asn1_delete_structure(&rasn);
					return _gnutls_asn2err(result);
				}
			}

			/* Handle Extension */
			if ( strcmp(extnID, extension_id)==0) { /* extension was found */
				asn1_delete_structure(&rasn);
				ret->data = gnutls_malloc( len);
				if (ret->data==NULL)
					return GNUTLS_E_MEMORY_ERROR;	

				ret->size = len;
				memcpy( ret->data, extnValue, len);
				
				return 0;
			}


		} while (0);
	} while (1);

	asn1_delete_structure(&rasn);


	if (result == ASN1_ELEMENT_NOT_FOUND) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	} else {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
}
