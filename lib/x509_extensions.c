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

#include <gnutls_int.h>
#include <x509_asn1.h>
#include <x509_der.h>
#include <gnutls_num.h>
#include <gnutls_cert.h>
#include <gnutls_errors.h>
#include <gnutls_global.h>
#include "debug.h"
#include <gnutls_str.h>


/* Here we only extract the KeyUsage field
 */
static int _extract_keyUsage(char *keyUsage, opaque * extnValue,
			     int extnValueLen)
{
	node_asn *ext;
	char str[10];
	int len, result;

	keyUsage[0] = 0;
	
	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.KeyUsage", &ext,
	     "ku") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_der(ext, extnValue, extnValueLen);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return 0;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "ku", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return 0;
	}

	keyUsage[0] = str[0];

	asn1_delete_structure(ext);

	return 0;
}

static int _extract_basicConstraints(int *CA, opaque * extnValue,
				     int extnValueLen)
{
	node_asn *ext;
	char str[128];
	int len, result;

	*CA = 0;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.BasicConstraints", &ext,
	     "bc") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_der(ext, extnValue, extnValueLen);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return 0;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "bc.cA", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return 0;
	}

	asn1_delete_structure(ext);

	if (strcmp(str, "TRUE") == 0)
		*CA = 1;
	else
		*CA = 0;


	return 0;
}


static int _parse_extension(gnutls_cert * cert, char *extnID,
			    char *critical, char *extnValue,
			    int extnValueLen)
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

	_gnutls_log("X509_ext: CERT[%s]: Unsupported Extension: %s, %s\n",
		    GET_CN(cert->raw), extnID, critical);

	if (strcmp(critical, "TRUE") == 0) {
		gnutls_assert();
		return GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION;
	}
	return 0;

}

/* This function will attempt to parse Extensions in
 * an X509v3 certificate
 */
int _gnutls_get_ext_type(node_asn * rasn, char *root, gnutls_cert * cert)
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

		if (result == ASN_ELEMENT_NOT_FOUND)
			break;

		do {

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnID");

			len = sizeof(extnID) - 1;
			result =
			    asn1_read_value(rasn, name2, extnID, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".critical"); 

			len = sizeof(critical) - 1;
			result =
			    asn1_read_value(rasn, name2, critical, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnValue"); 

			len = sizeof(extnValue) - 1;
			result =
			    asn1_read_value(rasn, name2, extnValue, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else {
				if (result == ASN_MEM_ERROR
				    && strcmp(critical, "FALSE") == 0) {

					_gnutls_log
					    ("X509_ext: Cannot parse extension: %s. Too small buffer.",
					     extnID);

					continue;
				}
				if (result != ASN_OK) {
					gnutls_assert();
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}
			}

			/* Handle Extension */
			if ((result =
			     _parse_extension(cert, extnID, critical,
					      extnValue, len)) < 0) {
				gnutls_assert();
				return result;
			}


		} while (0);
	} while (1);

	if (result == ASN_ELEMENT_NOT_FOUND)
		return 0;
	else
		return GNUTLS_E_ASN1_PARSING_ERROR;
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
	node_asn* rasn;

	ret->data = NULL;
	ret->size = 0;
	
	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &rasn,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result =
	    asn1_get_der(rasn, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_ext: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(rasn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), "certificate2"); 
		_gnutls_str_cat(name, sizeof(name), ".?"); 
		_gnutls_int2str(k, counter); 
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;
		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */

		if (result == ASN_ELEMENT_NOT_FOUND)
			break;

		do {

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnID"); 

			len = sizeof(extnID) - 1;
			result =
			    asn1_read_value(rasn, name2, extnID, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".critical"); 

			len = sizeof(critical) - 1;
			result =
			    asn1_read_value(rasn, name2, critical, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				asn1_delete_structure(rasn);
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnValue"); 

			len = sizeof(extnValue) - 1;
			result =
			    asn1_read_value(rasn, name2, extnValue, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else {
				if (result == ASN_MEM_ERROR
				    && strcmp(critical, "FALSE") == 0) {

					_gnutls_log
					    ("X509_ext: Cannot parse extension: %s. Too small buffer.",
					     extnID);

					continue;
				}
				if (result != ASN_OK) {
					gnutls_assert();
					asn1_delete_structure(rasn);
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}
			}

			/* Handle Extension */
			if ( strcmp(extnID, extension_id)==0) { /* extension was found */
				asn1_delete_structure(rasn);
				ret->data = gnutls_malloc( len);
				if (ret->data==NULL)
					return GNUTLS_E_MEMORY_ERROR;	

				ret->size = len;
				memcpy( ret->data, extnValue, len);
				
				return 0;
			}


		} while (0);
	} while (1);

	asn1_delete_structure(rasn);


	if (result == ASN_ELEMENT_NOT_FOUND)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	else
		return GNUTLS_E_ASN1_PARSING_ERROR;
}
