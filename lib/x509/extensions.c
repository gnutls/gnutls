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

/* Functions that relate to the X.509 extension parsing.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_global.h>
#include <libtasn1.h>
#include <common.h>
#include <x509.h>

/* This function will attempt to return the requested extension found in
 * the given X509v3 certificate. The return value is allocated and stored into
 * ret.
 *
 * Critical will be either 0 or 1.
 */
int _gnutls_x509_crt_get_extension( gnutls_x509_crt cert, const char* extension_id, 
	int indx, gnutls_datum* ret, int * _critical)
{
	int k, result, len;
	char name[128], name2[128], counter[MAX_INT_DIGITS];
	char str[1024];
	char str_critical[10];
	int critical = 0;
	char extnID[128];
	char extnValue[256];
	int indx_counter = 0;

	ret->data = NULL;
	ret->size = 0;
	
	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), "tbsCertificate.extensions.?"); 
		_gnutls_int2str(k, counter); 
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;
		result = asn1_read_value(cert->cert, name, str, &len);

		/* move to next
		 */

		if (result == ASN1_ELEMENT_NOT_FOUND) {
			break;
		}

		do {

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnID"); 

			len = sizeof(extnID) - 1;
			result =
			    asn1_read_value(cert->cert, name2, extnID, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND) {
				gnutls_assert();
				break;
			} else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".critical"); 

			len = sizeof(str_critical);
			result =
			    asn1_read_value(cert->cert, name2, str_critical, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND) {
				gnutls_assert();
				break;
			} else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			if (strcmp( str_critical, "TRUE")==0)
				critical = 1;
			else critical = 0;

			_gnutls_str_cpy(name2, sizeof(name2), name);
			_gnutls_str_cat(name2, sizeof(name2), ".extnValue"); 

			len = sizeof(extnValue) - 1;
			result =
			    asn1_read_value(cert->cert, name2, extnValue, &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else {
				if (result == ASN1_MEM_ERROR
				    && critical == 0) {

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
			if ( strcmp(extnID, extension_id)==0 && indx == indx_counter++) { 
				/* extension was found */

				ret->data = gnutls_malloc( len);
				if (ret->data==NULL)
					return GNUTLS_E_MEMORY_ERROR;	

				ret->size = len;
				memcpy( ret->data, extnValue, len);
				
				if (_critical)
					*_critical = critical;
				
				return 0;
			}


		} while (0);
	} while (1);

	if (result == ASN1_ELEMENT_NOT_FOUND) {
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	} else {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
}

/* Here we only extract the KeyUsage field, from the DER encoded
 * extension.
 */
int _gnutls_x509_ext_extract_keyUsage(uint16 *keyUsage, opaque * extnValue,
			     int extnValueLen)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	char str[10];
	int len, result;

	keyUsage[0] = 0;

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.KeyUsage", &ext
	     )) != ASN1_SUCCESS) {
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
	result = asn1_read_value(ext, "", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}

	keyUsage[0] = str[0];

	asn1_delete_structure(&ext);

	return 0;
}

/* extract the basicConstraints from the DER encoded extension
 */
int _gnutls_x509_ext_extract_basicConstraints(int *CA, opaque * extnValue,
				     int extnValueLen)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	char str[128];
	int len, result;

	*CA = 0;

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.BasicConstraints", &ext
	     )) != ASN1_SUCCESS) {
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
	result = asn1_read_value(ext, "cA", str, &len);
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
