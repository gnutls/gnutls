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
#include <extensions.h>
#include <gnutls_datum.h>

/* This function will attempt to return the requested extension found in
 * the given X509v3 certificate. The return value is allocated and stored into
 * ret.
 *
 * Critical will be either 0 or 1.
 *
 * If the extension does not exist, GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will
 * be returned.
 */
int _gnutls_x509_crt_get_extension( gnutls_x509_crt cert, const char* extension_id, 
	int indx, gnutls_datum* ret, unsigned int * _critical)
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

/* This function will attempt to return the requested extension OID found in
 * the given X509v3 certificate. 
 *
 * If you have passed the last extension, GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will
 * be returned.
 */
int _gnutls_x509_crt_get_extension_oid( gnutls_x509_crt cert,
	int indx, void* oid, size_t* sizeof_oid)
{
	int k, result, len;
	char name[128], name2[128], counter[MAX_INT_DIGITS];
	char str[1024];
	char str_critical[10];
	int critical = 0;
	char extnID[128];
	char extnValue[256];
	int indx_counter = 0;

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
			if ( indx == indx_counter++) { 
				len = strlen( extnID) + 1;

				if ( *sizeof_oid < (uint)len) {
					*sizeof_oid = len;
					gnutls_assert();
					return GNUTLS_E_SHORT_MEMORY_BUFFER;
				}
				
				memcpy( oid, extnID, len);
				*sizeof_oid = len - 1;

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

/* This function will attempt to set the requested extension in
 * the given X509v3 certificate. 
 *
 * Critical will be either 0 or 1.
 */
int _gnutls_x509_crt_set_extension( gnutls_x509_crt cert, const char* extension_id, 
	const gnutls_datum* ext_data, unsigned int critical)
{
	int result;
	const char *str;

	/* Add a new extension in the list.
	 */
	result = asn1_write_value(cert->cert, "tbsCertificate.extensions", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value(cert->cert, "tbsCertificate.extensions.?LAST.extnID", extension_id, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (critical==0) str = "FALSE";
	else str = "TRUE";
	

	result = asn1_write_value(cert->cert, "tbsCertificate.extensions.?LAST.critical", str, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_write_value( cert->cert, "tbsCertificate.extensions.?LAST.extnValue",
		ext_data, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}
	
	return 0;
}


/* Here we only extract the KeyUsage field, from the DER encoded
 * extension.
 */
int _gnutls_x509_ext_extract_keyUsage(uint16 *keyUsage, opaque * extnValue,
			     int extnValueLen)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	int len, result;
	uint8 str[2];

	str[0] = str[1] = 0;
	*keyUsage = 0;

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

	len = sizeof(str);
	result = asn1_read_value(ext, "", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return 0;
	}
	
	*keyUsage = str[0] | (str[1] << 8);

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

/* generate the basicConstraints in a DER encoded extension
 * Use 0 or 1 (TRUE) for CA.
 */
int _gnutls_x509_ext_gen_basicConstraints(int CA, gnutls_datum* der_ext)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	const char *str;
	int result;

	if (CA == 0) str = "FALSE";
	else str = "TRUE";

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.BasicConstraints", &ext);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value(ext, "cA", str, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return _gnutls_asn2err(result);
	}

	asn1_write_value(ext, "pathLenConstraint", NULL, 0);
	
	result = _gnutls_x509_der_encode( ext, "", der_ext, 0);

	asn1_delete_structure(&ext);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

/* generate the keyUsage in a DER encoded extension
 * Use an ORed SEQUENCE of GNUTLS_KEY_* for usage.
 */
int _gnutls_x509_ext_gen_keyUsage(uint16 usage, gnutls_datum* der_ext)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	int result;
	uint8 str[2];

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.KeyUsage", &ext);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	str[0] = usage & 0xff;
	str[1] = usage >> 8;

	result = asn1_write_value(ext, "", str, 9);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_der_encode( ext, "", der_ext, 0);

	asn1_delete_structure(&ext);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

/* generate the subject alternative name in a DER encoded extension
 */
int _gnutls_x509_ext_gen_subject_alt_name(gnutls_x509_subject_alt_name type, 
	const char* data_string, gnutls_datum* der_ext)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	const char *str;
	char name[128];
	int result;

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.SubjectAltName", &ext);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value( ext, "", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	switch(type) {
		case GNUTLS_SAN_DNSNAME:
			str = "dNSName";
			break;
		case GNUTLS_SAN_RFC822NAME:
			str = "rfc822Name";
			break;
		case GNUTLS_SAN_URI:
			str = "uniformResourceIdentifier";
			break;
		case GNUTLS_SAN_IPADDRESS:
			str = "iPAddress";
			break;
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}

	result = asn1_write_value( ext, "?LAST", str, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	_gnutls_str_cpy( name, sizeof(name), "?LAST.");
	_gnutls_str_cat( name, sizeof(name), str);

	result = asn1_write_value(ext, name, data_string, strlen(data_string));
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_der_encode( ext, "", der_ext, 0);

	asn1_delete_structure(&ext);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

/* generate the SubjectKeyID in a DER encoded extension
 */
int _gnutls_x509_ext_gen_key_id(const void* id, size_t id_size, gnutls_datum* der_ext)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	int result;

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.SubjectKeyIdentifier", &ext);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value(ext, "", id, id_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&ext);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_der_encode( ext, "", der_ext, 0);

	asn1_delete_structure(&ext);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}


int _gnutls_x509_ext_gen_crl_dist_points(gnutls_x509_subject_alt_name type, 
	const void* data_string, unsigned int reason_flags, gnutls_datum* der_ext)
{
	ASN1_TYPE ext = ASN1_TYPE_EMPTY;
	gnutls_datum name = {NULL, 0};
	int result;
	uint8 reasons[2];

	reasons[0] = reason_flags & 0xff;
	reasons[1] = reason_flags >> 8;

	result = _gnutls_x509_ext_gen_subject_alt_name( type, data_string, &name);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.WritableCRLDistributionPoints", &ext);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_write_value( ext, "", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (reason_flags) {
		result = asn1_write_value( ext, "?LAST.reasons", reasons, 9);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}
	} else {
		result = asn1_write_value( ext, "?LAST.reasons", NULL, 0);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}
	}

	result = asn1_write_value( ext, "?LAST.cRLIssuer", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_write_value( ext, "?LAST.distributionPoint", "fullName", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_write_value( ext, "?LAST.distributionPoint.fullName", name.data, name.size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = _gnutls_x509_der_encode( ext, "", der_ext, 0);

	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = 0;

cleanup:
	_gnutls_free_datum( &name);
	asn1_delete_structure(&ext);

	return result;
}
