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

/* Here we only read subjectAltName, in case of
 * dnsName. Otherwise we read nothing.
 */
static int _extract_subjectAltName( char* subjectAltName, opaque* extnValue, int extnValueLen) {
node_asn* ext;
char counter[MAX_INT_DIGITS];
char name[1024];
char str[1024];
int len, k, result;

	subjectAltName[0] = 0;
	
	if (asn1_create_structure
	    ( _gnutls_get_pkix(), "PKIX1Implicit88.GeneralNames", &ext, 
	    	"san") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_der ( ext, extnValue, extnValueLen);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	k = 1;
	for (;;) {
		strcpy(name, "san.?");
		_gnutls_int2str(k, counter);
		strcat(name, counter);

		len = sizeof(str) - 1;
		result = asn1_read_value(ext, name, str, &len);
		if (result == ASN_ELEMENT_NOT_FOUND) break;
		
		if (strcmp( str, "dNSName") == 0) {
			strcat( name, "dNSName");
			len = sizeof( str) -1;
			result = asn1_read_value(ext, name, str, &len);

			if (result != ASN_OK) {
				gnutls_assert();
				asn1_delete_structure(ext);
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}
			
			strncpy( subjectAltName, str, GMIN( len, X509_CN_SIZE-1));
			subjectAltName[X509_CN_SIZE-1] = 0;
			
			break;
		}
		k++;
	}

	asn1_delete_structure(ext);
	return 0;
}

/* Here we only extract the KeyUsage field
 */
static int _extract_keyUsage( char* keyUsage, opaque* extnValue, int extnValueLen) {
node_asn* ext;
char str[128];
int len, result;

	
	if (asn1_create_structure
	    ( _gnutls_get_pkix(), "PKIX1Implicit88.KeyUsage", &ext, 
	    	"ku") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_der ( ext, extnValue, extnValueLen);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "ku", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	keyUsage[0] = str[0];

	asn1_delete_structure(ext);

	return 0;
}

static int _extract_basicConstraints( int* CA, opaque* extnValue, int extnValueLen) {
node_asn* ext;
char str[128];
int len, result;

	
	if (asn1_create_structure
	    ( _gnutls_get_pkix(), "PKIX1Implicit88.BasicConstraints", &ext, 
	    	"bc") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_der ( ext, extnValue, extnValueLen);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(ext, "bc.cA", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(ext);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	asn1_delete_structure(ext);

	if ( strcmp(str, "TRUE")==0) *CA = 1;
	else *CA = 0;


	return 0;
}


static int _parse_extension( gnutls_cert* cert, char* extnID, char* critical, char* extnValue, int extnValueLen) {

	if (strcmp( extnID, "2 5 29 14")==0) { /* subject Key ID */
		/* we don't use it */
		return 0;
	}

	if (strcmp( extnID, "2 5 29 15")==0) { /* Key Usage */
		return _extract_keyUsage( &cert->keyUsage, extnValue, extnValueLen);
	}

	if (strcmp( extnID, "2 5 29 19")==0) { /* Basic Constraints */
		/* actually checks if a certificate belongs to
		 * a Certificate Authority.
		 */
		return _extract_basicConstraints( &cert->CA, extnValue, extnValueLen);
	}

	if (strcmp( extnID, "2 5 29 17")==0) { /* subjectAltName */
		return _extract_subjectAltName( cert->subjectAltName, extnValue, extnValueLen);
	}

#ifdef DEBUG
	_gnutls_log("CERT[%s]: Unsupported Extension: %s, %s\n", cert->cert_info.common_name, extnID, critical);
#endif
	
	if (strcmp( critical, "TRUE")==0) {
		gnutls_assert();
		return GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION;
	}
	return 0;

}

/* This function will attempt to parse Extensions in
 * an X509v3 certificate
 */
int _gnutls_get_ext_type( node_asn *rasn, char *root, gnutls_cert *cert)
{
	int k, result, len;
	char name[128], name2[128], counter[MAX_INT_DIGITS];
	char str[1024];
	char critical[10];
	char extnID[128];
	char extnValue[128];

	k = 0;
	do {
		k++;
		
		strcpy(name, root);
		strcat(name, ".?");
		_gnutls_int2str(k, counter);
		strcat(name, counter);

		len = sizeof(str) - 1;
		result = asn1_read_value( rasn, name, str, &len);
		
		/* move to next
		 */

		if (result==ASN_ELEMENT_NOT_FOUND) break;

		do {

			strcpy(name2, name);
			strcat(name2, ".extnID");

			len = sizeof(extnID) - 1;
			result = asn1_read_value( rasn, name2, extnID, &len);

			if (result==ASN_ELEMENT_NOT_FOUND) break;
			else
				if (result != ASN_OK) {
					gnutls_assert();
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}

			strcpy(name2, name);
			strcat(name2, ".critical");
			
			len = sizeof(critical) - 1;
			result = asn1_read_value( rasn, name2, critical, &len);

			if (result==ASN_ELEMENT_NOT_FOUND) break;
			else
				if (result != ASN_OK) {
					gnutls_assert();
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}
				
			strcpy(name2, name);
			strcat(name2, ".extnValue");

			len = sizeof( extnValue) - 1;
			result = asn1_read_value( rasn, name2, extnValue, &len);

			if (result==ASN_ELEMENT_NOT_FOUND) break;
			else
				if (result != ASN_OK) {
					gnutls_assert();
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}

			/* Handle Extension */
			if ( (result=_parse_extension( cert, extnID, critical, extnValue, len)) < 0) {
				gnutls_assert();
				return result;
			}
			
			
		} while (0);
	} while (1);

	if (result==ASN_ELEMENT_NOT_FOUND)
		return 0;
	else 
		return GNUTLS_E_ASN1_PARSING_ERROR;
}
