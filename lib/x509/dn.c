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

#include <libtasn1.h>
#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_str.h>
#include <common.h>
#include <gnutls_num.h>
#include <dn.h>

/* This file includes all the required to parse an X.509 Distriguished
 * Name (you need a parser just to read a name in the X.509 protoocols!!!)
 */


/* Converts the given OID to an ldap acceptable string or
 * a dotted OID. 
 */
static const char *oid2ldap_string(const char *oid)
{
	const char *ret;

	ret = _gnutls_x509_oid2ldap_string(oid);
	if (ret)
		return ret;

	/* else return the OID in dotted format */
	return oid;
}

/* Escapes a string following the rules from RFC2253.
 */
static char *str_escape(char *str, char *buffer, unsigned int buffer_size)
{
	int str_length, j, i;

	if (str == NULL || buffer == NULL)
		return NULL;

	str_length = GMIN(strlen(str), buffer_size - 1);

	for (i = j = 0; i < str_length; i++) {
		if (str[i] == ',' || str[i] == '+' || str[i] == '"'
		    || str[i] == '\\' || str[i] == '<' || str[i] == '>'
		    || str[i] == ';')
			buffer[j++] = '\\';

		buffer[j++] = str[i];
	}

	/* null terminate the string */
	buffer[j] = 0;

	return buffer;
}

/* Parses an X509 DN in the asn1_struct, and puts the output into
 * the string buf. The output is an LDAP encoded DN.
 *
 * asn1_rdn_name must be a string in the form "tbsCertificate.issuer.rdnSequence".
 * That is to point in the rndSequence.
 */
int _gnutls_x509_parse_dn(ASN1_TYPE asn1_struct,
			  const char *asn1_rdn_name, char *buf,
			  int *sizeof_buf)
{
	gnutls_string out_str;
	int k2, k1, result;
	char tmpbuffer1[64];
	char tmpbuffer2[64];
	char tmpbuffer3[64];
	char counter[MAX_INT_DIGITS];
	char value[256];
	char escaped[256];
	const char *ldap_desc;
	char oid[128];
	int len, printable;

	if (*sizeof_buf == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	buf[0] = 0;

	_gnutls_string_init(&out_str, gnutls_malloc, gnutls_realloc,
			    gnutls_free);

	k1 = 0;
	do {

		k1++;
		/* create a string like "tbsCertList.issuer.rdnSequence.?1"
		 */
		_gnutls_int2str(k1, counter);
		_gnutls_str_cpy(tmpbuffer1, sizeof(tmpbuffer1),
				asn1_rdn_name);
		if (strlen(tmpbuffer1) > 0)
			_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), ".");
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), "?");
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), counter);

		len = sizeof(value) - 1;
		result =
		    asn1_read_value(asn1_struct, tmpbuffer1, value, &len);

		if (result == ASN1_ELEMENT_NOT_FOUND) {
			break;
		}

		if (result != ASN1_VALUE_NOT_FOUND) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}

		k2 = 0;

		do {		/* Move to the attibute type and values
				 */
			k2++;

			_gnutls_int2str(k2, counter);
			_gnutls_str_cpy(tmpbuffer2, sizeof(tmpbuffer2),
					tmpbuffer1);
			if (strlen( tmpbuffer2) > 0)
				_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2),
					".");
			_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2), "?");
			_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2),
					counter);

			/* Try to read the RelativeDistinguishedName attributes.
			 */

			len = sizeof(value) - 1;
			result =
			    asn1_read_value(asn1_struct, tmpbuffer2, value,
					    &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			if (result != ASN1_VALUE_NOT_FOUND) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

			/* Read the OID 
			 */
			_gnutls_str_cpy(tmpbuffer3, sizeof(tmpbuffer3),
					tmpbuffer2);
			_gnutls_str_cat(tmpbuffer3, sizeof(tmpbuffer3),
					".type");

			len = sizeof(oid) - 1;
			result =
			    asn1_read_value(asn1_struct, tmpbuffer3, oid,
					    &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

			/* Read the Value 
			 */
			_gnutls_str_cpy(tmpbuffer3, sizeof(tmpbuffer3),
					tmpbuffer2);
			_gnutls_str_cat(tmpbuffer3, sizeof(tmpbuffer3),
					".value");

			len = sizeof(value) - 1;
			result =
			    asn1_read_value(asn1_struct, tmpbuffer3, value,
					    &len);

			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

#define STR_APPEND(y) if ((result=_gnutls_string_append_str( &out_str, y)) < 0) { \
	gnutls_assert(); \
	goto cleanup; \
}
			/*   The encodings of adjoining RelativeDistinguishedNames are separated
			 *   by a comma character (',' ASCII 44).
			 */

			/*   Where there is a multi-valued RDN, the outputs from adjoining
			 *   AttributeTypeAndValues are separated by a plus ('+' ASCII 43)
			 *   character.
			 */
			if (k1 != 1) {	/* the first time do not append a comma */
				if (k2 != 1) { /* adjoining multi-value RDN */
					STR_APPEND("+");
				} else {
					STR_APPEND(",");
				}
			}

			ldap_desc = oid2ldap_string(oid);
			printable = _gnutls_x509_oid_data_printable(oid);

			if (printable == 1) {
				char string[256];
				int sizeof_string = sizeof(string);

				STR_APPEND(ldap_desc);
				STR_APPEND("=");
				if ((result =
				     _gnutls_x509_oid_data2string(oid,
								  value,
								  len,
								  string,
								  &sizeof_string))
				    < 0) {
					gnutls_assert();
					_gnutls_x509_log("Found OID: '%s' with value '%s'\n", 
						oid, _gnutls_bin2hex(value, len, escaped, sizeof(escaped)) );
					goto cleanup;
				}
				STR_APPEND(str_escape
					   (string, escaped,
					    sizeof(escaped)));
			} else {
				char *res;

				res =
				    _gnutls_bin2hex(value, len, escaped,
						    sizeof(escaped));
				if (res) {
					STR_APPEND(ldap_desc);
					STR_APPEND("=#");
					STR_APPEND(res);
				}
			}
		} while (1);

	} while (1);

	if (out_str.length >= (unsigned int) *sizeof_buf) {
		gnutls_assert();
		*sizeof_buf = out_str.length;
		result = GNUTLS_E_SHORT_MEMORY_BUFFER;
		goto cleanup;
	}

	if (buf) {
		memcpy(buf, out_str.data, out_str.length);
		buf[out_str.length] = 0;
	}
	*sizeof_buf = out_str.length;

	result = 0;

      cleanup:
	_gnutls_string_clear(&out_str);
	return result;
}

/* Parses an X509 DN in the asn1_struct, and searches for the
 * given OID in the DN.
 * The output will be encoded in the LDAP way. (#hex for non printable).
 *
 * asn1_rdn_name must be a string in the form "tbsCertificate.issuer.rdnSequence".
 * That is to point in the rndSequence.
 *
 * indx specifies which OID to return. Ie 0 means return the first specified
 * OID found, 1 the second etc.
 */
int _gnutls_x509_parse_dn_oid(ASN1_TYPE asn1_struct,
			      const char *asn1_rdn_name,
			      const char *given_oid, int indx, char *buf,
			      int *sizeof_buf)
{
	int k2, k1, result;
	char tmpbuffer1[64];
	char tmpbuffer2[64];
	char tmpbuffer3[64];
	char counter[MAX_INT_DIGITS];
	char value[200];
	char escaped[256];
	char oid[128];
	int len, printable;
	int i = 0;

	if (*sizeof_buf == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	buf[0] = 0;

	k1 = 0;
	do {

		k1++;
		/* create a string like "tbsCertList.issuer.rdnSequence.?1"
		 */
		_gnutls_int2str(k1, counter);
		_gnutls_str_cpy(tmpbuffer1, sizeof(tmpbuffer1),
				asn1_rdn_name);

		if (strlen( tmpbuffer1) > 0)
			_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), ".");
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), "?");
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), counter);

		len = sizeof(value) - 1;
		result =
		    asn1_read_value(asn1_struct, tmpbuffer1, value, &len);

		if (result == ASN1_ELEMENT_NOT_FOUND) {
			gnutls_assert();
			break;
		}

		if (result != ASN1_VALUE_NOT_FOUND) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}

		k2 = 0;

		do {		/* Move to the attibute type and values
				 */
			k2++;

			_gnutls_int2str(k2, counter);
			_gnutls_str_cpy(tmpbuffer2, sizeof(tmpbuffer2),
					tmpbuffer1);

			if (strlen( tmpbuffer2) > 0)
				_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2), ".");
			_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2),
					"?");
			_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2),
					counter);

			/* Try to read the RelativeDistinguishedName attributes.
			 */

			len = sizeof(value) - 1;
			result =
			    asn1_read_value(asn1_struct, tmpbuffer2, value,
					    &len);

			if (result == ASN1_ELEMENT_NOT_FOUND) {
				break;
			}
			if (result != ASN1_VALUE_NOT_FOUND) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

			/* Read the OID 
			 */
			_gnutls_str_cpy(tmpbuffer3, sizeof(tmpbuffer3),
					tmpbuffer2);
			_gnutls_str_cat(tmpbuffer3, sizeof(tmpbuffer3),
					".type");

			len = sizeof(oid) - 1;
			result =
			    asn1_read_value(asn1_struct, tmpbuffer3, oid,
					    &len);

			if (result == ASN1_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN1_SUCCESS) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

			if (strcmp(oid, given_oid) == 0 && indx == i++) { /* Found the OID */
				
				/* Read the Value 
				 */
				_gnutls_str_cpy(tmpbuffer3,
						sizeof(tmpbuffer3),
						tmpbuffer2);
				_gnutls_str_cat(tmpbuffer3,
						sizeof(tmpbuffer3),
						".value");

				len = sizeof(value) - 1;
				result =
				    asn1_read_value(asn1_struct,
						    tmpbuffer3, value,
						    &len);

				if (result != ASN1_SUCCESS) {
					gnutls_assert();
					result = _gnutls_asn2err(result);
					goto cleanup;
				}


				printable =
				    _gnutls_x509_oid_data_printable(oid);

				if (printable == 1) {
					if ((result =
					     _gnutls_x509_oid_data2string
					     (oid, value, len, buf,
					      sizeof_buf)) < 0) {
						gnutls_assert();
						goto cleanup;
					}

					return 0;
				} else {
					char *res;

					res =
					    _gnutls_bin2hex(value, len,
							    escaped,
							    sizeof
							    (escaped));
					if (res) {
						int size = strlen(res) + 1;
						if (size + 1 > *sizeof_buf) {
							*sizeof_buf = size;
							return
							    GNUTLS_E_SHORT_MEMORY_BUFFER;
						}
						*sizeof_buf = size; /* -1 for the null +1 for the '#' */
						
						if (buf) {
							strcpy(buf, "#");
							strcat(buf, res);
						}

						return 0;
					} else {
						gnutls_assert();
						return
						    GNUTLS_E_INTERNAL_ERROR;
					}
				}
			}
		} while (1);

	} while (1);

	gnutls_assert();

	result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

      cleanup:
	return result;
}

/* This will encode and write the AttributeTypeAndValue field.
 * 'multi' must be zero if writing an AttributeTypeAndValue, and 1 if Attribute.
 * In all cases only one value is written.
 */
int _gnutls_x509_encode_and_write_attribute( const char* given_oid, ASN1_TYPE asn1_struct, 
	const char* where, const unsigned char* data, int sizeof_data, int multi) 
{
const char *val_name;
char tmp[128];
ASN1_TYPE c2;
int result;


	/* Find how to encode the data.
	 */
	val_name = asn1_find_structure_from_oid( _gnutls_get_pkix(), given_oid);
	if (val_name == NULL) {
		gnutls_assert();
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	_gnutls_str_cpy( tmp, sizeof(tmp), "PKIX1.");
	_gnutls_str_cat( tmp, sizeof(tmp), val_name);

	result = asn1_create_element( _gnutls_get_pkix(), tmp, &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	tmp[0] = 0;

	if ((result=_gnutls_x509_oid_data_choice( given_oid)) > 0) {
		char* string_type;
		int i;

		string_type = "printableString";

		/* Check if the data is plain ascii, and use
		 * the UTF8 string type if not.
		 */
		for (i=0;i<sizeof_data;i++) {
			if (!isascii(data[i])) {
				string_type = "utf8String";
				break;
			}
		}

		/* if the type is a CHOICE then write the
		 * type we'll use.
		 */
		result = asn1_write_value( c2, "", string_type, 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			asn1_delete_structure( &c2);
			return _gnutls_asn2err(result);
		}

		_gnutls_str_cpy( tmp, sizeof(tmp), string_type);
	}

	result = asn1_write_value( c2, tmp, data, sizeof_data);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure( &c2);
		return _gnutls_asn2err(result);
	}

	
	/* write the data (value)
	 */

	_gnutls_str_cpy(tmp, sizeof(tmp), where);
	_gnutls_str_cat(tmp, sizeof(tmp), ".value");

	if (multi != 0) { /* if not writing an AttributeTypeAndValue, but an Attribute */
		_gnutls_str_cat(tmp, sizeof(tmp), "s"); /* values */

		result = asn1_write_value( asn1_struct, tmp, "NEW", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		_gnutls_str_cat(tmp, sizeof(tmp), ".?LAST");
	
	}

	result = _gnutls_x509_der_encode_and_copy( c2, "", asn1_struct, tmp, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	/* write the type
	 */
	_gnutls_str_cpy(tmp, sizeof(tmp), where);
	_gnutls_str_cat(tmp, sizeof(tmp), ".type");

	result = asn1_write_value( asn1_struct, tmp, given_oid, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/* Decodes an X.509 Attribute (if multi==1) or an AttributeTypeAndValue
 * otherwise.
 */
int _gnutls_x509_decode_and_read_attribute(ASN1_TYPE asn1_struct, const char* where,
	char* oid, int oid_size, gnutls_datum* value, int multi) 
{
char tmpbuffer[128];
int len, result;

	/* Read the OID 
	 */
	_gnutls_str_cpy(tmpbuffer, sizeof(tmpbuffer), where);
	_gnutls_str_cat(tmpbuffer, sizeof(tmpbuffer), ".type");

	len = oid_size - 1;
	result = asn1_read_value(asn1_struct, tmpbuffer, oid, &len);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		return result;
	}

	/* Read the Value 
	 */

	_gnutls_str_cpy(tmpbuffer, sizeof(tmpbuffer), where);
	_gnutls_str_cat(tmpbuffer, sizeof(tmpbuffer), ".value");

	if (multi)
		_gnutls_str_cat(tmpbuffer, sizeof(tmpbuffer), "s.?1"); /* .values.?1 */

	result = _gnutls_x509_read_value( asn1_struct, tmpbuffer, value, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;

}

/* Sets an X509 DN in the asn1_struct, and puts the given OID in the DN.
 * The input is assumed to be raw data.
 *
 * asn1_rdn_name must be a string in the form "tbsCertificate.issuer".
 * That is to point before the rndSequence.
 *
 */
int _gnutls_x509_set_dn_oid(ASN1_TYPE asn1_struct,
			      const char *asn1_name,
			      const char *given_oid, const char *name,
			      int sizeof_name)
{
	int result;
	char tmp[64], asn1_rdn_name[64];

	if (sizeof_name == 0 || name == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* create the rdnSequence
	 */
	result = asn1_write_value( asn1_struct, asn1_name, "rdnSequence", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	_gnutls_str_cpy(asn1_rdn_name, sizeof(asn1_rdn_name), asn1_name);
	_gnutls_str_cat(asn1_rdn_name, sizeof(asn1_rdn_name), ".rdnSequence");

	/* create a new element 
	 */
	result = asn1_write_value( asn1_struct, asn1_rdn_name, "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	_gnutls_str_cpy(tmp, sizeof(tmp), asn1_rdn_name);
	_gnutls_str_cat(tmp, sizeof(tmp), ".?LAST");

	/* create the set with only one element
	 */
	result = asn1_write_value( asn1_struct, tmp, "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}


	/* Encode and write the data
	 */
	_gnutls_str_cpy(tmp, sizeof(tmp), asn1_rdn_name);
	_gnutls_str_cat(tmp, sizeof(tmp), ".?LAST.?LAST");

	result = _gnutls_x509_encode_and_write_attribute( given_oid, asn1_struct, tmp,
		name, sizeof_name, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}
	
	return 0;
}


/**
  * gnutls_x509_rdn_get - This function parses an RDN sequence and returns a string
  * @idn: should contain a DER encoded RDN sequence
  * @buf: a pointer to a structure to hold the peer's name
  * @sizeof_buf: holds the size of 'buf'
  *
  * This function will return the name of the given RDN sequence.
  * The name will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described 
  * in RFC2253.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough,
  * and 0 on success.
  *
  **/
int gnutls_x509_rdn_get(const gnutls_datum * idn,
				  char *buf, unsigned int *sizeof_buf)
{
	int result;
	ASN1_TYPE dn = ASN1_TYPE_EMPTY;

	if (sizeof_buf == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (buf)
		buf[0] = 0;


	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.Name", &dn
					 )) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&dn, idn->data, idn->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&dn);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_parse_dn(dn, "rdnSequence", buf, sizeof_buf);

	asn1_delete_structure(&dn);
	return result;

}

/**
  * gnutls_x509_rdn_get_by_oid - This function parses an RDN sequence and returns a string
  * @idn: should contain a DER encoded RDN sequence
  * @oid: an Object Identifier
  * @indx: In case multiple same OIDs exist in the RDN indicates which to send. Use 0 for the first one.
  * @buf: a pointer to a structure to hold the peer's name
  * @sizeof_buf: holds the size of 'buf'
  *
  * This function will return the name of the given Object identifier, 
  * of the RDN sequence.
  * The name will be encoded using the rules from RFC2253.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough,
  * and 0 on success.
  *
  **/
int gnutls_x509_rdn_get_by_oid(const gnutls_datum * idn, const char* oid, int indx,
				  char *buf, unsigned int *sizeof_buf)
{
	int result;
	ASN1_TYPE dn = ASN1_TYPE_EMPTY;

	if (sizeof_buf == 0) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (buf)
		buf[0] = 0;


	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.Name", &dn
					 )) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&dn, idn->data, idn->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&dn);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_parse_dn_oid(dn, "rdnSequence", oid, indx, buf, sizeof_buf);

	asn1_delete_structure(&dn);
	return result;

}

/*
 * Compares the DER encoded part of a DN.
 *
 * FIXME: use a real DN comparison algorithm.
 *
 * Returns 1 if the DN's match and zero if they don't match. Otherwise
 * a negative value is returned to indicate error.
 */
int _gnutls_x509_compare_raw_dn(const gnutls_const_datum * dn1,
	const gnutls_const_datum * dn2) 
{

	if (dn1->size != dn2->size) {
		gnutls_assert();
		return 0;
	}
	if (memcmp(dn1->data, dn2->data, dn2->size) != 0) {
		gnutls_assert();
		return 0;
	}
	return 1; /* they match */
}
