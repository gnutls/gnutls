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
#include <gnutls_x509.h>
#include <gnutls_num.h>
#include <dn.h>

typedef struct _oid2ldap_str {
	const char *oid;
	const char *desc;
} oid2ldap_str;


static const oid2ldap_str OID2STR[] = {
	{"2 5 4 6", "C"},
	{"2 5 4 10", "O"},
	{"2 5 4 11", "OU"},
	{"2 5 4 3", "CN"},
	{"2 5 4 7", "L"},
	{"2 5 4 8", "ST"},
	{"2 5 4 9", "STREET"},
	{"1 2 840 113549 1 9 1", "1.2.840.113549.1.9.1"},
	{"0 9 2342 19200300 100 1 25", "DC"},
	{"0 9 2342 19200300 100 1 1", "UID"},
	{NULL, NULL}
};

/* converts all spaces to dots. Used to convert the
 * OIDs returned by libtasn1 to the dotted OID format.
 */
static void dot_spaces(char *str)
{
	char *p;

	do {
		p = strchr(str, ' ');
		if (p)
			*p = '.';
	} while (p);
}

/* Converts the given OID to an ldap acceptable string or
 * a dotted OID. Printable will be zero if the OID does not
 * contain printable stuff.
 */
static const char *oid2ldap_string(char *oid, int *printable)
{
	int i = 0;

	*printable = 1;
	do {
		if (strcmp(OID2STR[i].oid, oid) == 0)
			return OID2STR[i].desc;
		i++;
	} while (OID2STR[i].oid != NULL);

	*printable = 0;
	dot_spaces(oid);
	return oid;
}

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
 * asn1_rdn_name must be a string in the form "crl2.tbsCertificate.issuer.rdnSequence".
 * That is to point in the rndSequence.
 */
int _gnutls_x509_parse_dn(ASN1_TYPE asn1_struct,
			  const char *asn1_rdn_name, char *buf,
			  unsigned int sizeof_buf)
{
	gnutls_string out_str;
	int k2, k1, result;
	char tmpbuffer1[64];
	char tmpbuffer2[64];
	char tmpbuffer3[64];
	char counter[MAX_INT_DIGITS];
	char value[200];
	char escaped[256];
	const char *_oid;
	char oid[128];
	int first = 0;
	int len, printable;

	if (buf == NULL || sizeof_buf == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	buf[0] = 0;

	_gnutls_string_init(&out_str, gnutls_malloc, gnutls_realloc,
			    gnutls_free);

	k1 = 0;
	do {

		k1++;
		/* create a string like "crl2.tbsCertList.issuer.rdnSequence.?1"
		 */
		_gnutls_int2str(k1, counter);
		_gnutls_str_cpy(tmpbuffer1, sizeof(tmpbuffer1),
				asn1_rdn_name);
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), ".?");
		_gnutls_str_cat(tmpbuffer1, sizeof(tmpbuffer1), counter);

		len = sizeof(value) - 1;
		result =
		    asn1_read_value(asn1_struct, tmpbuffer1, value, &len);

		if (result == ASN1_ELEMENT_NOT_FOUND) {
			gnutls_assert();
			break;
			result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
			goto cleanup;
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
			_gnutls_str_cat(tmpbuffer2, sizeof(tmpbuffer2),
					".?");
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

			value[len] = 0;

#define STR_APPEND(y) if ((result=_gnutls_string_append_str( &out_str, y)) < 0) { \
	gnutls_assert(); \
	goto cleanup; \
}

			if (k2 != 1) {	/* the first time do not append a comma */
				STR_APPEND(",");
			}

			_oid = oid2ldap_string(oid, &printable);

			if (printable) {
				if (first != 0) {
					STR_APPEND(",");
				}
				STR_APPEND(_oid);
				STR_APPEND("=");
				STR_APPEND(str_escape(value, escaped, sizeof(escaped)));	/* value */
				first = 1;
			}

			/* FIXME: we do not print non printable stuff 
			 */
		} while (1);

	} while (1);

	if (out_str.length >= sizeof_buf) {
		gnutls_assert();
		result = GNUTLS_E_SHORT_MEMORY_BUFFER;
		goto cleanup;
	}

	memcpy(buf, out_str.data, out_str.length);
	buf[out_str.length] = 0;

	return 0;

      cleanup:
	_gnutls_string_clear(&out_str);
	return result;
}
