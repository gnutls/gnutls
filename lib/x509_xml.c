/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The LIBTASN1 library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public   
 * License as published by the Free Software Foundation; either 
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */


#include <int.h>
#include <errors.h>
#include <structure.h>
#include <parser_aux.h>
#include <der.h>
#define LIBASN1_H /* we use this since this file uses
		   * libtasn1 internals, and we don't want the
		   * exported API.
		   */
#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>

static void *find_default_value(ASN1_TYPE x)
{
	ASN1_TYPE p = x;

	if (x->value == NULL && x->type & CONST_DEFAULT) {
		if (x->down) {
			x = x->down;
			do {
				if (type_field(x->type) == TYPE_DEFAULT) {
					if (type_field(p->type) ==
					    TYPE_BOOLEAN) {
						if (x->type & CONST_TRUE)
							return "TRUE";
						else
							return "FALSE";
					} else
						return x->value;
				}
				x = x->right;
			} while (x != NULL);

		}
	}
	return NULL;
}


static int is_node_printable(ASN1_TYPE x)
{
	switch (type_field(x->type)) {
	case TYPE_CONSTANT:
	case TYPE_TAG:
	case TYPE_SIZE:
	case TYPE_DEFAULT:
		return 0;
	}
	if (x->name == NULL)
		return 0;
	if (x->value == NULL && x->down == NULL)
		return 0;
//  else if (x->value==NULL && !(x->type&CONST_DEFAULT)) return 0;
	return 1;
}

/* returns true if the node is the only one printable in 
 * the level down of it.
 */
static int is_leaf(ASN1_TYPE p)
{
	ASN1_TYPE x;


	if (p == NULL)
		return 1;
	if (p->down == NULL)
		return 1;

	x = p->down;

	while (x != NULL) {
		if (is_node_printable(x))
			return 0;
		if (is_leaf(x) == 0)
			return 0;
		x = x->right;
	}

	return 1;

}

#define APPEND(y, z) if (_gnutls_datum_append_m( res, y, z, realloc) < 0) { \
		gnutls_assert(); \
		return GNUTLS_E_MEMORY_ERROR; \
	}
#define STR_APPEND(y) if (_gnutls_datum_append_m( res, y, strlen(y), realloc) < 0) { \
		gnutls_assert(); \
		return GNUTLS_E_MEMORY_ERROR; \
	}

#define UNNAMED "unnamed"
/* This function removes the '?' character from ASN.1 names
 */
static int normalize_name( const char* aname, char* output, int output_size) 
{
	if (output_size > 0)
		output[0] = 0;

	if (aname==NULL) return 0;

	if ( aname[0]=='?') {
		_gnutls_str_cpy( output, output_size, UNNAMED);
		if (strlen(aname) > 1)
			_gnutls_str_cat( output, output_size, &aname[1]);
	} else {
		_gnutls_str_cpy( output, output_size, aname);
	}
	return 0;
}

#define XML_HEADER "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"

/* FIXME: This function is way too expensive.
 */
static int
_gnutls_asn1_get_structure_xml(ASN1_TYPE structure, char *name,
			 gnutls_datum * res)
{
	node_asn *p, *root;
	int k, indent = 0, len, len2, len3;
	opaque tmp[1024];
	char nname[256];
	int ret;

	if (res == NULL || structure == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	res->data = NULL;
	res->size = 0;

	STR_APPEND(XML_HEADER);

	root = _asn1_find_node(structure, name);

	if (root == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	p = root;
	while (p) {

		if (is_node_printable(p) && p->name) {
			for (k = 0; k < indent; k++)
				APPEND(" ", 1);

			if ((ret=normalize_name( p->name, nname, sizeof(nname))) < 0) {
				gnutls_assert();
				return ret;
			}

			APPEND("<", 1);
			STR_APPEND(nname);
		}

		if (is_node_printable(p)) {
			switch (type_field(p->type)) {
			case TYPE_DEFAULT:
				STR_APPEND(" type=\"DEFAULT\"");
				break;
			case TYPE_NULL:
				STR_APPEND(" type=\"NULL\"");
				break;
			case TYPE_IDENTIFIER:
				STR_APPEND(" type=\"IDENTIFIER\"");
			        break;
			case TYPE_INTEGER:
				STR_APPEND(" type=\"INTEGER\"");
				STR_APPEND(" encoding=\"HEX\"");
				break;
			case TYPE_ENUMERATED:
				STR_APPEND(" type=\"ENUMERATED\"");
				STR_APPEND(" encoding=\"HEX\"");
				break;
			case TYPE_TIME:
				STR_APPEND(" type=\"TIME\"");
				break;
			case TYPE_BOOLEAN:
				STR_APPEND(" type=\"BOOLEAN\"");
				break;
			case TYPE_SEQUENCE:
				STR_APPEND(" type=\"SEQUENCE\"");
				break;
			case TYPE_BIT_STRING:
				STR_APPEND(" type=\"BIT STRING\"");
				STR_APPEND(" encoding=\"HEX\"");
				break;
			case TYPE_OCTET_STRING:
				STR_APPEND(" type=\"OCTET STRING\"");
				STR_APPEND(" encoding=\"HEX\"");
				break;
			case TYPE_SEQUENCE_OF:
				STR_APPEND(" type=\"SEQUENCE OF\"");
				break;
			case TYPE_OBJECT_ID:
				STR_APPEND(" type=\"OBJECT ID\"");
				break;
			case TYPE_ANY:
				STR_APPEND(" type=\"ANY\"");
				STR_APPEND(" encoding=\"HEX\"");
				break;
			case TYPE_SET:
				STR_APPEND(" type=\"SET\"");
				break;
			case TYPE_SET_OF:
				STR_APPEND(" type=\"SET OF\"");
				break;
			case TYPE_CHOICE:
				STR_APPEND(" type=\"CHOICE\"");
				break;
			case TYPE_DEFINITIONS:
				STR_APPEND(" type=\"DEFINITIONS\"");
				break;
			default:
				break;
			}
		}


		if (p->type == TYPE_BIT_STRING) {
			len2 = -1;
			len = _asn1_get_length_der(p->value, &len2);
			snprintf(tmp, sizeof(tmp), " length=\"%i\"",
				 (len - 1) * 8 - (p->value[len2]));
			STR_APPEND(tmp);
		}

		if (is_node_printable(p))
			STR_APPEND( ">");

		if (is_node_printable(p)) {
			unsigned char *value;

			if (p->value == NULL)
				value = find_default_value(p);
			else
				value = p->value;

			switch (type_field(p->type)) {

			case TYPE_DEFAULT:
				if (value)
					STR_APPEND(value);
				break;
			case TYPE_IDENTIFIER:
				if (value)
					STR_APPEND(value);
				break;
			case TYPE_INTEGER:
				if (value) {
					len2 = -1;
					len =
					    _asn1_get_length_der(value,
								 &len2);

					for (k = 0; k < len; k++) {
						snprintf(tmp, sizeof(tmp),
							 "%02X",
							 (value)[k +
								 len2]);
						STR_APPEND(tmp);
					}

				}
				break;
			case TYPE_ENUMERATED:
				if (value) {
					len2 = -1;
					len =
					    _asn1_get_length_der(value,
								 &len2);

					for (k = 0; k < len; k++) {
						snprintf(tmp, sizeof(tmp),
							 "%02X",
							 (value)[k +
								 len2]);
						STR_APPEND(tmp);
					}
				}
				break;
			case TYPE_TIME:
				if (value)
					STR_APPEND(value);
				break;
			case TYPE_BOOLEAN:
				if (value) {
					if (value[0] == 'T') {
						STR_APPEND("TRUE");
					} else if (value[0] == 'F') {
						STR_APPEND("FALSE");
					}
				}
				break;
			case TYPE_BIT_STRING:
				if (value) {
					len2 = -1;
					len =
					    _asn1_get_length_der(value,
								 &len2);

					for (k = 1; k < len; k++) {
						snprintf(tmp, sizeof(tmp),
							 "%02X",
							 (value)[k +
								 len2]);
						STR_APPEND(tmp);
					}
				}
				break;
			case TYPE_OCTET_STRING:
				if (value) {
					len2 = -1;
					len =
					    _asn1_get_length_der(value,
								 &len2);
					for (k = 0; k < len; k++) {
						snprintf(tmp, sizeof(tmp),
							 "%02X",
							 (value)[k +
								 len2]);
						STR_APPEND(tmp);
					}
				}
				break;
			case TYPE_OBJECT_ID:
				if (value)
					STR_APPEND(value);
				break;
			case TYPE_ANY:
				if (value) {
					len3 = -1;
					len2 =
					    _asn1_get_length_der(value,
								 &len3);

					for (k = 0; k < len2; k++) {
						snprintf(tmp, sizeof(tmp),
							 "%02X",
							 (value)[k +
								 len3]);
						STR_APPEND(tmp);
					}
				}
				break;
			case TYPE_SET:
			case TYPE_SET_OF:
			case TYPE_CHOICE:
			case TYPE_DEFINITIONS:
			case TYPE_SEQUENCE_OF:
			case TYPE_SEQUENCE:
			case TYPE_NULL:
				break;
			default:
				break;
			}
		}

		if (p->down && is_node_printable(p)) {
			ASN1_TYPE x;
			p = p->down;
			indent += 2;
			x = p;
			do {
				if (is_node_printable(x)) {
					STR_APPEND("\n");
					break;
				}
				x = x->right;
			} while (x != NULL);
		} else if (p == root) {
			if (is_node_printable(p)) {
				if ((ret=normalize_name( p->name, nname, sizeof(nname))) < 0) {
					gnutls_assert();
					return ret;
				}

				APPEND("</", 2);
				STR_APPEND(nname);
				APPEND(">\n", 2);
			}
			p = NULL;
			break;
		} else {
			if (is_node_printable(p)) {
				if ((ret=normalize_name( p->name, nname, sizeof(nname))) < 0) {
					gnutls_assert();
					return ret;
				}

				APPEND("</", 2);
				STR_APPEND(nname);
				APPEND(">\n", 2);
			}
			if (p->right)
				p = p->right;
			else {
				while (1) {
					ASN1_TYPE old_p;

					old_p = p;

					p = _asn1_find_up(p);
					indent -= 2;
					if (is_node_printable(p)) {
						if (!is_leaf(p))	/* XXX */
							for (k = 0;
							     k < indent;
							     k++)
								STR_APPEND(" ");

						if ((ret=normalize_name( p->name, nname, sizeof(nname))) < 0) {
							gnutls_assert();
							return ret;
						}

						APPEND("</", 2);
						STR_APPEND(nname);
						APPEND(">\n", 2);
					}
					if (p == root) {
						p = NULL;
						break;
					}

					if (p->right) {
						p = p->right;
						break;
					}
				}
			}
		}
	}
	
	APPEND( "\n\0", 2);
	
	return 0;
}

/**
  * gnutls_x509_get_certificate_xml - This function parses an RDN sequence
  * @cert: should contain a DER encoded certificate
  * @detail: The detail level (must be 0 for now)
  * @res: The datum that will hold the result
  *
  * This function will return the XML structures of the given X.509 certificate.
  * The XML structures are allocated internaly (with malloc) and stored into res.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_get_certificate_xml(const gnutls_datum * cert, int detail, gnutls_datum* res)
{
	ASN1_TYPE asn1_cert;
	int result;

	res->data = NULL;
	res->size = 0;
	
	if ((result =
	     _gnutls_asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.Certificate", &asn1_cert,
				   "certificate")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&asn1_cert, cert->data, cert->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&asn1_cert);
		return _gnutls_asn2err(result);
	}


	result = _gnutls_asn1_get_structure_xml( asn1_cert, "certificate", res);
	asn1_delete_structure(&asn1_cert);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}
