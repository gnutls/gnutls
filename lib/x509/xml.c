/*
 * Copyright (C) 2002,2003 Nikos Mavroyanopoulos
 * Copyright (C) 2004 Free Software Foundation
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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


/* This file has the required functions to convert an X.509 DER certificate
 * to XML format.
 */

#include <defines.h>

#ifdef ENABLE_PKI

#include <int.h>
#include <errors.h>
#include <structure.h>
#include <parser_aux.h>
#include <der.h>
#define LIBASN1_H		/* we use this since this file uses
				 * libtasn1 internals, and we don't want the
				 * exported API.
				 */
#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_str.h>
#include <gnutls_x509.h>
#include <x509.h>
#include <common.h>

const char *asn1_find_structure_from_oid(ASN1_TYPE definitions,
					 const char *oidValue);

static int _gnutls_x509_expand_extensions(ASN1_TYPE * rasn);

static const void *find_default_value(ASN1_TYPE x)
{
    ASN1_TYPE p = x;

    if (x->value == NULL && x->type & CONST_DEFAULT) {
	if (x->down) {
	    x = x->down;
	    do {
		if (type_field(x->type) == TYPE_DEFAULT) {
		    if (type_field(p->type) == TYPE_BOOLEAN) {
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
    case TYPE_TAG:
    case TYPE_SIZE:
    case TYPE_DEFAULT:
	return 0;
    case TYPE_CONSTANT:{
	    ASN1_TYPE up = _asn1_find_up(x);

	    if (up != NULL && type_field(up->type) != TYPE_ANY &&
		up->value != NULL)
		return 0;
	}
	return 1;
    }
    if (x->name == NULL && _asn1_find_up(x) != NULL)
	return 0;
    if (x->value == NULL && x->down == NULL)
	return 0;
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

#define APPEND(y, z) if (_gnutls_string_append_data( &str, y, z) < 0) { \
		_gnutls_string_clear( &str); \
		gnutls_assert(); \
		return GNUTLS_E_MEMORY_ERROR; \
	}
#define STR_APPEND(y) if (_gnutls_string_append_str( &str, y) < 0) { \
		_gnutls_string_clear( &str); \
		gnutls_assert(); \
		return GNUTLS_E_MEMORY_ERROR; \
	}

#define UNNAMED "unnamed"
#define ROOT "certificate"
/* This function removes the '?' character from ASN.1 names
 */
static int normalize_name(ASN1_TYPE p, char *output, int output_size)
{
    const char *name;

    if (output_size > 0)
	output[0] = 0;
    else
	return GNUTLS_E_INTERNAL_ERROR;

    if (p == NULL)
	return GNUTLS_E_INTERNAL_ERROR;

    name = p->name;
    if (name == NULL)
	name = ROOT;

    if (type_field(p->type) == TYPE_CONSTANT) {
	ASN1_TYPE up = _asn1_find_up(p);
	const char *tmp;

	if (up && type_field(up->type) == TYPE_ANY &&
	    up->left && up->left->value &&
	    up->type & CONST_DEFINED_BY &&
	    type_field(up->left->type) == TYPE_OBJECT_ID) {

	    tmp =
		asn1_find_structure_from_oid(_gnutls_get_pkix(),
					     up->left->value);
	    if (tmp != NULL)
		_gnutls_str_cpy(output, output_size, tmp);
	    else {
		_gnutls_str_cpy(output, output_size, "DEFINED_BY_");
		_gnutls_str_cat(output, output_size, name);
	    }
	} else {
	    _gnutls_str_cpy(output, output_size, "DEFINED_BY_");
	    _gnutls_str_cat(output, output_size, name);
	}


	return 0;
    }

    if (name[0] == '?') {
	_gnutls_str_cpy(output, output_size, UNNAMED);
	if (strlen(name) > 1)
	    _gnutls_str_cat(output, output_size, &name[1]);
    } else {
	_gnutls_str_cpy(output, output_size, name);
    }
    return 0;
}

#define XML_HEADER "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\n" \
	"<gnutls:x509:certificate version=\"1.1\">\n"

#define XML_FOOTER "</gnutls:x509:certificate>\n"

static int
_gnutls_asn1_get_structure_xml(ASN1_TYPE structure,
			       gnutls_datum * res, int detail)
{
    node_asn *p, *root;
    int k, indent = 0, len, len2, len3;
    opaque tmp[1024];
    char nname[256];
    int ret;
    gnutls_string str;

    if (res == NULL || structure == NULL) {
	gnutls_assert();
	return GNUTLS_E_INVALID_REQUEST;
    }

    _gnutls_string_init(&str, malloc, realloc, free);

    STR_APPEND(XML_HEADER);
    indent = 1;

    root = _asn1_find_node(structure, "");

    if (root == NULL) {
	gnutls_assert();
	_gnutls_string_clear(&str);
	return GNUTLS_E_INTERNAL_ERROR;
    }

    if (detail == GNUTLS_XML_SHOW_ALL)
	ret = asn1_expand_any_defined_by(_gnutls_get_pkix(), &structure);
    /* we don't need to check the error value
     * here.
     */

    if (detail == GNUTLS_XML_SHOW_ALL) {
	ret = _gnutls_x509_expand_extensions(&structure);
	if (ret < 0) {
	    gnutls_assert();
	    return ret;
	}
    }

    p = root;
    while (p) {
	if (is_node_printable(p)) {
	    for (k = 0; k < indent; k++)
		APPEND(" ", 1);

	    if ((ret = normalize_name(p, nname, sizeof(nname))) < 0) {
		_gnutls_string_clear(&str);
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
		if (!p->down)
		    STR_APPEND(" encoding=\"HEX\"");
		break;
	    case TYPE_CONSTANT:{
		    ASN1_TYPE up = _asn1_find_up(p);

		    if (up && type_field(up->type) == TYPE_ANY &&
			up->left && up->left->value &&
			up->type & CONST_DEFINED_BY &&
			type_field(up->left->type) == TYPE_OBJECT_ID) {

			if (_gnutls_x509_oid_data_printable
			    (up->left->value) == 0) {
			    STR_APPEND(" encoding=\"HEX\"");
			}

		    }
		}
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
	    STR_APPEND(">");

	if (is_node_printable(p)) {
	    const unsigned char *value;

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
		    len = _asn1_get_length_der(value, &len2);

		    for (k = 0; k < len; k++) {
			snprintf(tmp, sizeof(tmp),
				 "%02X", (value)[k + len2]);
			STR_APPEND(tmp);
		    }

		}
		break;
	    case TYPE_ENUMERATED:
		if (value) {
		    len2 = -1;
		    len = _asn1_get_length_der(value, &len2);

		    for (k = 0; k < len; k++) {
			snprintf(tmp, sizeof(tmp),
				 "%02X", (value)[k + len2]);
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
		    len = _asn1_get_length_der(value, &len2);

		    for (k = 1; k < len; k++) {
			snprintf(tmp, sizeof(tmp),
				 "%02X", (value)[k + len2]);
			STR_APPEND(tmp);
		    }
		}
		break;
	    case TYPE_OCTET_STRING:
		if (value) {
		    len2 = -1;
		    len = _asn1_get_length_der(value, &len2);
		    for (k = 0; k < len; k++) {
			snprintf(tmp, sizeof(tmp),
				 "%02X", (value)[k + len2]);
			STR_APPEND(tmp);
		    }
		}
		break;
	    case TYPE_OBJECT_ID:
		if (value)
		    STR_APPEND(value);
		break;
	    case TYPE_ANY:
		if (!p->down) {
		    if (value) {
			len3 = -1;
			len2 = _asn1_get_length_der(value, &len3);
			for (k = 0; k < len2; k++) {
			    snprintf(tmp, sizeof(tmp),
				     "%02X", (value)[k + len3]);
			    STR_APPEND(tmp);
			}
		    }
		}
		break;
	    case TYPE_CONSTANT:{
		    ASN1_TYPE up = _asn1_find_up(p);

		    if (up && type_field(up->type) == TYPE_ANY &&
			up->left && up->left->value &&
			up->type & CONST_DEFINED_BY &&
			type_field(up->left->type) == TYPE_OBJECT_ID) {

			len2 = _asn1_get_length_der(up->value, &len3);

			if (len2 > 0 && strcmp(p->name, "type") == 0) {
			    int len = sizeof(tmp);
			    ret =
				_gnutls_x509_oid_data2string(up->left->
							     value,
							     up->value +
							     len3, len2,
							     tmp, &len);

			    if (ret >= 0) {
				STR_APPEND(tmp);
			    }
			} else {
			    for (k = 0; k < len2; k++) {
				snprintf(tmp, sizeof(tmp),
					 "%02X", (up->value)[k + len3]);
				STR_APPEND(tmp);
			    }

			}
		    } else {
			if (value)
			    STR_APPEND(value);
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
		if ((ret = normalize_name(p, nname, sizeof(nname))) < 0) {
		    _gnutls_string_clear(&str);
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
		if ((ret = normalize_name(p, nname, sizeof(nname))) < 0) {
		    _gnutls_string_clear(&str);
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
			    for (k = 0; k < indent; k++)
				STR_APPEND(" ");

			if ((ret =
			     normalize_name(p, nname,
					    sizeof(nname))) < 0) {
			    _gnutls_string_clear(&str);
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

    STR_APPEND(XML_FOOTER);
    APPEND("\n\0", 2);

    *res = _gnutls_string2datum(&str);
    res->size -= 1;		/* null is not included in size */

    return 0;
}

/**
  * gnutls_x509_crt_to_xml - This function parses an RDN sequence
  * @cert: should contain a gnutls_x509_crt structure
  * @res: The datum that will hold the result
  * @detail: The detail level (must be GNUTLS_XML_SHOW_ALL or GNUTLS_XML_NORMAL)
  *
  * This function will return the XML structures of the given X.509 certificate.
  * The XML structures are allocated internally (with malloc) and stored into res.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_crt_to_xml(gnutls_x509_crt cert, gnutls_datum * res,
			   int detail)
{
    int result;

    res->data = NULL;
    res->size = 0;

    result = _gnutls_asn1_get_structure_xml(cert->cert, res, detail);
    if (result < 0) {
	gnutls_assert();
	return result;
    }

    return 0;
}

/* This function will attempt to parse Extensions in
 * an X509v3 certificate
 *
 * If no_critical_ext is non zero, then unsupported critical extensions
 * do not lead into a fatal error.
 */
static int _gnutls_x509_expand_extensions(ASN1_TYPE * rasn)
{
    int k, result, len;
    char name[128], name2[128], counter[MAX_INT_DIGITS];
    char name1[128];
    char extnID[128];

    k = 0;
    do {
	k++;

	_gnutls_str_cpy(name, sizeof(name), "tbsCertificate.extensions.?");
	_gnutls_int2str(k, counter);
	_gnutls_str_cat(name, sizeof(name), counter);

	_gnutls_str_cpy(name2, sizeof(name2), name);
	_gnutls_str_cat(name2, sizeof(name2), ".extnID");

	_gnutls_str_cpy(name1, sizeof(name1), name);
	_gnutls_str_cat(name1, sizeof(name1), ".extnValue");

	len = sizeof(extnID) - 1;

	result = asn1_expand_octet_string(_gnutls_get_pkix(),
					  rasn, name1, name2);

	if (result == ASN1_ELEMENT_NOT_FOUND)
	    break;
	else if (result != ASN1_SUCCESS) {
	    gnutls_assert();
	    return _gnutls_asn2err(result);
	}

    } while (1);

    if (result == ASN1_ELEMENT_NOT_FOUND)
	return 0;
    else
	return _gnutls_asn2err(result);
}

#endif
