/*
 *      Copyright (C) 2004, 2006 Free Software Foundation, Inc.
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBTASN1.
 *
 * The LIBTASN1 library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef INT_H
#define INT_H

#include <libtasn1.h>
#include <libtasn1-dont.h>

#include <defines.h>

/*
#define LIBTASN1_DEBUG
#define LIBTASN1_DEBUG_PARSER
#define LIBTASN1_DEBUG_INTEGER
*/

#include <mem.h>

#define MAX_LOG_SIZE 1024 /* maximum number of characters of a log message */

/* Define used for visiting trees. */
#define UP     1
#define RIGHT  2
#define DOWN   3

#define type_field(x) ASN1_TYPE_FIELD(x)

#define TYPE_CONSTANT ASN1_TYPE_CONSTANT
#define TYPE_IDENTIFIER ASN1_TYPE_IDENTIFIER
#define TYPE_INTEGER ASN1_TYPE_INTEGER
#define TYPE_BOOLEAN ASN1_TYPE_BOOLEAN
#define TYPE_SEQUENCE ASN1_TYPE_SEQUENCE
#define TYPE_BIT_STRING ASN1_TYPE_BIT_STRING
#define TYPE_OCTET_STRING ASN1_TYPE_OCTET_STRING
#define TYPE_TAG ASN1_TYPE_TAG
#define TYPE_DEFAULT ASN1_TYPE_DEFAULT
#define TYPE_SIZE ASN1_TYPE_SIZE
#define TYPE_SEQUENCE_OF ASN1_TYPE_SEQUENCE_OF
#define TYPE_OBJECT_ID ASN1_TYPE_OBJECT_ID
#define TYPE_ANY ASN1_TYPE_ANY
#define TYPE_SET ASN1_TYPE_SET
#define TYPE_SET_OF ASN1_TYPE_SET_OF
#define TYPE_DEFINITIONS ASN1_TYPE_DEFINITIONS
#define TYPE_TIME ASN1_TYPE_TIME
#define TYPE_CHOICE ASN1_TYPE_CHOICE
#define TYPE_IMPORTS ASN1_TYPE_IMPORTS
#define TYPE_NULL ASN1_TYPE_NULL
#define TYPE_ENUMERATED ASN1_TYPE_ENUMERATED
#define TYPE_GENERALSTRING ASN1_TYPE_GENERALSTRING

#define CONST_UNIVERSAL ASN1_CONST_UNIVERSAL
#define CONST_PRIVATE ASN1_CONST_PRIVATE
#define CONST_APPLICATION ASN1_CONST_APPLICATION
#define CONST_EXPLICIT ASN1_CONST_EXPLICIT
#define CONST_IMPLICIT ASN1_CONST_IMPLICIT
#define CONST_TAG ASN1_CONST_TAG
#define CONST_OPTION ASN1_CONST_OPTION
#define CONST_DEFAULT ASN1_CONST_DEFAULT
#define CONST_TRUE ASN1_CONST_TRUE
#define CONST_FALSE ASN1_CONST_FALSE
#define CONST_LIST ASN1_CONST_LIST
#define CONST_MIN_MAX ASN1_CONST_MIN_MAX
#define CONST_1_PARAM ASN1_CONST_1_PARAM
#define CONST_SIZE ASN1_CONST_SIZE
#define CONST_DEFINED_BY ASN1_CONST_DEFINED_BY
#define CONST_GENERALIZED ASN1_CONST_GENERALIZED
#define CONST_UTC ASN1_CONST_UTC
/* #define CONST_IMPORTS ASN1_CONST_IMPORTS */
#define CONST_NOT_USED ASN1_CONST_NOT_USED
#define CONST_SET ASN1_CONST_SET
#define CONST_ASSIGN ASN1_CONST_ASSIGN
#define CONST_DOWN ASN1_CONST_DOWN
#define CONST_RIGHT ASN1_CONST_RIGHT

#endif /* INT_H */
