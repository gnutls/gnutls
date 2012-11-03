/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <libtasn1.h>

#define ASN1_SMALL_VALUE_SIZE 16

/* This structure is also in libtasn1.h, but then contains less
   fields.  You cannot make any modifications to these first fields
   without breaking ABI.  */
struct asn1_node_st
{
  /* public fields: */
  char name[ASN1_MAX_NAME_SIZE+1];			/* Node name */
  unsigned int name_hash;
  unsigned int type;		/* Node type */
  unsigned char *value;		/* Node value */
  int value_len;
  asn1_node down;		/* Pointer to the son node */
  asn1_node right;		/* Pointer to the brother node */
  asn1_node left;		/* Pointer to the next list element */
  /* private fields: */
  unsigned char small_value[ASN1_SMALL_VALUE_SIZE];	/* For small values */
};

#define _asn1_strlen(s) strlen((const char *) s)
#define _asn1_strtol(n,e,b) strtol((const char *) n, e, b)
#define _asn1_strtoul(n,e,b) strtoul((const char *) n, e, b)
#define _asn1_strcmp(a,b) strcmp((const char *)a, (const char *)b)
#define _asn1_strcpy(a,b) strcpy((char *)a, (const char *)b)
#define _asn1_strcat(a,b) strcat((char *)a, (const char *)b)

#define MAX_LOG_SIZE 1024	/* maximum number of characters of a log message */

/* Define used for visiting trees. */
#define UP     1
#define RIGHT  2
#define DOWN   3

/****************************************/
/* Returns the first 8 bits.            */
/* Used with the field type of asn1_node_st */
/****************************************/
#define type_field(x)     (x&0xFF)

/* List of constants for field type of typedef asn1_node_st  */
#define TYPE_CONSTANT      ASN1_ETYPE_CONSTANT
#define TYPE_IDENTIFIER    ASN1_ETYPE_IDENTIFIER
#define TYPE_INTEGER       ASN1_ETYPE_INTEGER
#define TYPE_BOOLEAN       ASN1_ETYPE_BOOLEAN
#define TYPE_SEQUENCE      ASN1_ETYPE_SEQUENCE
#define TYPE_BIT_STRING    ASN1_ETYPE_BIT_STRING
#define TYPE_OCTET_STRING  ASN1_ETYPE_OCTET_STRING
#define TYPE_TAG           ASN1_ETYPE_TAG
#define TYPE_DEFAULT       ASN1_ETYPE_DEFAULT
#define TYPE_SIZE          ASN1_ETYPE_SIZE
#define TYPE_SEQUENCE_OF   ASN1_ETYPE_SEQUENCE_OF
#define TYPE_OBJECT_ID     ASN1_ETYPE_OBJECT_ID
#define TYPE_ANY           ASN1_ETYPE_ANY
#define TYPE_SET           ASN1_ETYPE_SET
#define TYPE_SET_OF        ASN1_ETYPE_SET_OF
#define TYPE_DEFINITIONS   ASN1_ETYPE_DEFINITIONS
#define TYPE_TIME          ASN1_ETYPE_TIME
#define TYPE_CHOICE        ASN1_ETYPE_CHOICE
#define TYPE_IMPORTS       ASN1_ETYPE_IMPORTS
#define TYPE_NULL          ASN1_ETYPE_NULL
#define TYPE_ENUMERATED    ASN1_ETYPE_ENUMERATED
#define TYPE_GENERALSTRING ASN1_ETYPE_GENERALSTRING


/***********************************************************************/
/* List of constants to better specify the type of typedef asn1_node_st.   */
/***********************************************************************/
/*  Used with TYPE_TAG  */
#define CONST_UNIVERSAL   (1<<8)
#define CONST_PRIVATE     (1<<9)
#define CONST_APPLICATION (1<<10)
#define CONST_EXPLICIT    (1<<11)
#define CONST_IMPLICIT    (1<<12)

#define CONST_TAG         (1<<13)	/*  Used in ASN.1 assignement  */
#define CONST_OPTION      (1<<14)
#define CONST_DEFAULT     (1<<15)
#define CONST_TRUE        (1<<16)
#define CONST_FALSE       (1<<17)

#define CONST_LIST        (1<<18)	/*  Used with TYPE_INTEGER and TYPE_BIT_STRING  */
#define CONST_MIN_MAX     (1<<19)

#define CONST_1_PARAM     (1<<20)

#define CONST_SIZE        (1<<21)

#define CONST_DEFINED_BY  (1<<22)

#define CONST_GENERALIZED (1<<23)
#define CONST_UTC         (1<<24)

/* #define CONST_IMPORTS     (1<<25) */

#define CONST_NOT_USED    (1<<26)
#define CONST_SET         (1<<27)
#define CONST_ASSIGN      (1<<28)

#define CONST_DOWN        (1<<29)
#define CONST_RIGHT       (1<<30)

#endif /* INT_H */
