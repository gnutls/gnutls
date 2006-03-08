/*
 *      Copyright (C) 2004, 2005, 2006 Free Software Foundation
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBTASN1.
 *
 * LIBTASN1 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * LIBTASN1 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with LIBTASN1; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef LIBTASN1_DONT_H
# define LIBTASN1_DONT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <libtasn1.h>

/******************************************************/
/* List of constants for field type of typedef node_asn */
/********************************************************/
#define ASN1_TYPE_CONSTANT       1
#define ASN1_TYPE_IDENTIFIER     2
#define ASN1_TYPE_INTEGER        3
#define ASN1_TYPE_BOOLEAN        4
#define ASN1_TYPE_SEQUENCE       5
#define ASN1_TYPE_BIT_STRING     6
#define ASN1_TYPE_OCTET_STRING   7
#define ASN1_TYPE_TAG            8
#define ASN1_TYPE_DEFAULT        9
#define ASN1_TYPE_SIZE          10
#define ASN1_TYPE_SEQUENCE_OF   11
#define ASN1_TYPE_OBJECT_ID     12
#define ASN1_TYPE_ANY           13
#define ASN1_TYPE_SET           14
#define ASN1_TYPE_SET_OF	15
#define ASN1_TYPE_DEFINITIONS   16
#define ASN1_TYPE_TIME		17
#define ASN1_TYPE_CHOICE	18
#define ASN1_TYPE_IMPORTS       19
#define ASN1_TYPE_NULL		20
#define ASN1_TYPE_ENUMERATED    21
#define ASN1_TYPE_GENERALSTRING 27

/***********************************************************************/
/* List of constants to better specify the type of typedef node_asn.   */
/* Used with TYPE_TAG.                                                 */
/***********************************************************************/
#define ASN1_CONST_UNIVERSAL   (1<<8)
#define ASN1_CONST_PRIVATE     (1<<9)
#define ASN1_CONST_APPLICATION (1<<10)
#define ASN1_CONST_EXPLICIT    (1<<11)
#define ASN1_CONST_IMPLICIT    (1<<12)
#define ASN1_CONST_TAG         (1<<13)  /*  Used in ASN.1 assignement  */
#define ASN1_CONST_OPTION      (1<<14)
#define ASN1_CONST_DEFAULT     (1<<15)
#define ASN1_CONST_TRUE        (1<<16)
#define ASN1_CONST_FALSE       (1<<17)
#define ASN1_CONST_LIST        (1<<18)  /*  Used with TYPE_INTEGER and TYPE_BIT_STRING  */
#define ASN1_CONST_MIN_MAX     (1<<19)
#define ASN1_CONST_1_PARAM     (1<<20)
#define ASN1_CONST_SIZE        (1<<21)
#define ASN1_CONST_DEFINED_BY  (1<<22)
#define ASN1_CONST_GENERALIZED (1<<23)
#define ASN1_CONST_UTC         (1<<24)
  /* #define ASN1_CONST_IMPORTS     (1<<25) */
#define ASN1_CONST_NOT_USED    (1<<26)
#define ASN1_CONST_SET         (1<<27)
#define ASN1_CONST_ASSIGN      (1<<28)
#define ASN1_CONST_DOWN        (1<<29)
#define ASN1_CONST_RIGHT       (1<<30)

/****************************************/
/* Returns the first 8 bits.            */
/* Used with the field type of node_asn */
/****************************************/
#define ASN1_TYPE_FIELD(x) (x&0xFF)

/* DER utility functions. */

  int asn1_get_tag_der (const unsigned char *der, int der_len,
			unsigned char *class, int *len, unsigned long *tag);

  void asn1_octet_der (const unsigned char *str, int str_len,
		       unsigned char *der, int *der_len);

  asn1_retCode asn1_get_octet_der (const unsigned char *der, int der_len,
				   int *ret_len, unsigned char *str,
				   int str_size, int *str_len);

  void asn1_bit_der (const unsigned char *str, int bit_len,
		     unsigned char *der, int *der_len);

  asn1_retCode asn1_get_bit_der (const unsigned char *der, int der_len,
				 int *ret_len, unsigned char *str,
				 int str_size, int *bit_len);

  signed long asn1_get_length_der (const unsigned char *der, int der_len,
				   int *len);

  void asn1_length_der (unsigned long len, unsigned char *ans, int *ans_len);

/* Other utility functions. */

  ASN1_TYPE asn1_find_up (ASN1_TYPE node);

  ASN1_TYPE asn1_find_node (ASN1_TYPE pointer, const char *name);

#ifdef __cplusplus
}
#endif

#endif				/* LIBTASN1_DONT_H */
