/*
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBASN1.
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

#ifndef INT_H

#define INT_H

#include <defines.h>

/*
#define LIBTASN1_DEBUG
#define LIBTASN1_DEBUG_PARSER
#define LIBTASN1_DEBUG_INTEGER
*/

#include <mem.h>

#define LIBTASN1_VERSION "0.2.6"

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

#define MAX_LOG_SIZE 1024 /* maximum number of characters of a log message */
#define MAX_NAME_SIZE 128 /* maximum number of characters of a name inside an ASN1 file definitons */
#define MAX_ERROR_DESCRIPTION_SIZE 128 /* maximum number of characters of a description message */

/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
#define ASN1_CLASS_UNIVERSAL        1
#define ASN1_CLASS_APPLICATION      2
#define ASN1_CLASS_CONTEXT_SPECIFIC 3
#define ASN1_CLASS_PRIVATE          4


/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
#define ASN1_TAG_BOOLEAN          0x01
#define ASN1_TAG_INTEGER          0x02
#define ASN1_TAG_SEQUENCE         0x10
#define ASN1_TAG_SET              0x11
#define ASN1_TAG_OCTET_STRING     0x04
#define ASN1_TAG_BIT_STRING       0x03
#define ASN1_TAG_UTCTime          0x17
#define ASN1_TAG_GENERALIZEDTime  0x18
#define ASN1_TAG_OBJECT_ID        0x06
#define ASN1_TAG_ENUMERATED       0x0A
#define ASN1_TAG_NULL             0x05
#define ASN1_TAG_GENERALSTRING    0x1B


/* define used for visiting trees */
#define UP     1
#define RIGHT  2
#define DOWN   3


typedef int asn1_retCode;  /* type returned by libasn1 functions */


/******************************************************/
/* Structure definition used for the node of the tree */
/* that rappresent an ASN.1 DEFINITION.               */
/******************************************************/
typedef struct node_asn_struct{
  char *name;                    /* Node name */
  unsigned int type;             /* Node type */
  unsigned char *value;          /* Node value */
  struct node_asn_struct *down;  /* Pointer to the son node */
  struct node_asn_struct *right; /* Pointer to the brother node */
  struct node_asn_struct *left;  /* Pointer to the next list element */ 
} node_asn;

typedef node_asn* ASN1_TYPE;

#define ASN1_TYPE_EMPTY  NULL

struct static_struct_asn{
  char *name;                    /* Node name */
  unsigned int type;             /* Node type */
  unsigned char *value;          /* Node value */
};

typedef struct static_struct_asn ASN1_ARRAY_TYPE;


/****************************************/
/* Returns the first 8 bits.            */
/* Used with the field type of node_asn */
/****************************************/
#define type_field(x)     (x&0xFF) 


/* List of constants for field type of typedef node_asn  */
#define TYPE_CONSTANT       1
#define TYPE_IDENTIFIER     2
#define TYPE_INTEGER        3
#define TYPE_BOOLEAN        4
#define TYPE_SEQUENCE       5
#define TYPE_BIT_STRING     6
#define TYPE_OCTET_STRING   7
#define TYPE_TAG            8
#define TYPE_DEFAULT        9
#define TYPE_SIZE          10
#define TYPE_SEQUENCE_OF   11
#define TYPE_OBJECT_ID     12
#define TYPE_ANY           13
#define TYPE_SET           14
#define TYPE_SET_OF        15
#define TYPE_DEFINITIONS   16
#define TYPE_TIME          17
#define TYPE_CHOICE        18
#define TYPE_IMPORTS       19
#define TYPE_NULL          20
#define TYPE_ENUMERATED    21
#define TYPE_GENERALSTRING 27


/***********************************************************************/
/* List of constants for specify better the type of typedef node_asn.  */
/***********************************************************************/
/*  Used with TYPE_TAG  */
#define CONST_UNIVERSAL   (1<<8)
#define CONST_PRIVATE     (1<<9)
#define CONST_APPLICATION (1<<10)
#define CONST_EXPLICIT    (1<<11)
#define CONST_IMPLICIT    (1<<12)

#define CONST_TAG         (1<<13)  /*  Used in ASN.1 assignement  */
#define CONST_OPTION      (1<<14)
#define CONST_DEFAULT     (1<<15)
#define CONST_TRUE        (1<<16)
#define CONST_FALSE       (1<<17)

#define CONST_LIST        (1<<18)  /*  Used with TYPE_INTEGER and TYPE_BIT_STRING  */
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


/* functions */
asn1_retCode asn1_delete_structure(ASN1_TYPE *structure);

asn1_retCode asn1_create_element(ASN1_TYPE definitions,const char *source_name,
                                 ASN1_TYPE *element);

asn1_retCode asn1_read_value(ASN1_TYPE element,const char *name,
			     unsigned char *value,int *len);

asn1_retCode
asn1_expand_octet_string(ASN1_TYPE definitions,ASN1_TYPE *element,
                         const char *octetName,const char *objectName);

asn1_retCode
asn1_expand_any_defined_by(ASN1_TYPE definitions,ASN1_TYPE *element);

asn1_retCode
asn1_der_decoding(ASN1_TYPE *element,const unsigned char *der,int len,
		  char *errorDescription);


#endif /* INT_H */


