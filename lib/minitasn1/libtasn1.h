/*
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBTASN1.
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
 *
 */

#ifndef LIBASN1_H
# define LIBASN1_H

#include <stdio.h> /* for FILE* */

#ifdef __cplusplus
extern "C" {
#endif

#define LIBASN1_VERSION "0.1.1"

#include <sys/types.h>
#include <time.h>

#define MAX_NAME_SIZE 128 /* maximum number of characters of a name */ 
			  /* inside a file with ASN1 definitons     */
#define MAX_ERROR_DESCRIPTION_SIZE 1024 /* maximum number of characters */ 
                                        /* of a description message     */
                                        /* (null character included)    */


typedef int asn1_retCode;  /* type returned by libasn1 functions */

  /*****************************************/
  /*  Errors returned by libasn1 functions */
  /*****************************************/
#define ASN1_SUCCESS               0
#define ASN1_FILE_NOT_FOUND        1
#define ASN1_ELEMENT_NOT_FOUND     2
#define ASN1_IDENTIFIER_NOT_FOUND  3
#define ASN1_DER_ERROR             4
#define ASN1_VALUE_NOT_FOUND       5
#define ASN1_GENERIC_ERROR         6
#define ASN1_VALUE_NOT_VALID       7
#define ASN1_TAG_ERROR             8
#define ASN1_TAG_IMPLICIT          9
#define ASN1_ERROR_TYPE_ANY        10
#define ASN1_SYNTAX_ERROR          11
#define ASN1_MEM_ERROR		   12
#define ASN1_DER_OVERFLOW          13
#define ASN1_NAME_TOO_LONG         14
#define ASN1_ARRAY_ERROR           15
#define ASN1_ELEMENT_NOT_EMPTY     16

/*************************************/
/* Constants used in asn1_visit_tree */
/*************************************/
#define ASN1_PRINT_NAME             1
#define ASN1_PRINT_NAME_TYPE        2
#define ASN1_PRINT_NAME_TYPE_VALUE  3
#define ASN1_PRINT_ALL              4


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



  /***********************************/
  /*  Functions definitions          */
  /***********************************/

asn1_retCode asn1_parser2tree(const char *file_name,ASN1_TYPE *definitions,
                              char *errorDescription);

asn1_retCode asn1_parser2array(const char *inputFileName,const char *outputFileName,
                               const char *vectorName,char *errorDescription);

asn1_retCode asn1_array2tree(const ASN1_ARRAY_TYPE *array,
                             ASN1_TYPE *definitions,char *errorDescription);

void asn1_print_structure(FILE *out,ASN1_TYPE structure,const char *name,int mode);

asn1_retCode asn1_create_element(ASN1_TYPE definitions,const char *source_name,
                                 ASN1_TYPE *element,const char *dest_name);

asn1_retCode asn1_delete_structure(ASN1_TYPE *structure);

asn1_retCode asn1_write_value(ASN1_TYPE element,const char *name,
			      const unsigned char *value,int len);

asn1_retCode asn1_read_value(ASN1_TYPE element,const char *name,unsigned char *value,
                             int *len);

asn1_retCode asn1_number_of_elements(ASN1_TYPE element,const char *name,int *num);

asn1_retCode asn1_der_coding(ASN1_TYPE element,const char *name,
               unsigned char *der,int *len,char *ErrorDescription);

asn1_retCode asn1_der_decoding(ASN1_TYPE *element,const unsigned char *der,int len,
                 char *errorDescription);

asn1_retCode asn1_der_decoding_element(ASN1_TYPE *structure,const char *elementName,
		 const unsigned char *der,int len,char *errorDescription);

asn1_retCode asn1_der_decoding_startEnd(ASN1_TYPE element,const unsigned char *der,
               int len,const char *name,int *start, int *end);

asn1_retCode asn1_expand_any_defined_by(ASN1_TYPE definitions,
               ASN1_TYPE *element);

asn1_retCode asn1_expand_octet_string(ASN1_TYPE definitions,ASN1_TYPE *element,
	       const char *octetName,const char *objectName);

const char* libtasn1_strerror(asn1_retCode error);

void libtasn1_perror(asn1_retCode error);

#ifdef __cplusplus
}
#endif

#endif /* LIBASN1_H */













