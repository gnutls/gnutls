
/*************************************************/
/* File: structure.h                             */
/* Description: list of exported object by       */
/*   "structure.c"                               */
/*************************************************/

#ifndef _STRUCTURE_H
#define _STRUCTURE_H

asn1_retCode _asn1_create_static_structure(ASN1_TYPE pointer,
       char* output_file_name,char *vector_name);

ASN1_TYPE _asn1_copy_structure3(ASN1_TYPE source_node);

ASN1_TYPE  _asn1_add_node_only(unsigned int type);

ASN1_TYPE  _asn1_find_left(ASN1_TYPE node);

#endif

