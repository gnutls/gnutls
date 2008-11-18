
#ifndef _ELEMENT_H
#define _ELEMENT_H


asn1_retCode _asn1_append_sequence_set(ASN1_TYPE node);

asn1_retCode _asn1_convert_integer(const char *value,unsigned char *value_out,
			  int value_out_size, int *len);

void _asn1_hierarchical_name(ASN1_TYPE node,char *name,int name_size);

#endif
