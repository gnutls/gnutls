
#ifndef _PARSER_AUX_H
#define _PARSER_AUX_H

#define DER_LEN 16

/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
ASN1_TYPE
_asn1_add_node(unsigned int type);

ASN1_TYPE
_asn1_set_value(ASN1_TYPE node,const void *value,unsigned int len);

ASN1_TYPE
_asn1_set_value_m(ASN1_TYPE node,void *value,unsigned int len);

ASN1_TYPE
_asn1_set_value_octet(ASN1_TYPE node,const void *value,unsigned int len);

ASN1_TYPE
_asn1_append_value(ASN1_TYPE node,const void *value,unsigned int len);

ASN1_TYPE
_asn1_set_name(ASN1_TYPE node,const char *name);

ASN1_TYPE
_asn1_set_right(ASN1_TYPE node, ASN1_TYPE right);

ASN1_TYPE
_asn1_get_right(ASN1_TYPE node);

ASN1_TYPE
_asn1_get_last_right(ASN1_TYPE node);

ASN1_TYPE
_asn1_set_down(ASN1_TYPE node, ASN1_TYPE down);

char *
_asn1_get_name(ASN1_TYPE node);

ASN1_TYPE
_asn1_get_down(ASN1_TYPE node);

ASN1_TYPE
_asn1_mod_type(ASN1_TYPE node,unsigned int value);

void
_asn1_remove_node(ASN1_TYPE node);

void _asn1_delete_list(void);

void _asn1_delete_list_and_nodes(void);

char * _asn1_ltostr(long v,char *str);

ASN1_TYPE _asn1_find_up(ASN1_TYPE node);

asn1_retCode _asn1_change_integer_value(ASN1_TYPE node);

asn1_retCode _asn1_expand_object_id(ASN1_TYPE node);

asn1_retCode _asn1_type_set_config(ASN1_TYPE node);

asn1_retCode _asn1_check_identifier(ASN1_TYPE node);

asn1_retCode _asn1_set_default_tag(ASN1_TYPE node);

#endif



