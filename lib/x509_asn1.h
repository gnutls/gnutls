
/*************************************************/
/* File: x509_asn1.h                             */
/* Description: list of exported object by       */
/*   "x509_asn1.c"                               */
/*************************************************/

#ifndef _GNUTLS_ASN1_H
#define _GNUTLS_ASN1_H

#define PARSE_MODE_CHECK  1
#define PARSE_MODE_CREATE 2

/* List of constants for field type of typedef node_asn  */
#define TYPE_CONSTANT     1
#define TYPE_IDENTIFIER   2
#define TYPE_INTEGER      3
#define TYPE_BOOLEAN      4
#define TYPE_SEQUENCE     5
#define TYPE_BIT_STRING   6
#define TYPE_OCTET_STRING 7
#define TYPE_TAG          8
#define TYPE_DEFAULT      9
#define TYPE_SIZE        10
#define TYPE_SEQUENCE_OF 11
#define TYPE_OBJECT_ID   12
#define TYPE_ANY         13
#define TYPE_SET         14
#define TYPE_SET_OF      15
#define TYPE_DEFINITIONS 16
#define TYPE_TIME        17
#define TYPE_CHOICE      18
#define TYPE_IMPORTS     19
#define TYPE_NULL        20
#define TYPE_ENUMERATED  21


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

#define CONST_IMPORTS     (1<<25)

#define CONST_NOT_USED    (1<<26)
#define CONST_SET         (1<<27)
#define CONST_ASSIGN      (1<<28)

#define CONST_DOWN        (1<<29)
#define CONST_RIGHT       (1<<30)


#define ASN_OK                    0
#define ASN_FILE_NOT_FOUND        1
#define ASN_ELEMENT_NOT_FOUND     2
#define ASN_IDENTIFIER_NOT_FOUND  3
#define ASN_DER_ERROR             4
#define ASN_VALUE_NOT_FOUND       5
#define ASN_GENERIC_ERROR         6
#define ASN_VALUE_NOT_VALID       7
#define ASN_TAG_ERROR             8
#define ASN_TAG_IMPLICIT          9
#define ASN_ERROR_TYPE_ANY        10
#define ASN_SYNTAX_ERROR          11
#define ASN_MEM_ERROR		  12
#define ASN_DER_OVERFLOW          13


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



typedef struct static_struct_asn{
  char *name;                    /* Node name */
  unsigned int type;             /* Node type */
  unsigned char *value;          /* Node value */
} static_asn;


/****************************************/
/* Returns the first 8 bits.            */
/* Used with the field type of node_asn */
/****************************************/
#define type_field(x)     (x&0xFF) 


/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
node_asn *
_asn1_add_node(unsigned int type);

node_asn *
_asn1_set_value(node_asn *node,unsigned char *value,unsigned int len);

node_asn *
_asn1_set_name(node_asn *node,char *name);

node_asn *
_asn1_set_right(node_asn *node,node_asn *right);

node_asn *
_asn1_get_right(node_asn *node);

node_asn *
_asn1_get_last_right(node_asn *node);

node_asn *
_asn1_set_down(node_asn *node,node_asn *down);

char *
_asn1_get_name(node_asn *node);

node_asn *
_asn1_get_down(node_asn *node);

node_asn *
_asn1_mod_type(node_asn *node,unsigned int value);

void
_asn1_append_tree(node_asn *node);

node_asn *
_asn1_find_node(node_asn *pointer,char *name);

node_asn *
_asn1_find_up(node_asn *node);

int 
_asn1_append_sequence_set(node_asn *node);

int 
_asn1_delete_not_used(node_asn *node);

int 
_asn1_set_default_tag(node_asn *node);

/* prototypes - not defined elsewere */
int _asn1_change_integer_value(node_asn *node);
int _asn1_expand_object_id(node_asn *node);
int _asn1_expand_identifier(node_asn **node,node_asn *root);
int _asn1_type_choice_config(node_asn *node);
int _asn1_type_set_config(node_asn *node);
int _asn1_check_identifier(node_asn *node);
int _asn1_create_static_structure(node_asn *pointer,char *file_name, char* out_name);

int 
asn1_parser_asn1(char *file_name,node_asn **pointer);

int
asn1_create_structure(node_asn *root,char *source_name,node_asn **pointer,
		 char *dest_name);

int
asn1_delete_structure(node_asn *root);

int 
asn1_write_value(node_asn *root,char *name,unsigned char *value,int len);

int 
asn1_read_value(node_asn *root,char *name,unsigned char *value,int *len);

int
asn1_create_tree(const static_asn *root,node_asn **pointer);

int 
asn1_number_of_elements(node_asn *root,char *name,int *num);

#endif

