
/*************************************************/
/* File: gnutls_asn1.h                           */
/* Description: list of exported object by       */
/*   "gnutls_asn1.c"                             */
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


#define CHECK_TYPE              1
#define CHECK_NOT_USED          2
#define CHECK_INTEGER           3
#define CHECK_DEFAULT_TAG_TYPE  4


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
#define ASN_ERROR_TYPE_ANY       10
#define ASN_SYNTAX_ERROR         11


/******************************************************/
/* Structure definition used for the node of the tree */
/* that rappresent an ASN.1 DEFINITION.               */
/******************************************************/
typedef struct node_asn_struct{
  struct node_asn_struct *list;  /* Pointer to the next list element */ 
  char *name;                    /* Node name */
  unsigned int type;             /* Node type */
  unsigned char *value;          /* Node value */
  struct node_asn_struct *down;  /* Pointer to the son node */
  struct node_asn_struct *right; /* Pointer to the brother node */
} node_asn;


/****************************************/
/* Returns the first 8 bits.            */
/* Used with the field type of node_asn */
/****************************************/
#define type_field(x)     (x&0xFF) 


/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
node_asn *
add_node(unsigned int type);

node_asn *
set_value(node_asn *node,unsigned char *value,unsigned int len);

node_asn *
set_name(node_asn *node,char *name);

node_asn *
set_right(node_asn *node,node_asn *right);

node_asn *
get_right(node_asn *node);

node_asn *
get_last_right(node_asn *node);

node_asn *
set_down(node_asn *node,node_asn *down);

char *
get_name(node_asn *node);

node_asn *
get_down(node_asn *node);

node_asn *
mod_type(node_asn *node,unsigned int value);

node_asn *
find_node(char *name);

node_asn *
find_up(node_asn *node);

int 
write_value(char *name,unsigned char *value,int len);

int 
read_value(char *name,unsigned char *value,int *len);


int 
check_asn(char *name,int check);

int 
expand_asn(char *name,char *root);

int
delete_tree2(node_asn *root);

int 
append_sequence_set(node_asn *node);

#endif

