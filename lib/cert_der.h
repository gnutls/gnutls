/*************************************************/
/* File: gnutls_der.h                            */
/* Description: list of exported object by       */
/*   "gnutls_der.c"                              */
/*************************************************/

#ifndef _GNUTLS_DER_H
#define _GNUTLS_DER_H

#define UNIVERSAL        0x00
#define APPLICATION      0x40
#define CONTEXT_SPECIFIC 0x80
#define PRIVATE          0xC0
#define STRUCTURED       0x20


int 
create_der(char *name,unsigned char *der,int *len);

int 
get_der(char *name,unsigned char *der,int len);

void
octet_der(unsigned char *str,int str_len,unsigned char *der,int *der_len);

void
get_octet_der(unsigned char *der,int *der_len,unsigned char *str,int *str_len);

void
bit_der(unsigned char *str,int bit_len,unsigned char *der,int *der_len);

void
get_bit_der(unsigned char *der,int *der_len,unsigned char *str,int *bit_len);

void
length_der(unsigned long len,unsigned char *ans,int *ans_len);

unsigned int
get_tag_der(unsigned char *der,unsigned char *class,int  *len);

unsigned long
get_length_der(unsigned char *der,int  *len);

char *
ltostr(long v,char *str);

#endif
