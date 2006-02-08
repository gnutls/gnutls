/*************************************************/
/* File: der.h                                   */
/* Description: list of definitions and exported */
/*   objects by coding.c and decoding.c          */
/*************************************************/

#ifndef _DER_H
#define _DER_H


#define UNIVERSAL        0x00
#define APPLICATION      0x40
#define CONTEXT_SPECIFIC 0x80
#define PRIVATE          0xC0
#define STRUCTURED       0x20


#define TAG_BOOLEAN          0x01
#define TAG_INTEGER          0x02
#define TAG_SEQUENCE         0x10
#define TAG_SET              0x11
#define TAG_OCTET_STRING     0x04
#define TAG_BIT_STRING       0x03
#define TAG_UTCTime          0x17
#define TAG_GENERALIZEDTime  0x18
#define TAG_OBJECT_ID        0x06
#define TAG_ENUMERATED       0x0A
#define TAG_NULL             0x05
#define TAG_GENERALSTRING    0x1B

int _asn1_get_tag_der(const unsigned char *der, int der_len,
                unsigned char *class,int  *len, unsigned long *tag);

void _asn1_octet_der(const unsigned char *str,int str_len,
                     unsigned char *der,int *der_len);

asn1_retCode _asn1_get_octet_der(const unsigned char *der, int der_len,
                int *ret_len,unsigned char *str,int str_size, int *str_len);

void _asn1_bit_der(const unsigned char *str,int bit_len,
                   unsigned char *der,int *der_len);

asn1_retCode _asn1_get_bit_der(const unsigned char *der, int der_len,
                int *ret_len,unsigned char *str, int str_size, 
                int *bit_len);

signed long _asn1_get_length_der(const unsigned char *der,int der_len, int  *len);

void _asn1_length_der(unsigned long len,unsigned char *ans,int *ans_len);


#endif





