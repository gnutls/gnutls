#ifndef GNUTLS_GLOBAL_H
# define GNUTLS_GLOBAL_H

#include <libtasn1.h>

int gnutls_global_init(void);
int gnutls_is_secure_memory(const void *mem);

extern ASN1_TYPE _gnutls_pkix1_asn;
extern ASN1_TYPE _gnutls_gnutls_asn;

#define _gnutls_get_gnutls_asn() _gnutls_gnutls_asn
#define _gnutls_get_pkix() _gnutls_pkix1_asn

#endif
