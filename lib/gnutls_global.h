#ifndef GNUTLS_GLOBAL_H
# define GNUTLS_GLOBAL_H

#include <libasn1.h>

int gnutls_is_secure_memory(const void* mem);
ASN1_TYPE _gnutls_get_gnutls_asn(void);
ASN1_TYPE _gnutls_get_pkix(void);

#endif
