#ifndef GNUTLS_GLOBAL_H
# define GNUTLS_GLOBAL_H

#include <x509_asn1.h>

int gnutls_is_secure_memory(const void* mem);
node_asn* _gnutls_get_pkcs(void);
node_asn* _gnutls_get_pkix(void);

#endif
