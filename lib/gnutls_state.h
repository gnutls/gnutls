#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertificateType);
KXAlgorithm gnutls_kx_get( GNUTLS_STATE state);
CertificateType gnutls_cert_type_get( GNUTLS_STATE state);


#endif
