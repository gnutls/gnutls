#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

CertType _gnutls_state_cert_type_get( GNUTLS_STATE state);
void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertType);


#endif
