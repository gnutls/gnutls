#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertificateType);
KXAlgorithm gnutls_kx_get( GNUTLS_STATE state);
CertificateType gnutls_cert_type_get( GNUTLS_STATE state);

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

#endif

int _gnutls_state_cert_type_supported( GNUTLS_STATE, CertificateType);
int _gnutls_dh_set_peer_public_bits( GNUTLS_STATE state, int bits);
int _gnutls_dh_set_secret_bits( GNUTLS_STATE state, int bits);
int _gnutls_dh_set_prime_bits( GNUTLS_STATE state, int bits);
int _gnutls_dh_get_prime_bits( GNUTLS_STATE state);
void gnutls_dh_set_prime_bits( GNUTLS_STATE state, int bits);

int _gnutls_openpgp_send_fingerprint( GNUTLS_STATE state);

#define DEFAULT_CERT_TYPE GNUTLS_CRT_X509
