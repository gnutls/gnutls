#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_record_set_default_version(GNUTLS_STATE state, GNUTLS_Version version);

void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertificateType);
KXAlgorithm gnutls_kx_get( GNUTLS_STATE state);
GNUTLS_BulkCipherAlgorithm	gnutls_cipher_get( GNUTLS_STATE state);
CertificateType gnutls_cert_type_get( GNUTLS_STATE state);

#include <gnutls_auth_int.h>

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
void _gnutls_handshake_internal_state_clear( GNUTLS_STATE);

int _gnutls_rsa_export_set_modulus_bits( GNUTLS_STATE state, int bits);

int _gnutls_session_is_resumable( GNUTLS_STATE state);
int _gnutls_session_is_export( GNUTLS_STATE state);

int _gnutls_openpgp_send_fingerprint( GNUTLS_STATE state);

int _gnutls_PRF( const opaque * secret, int secret_size, const uint8 * label, int label_size, opaque * seed, int seed_size, int total_bytes, void* ret);

#define DEFAULT_CERT_TYPE GNUTLS_CRT_X509
