#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_record_set_default_version(gnutls_session session, gnutls_protocol_version version);

void _gnutls_session_cert_type_set( gnutls_session session, gnutls_certificate_type);
gnutls_kx_algorithm gnutls_kx_get( gnutls_session session);
gnutls_cipher_algorithm	gnutls_cipher_get( gnutls_session session);
gnutls_certificate_type gnutls_certificate_type_get( gnutls_session session);

#include <gnutls_auth_int.h>

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(session) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

#endif

int _gnutls_session_cert_type_supported( gnutls_session, gnutls_certificate_type);
int _gnutls_dh_set_peer_public_bits( gnutls_session session, int bits);
int _gnutls_dh_set_secret_bits( gnutls_session session, int bits);
int _gnutls_dh_set_prime_bits( gnutls_session session, int bits);
int _gnutls_dh_get_prime_bits( gnutls_session session);
void gnutls_dh_set_prime_bits( gnutls_session session, int bits);
void _gnutls_handshake_internal_state_clear( gnutls_session);

int _gnutls_rsa_export_set_modulus_bits( gnutls_session session, int bits);

int _gnutls_session_is_resumable( gnutls_session session);
int _gnutls_session_is_export( gnutls_session session);

int _gnutls_openpgp_send_fingerprint( gnutls_session session);

int _gnutls_PRF( const opaque * secret, int secret_size, const uint8 * label, int label_size, opaque * seed, int seed_size, int total_bytes, void* ret);

#define DEFAULT_CERT_TYPE GNUTLS_CRT_X509
