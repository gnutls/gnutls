#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_session_cert_type_set(gnutls_session_t session,
				   gnutls_certificate_type_t);
gnutls_kx_algorithm_t gnutls_kx_get(gnutls_session_t session);
gnutls_cipher_algorithm_t gnutls_cipher_get(gnutls_session_t session);
gnutls_certificate_type_t gnutls_certificate_type_get(gnutls_session_t);

#include <gnutls_auth_int.h>

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(session) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

#endif

int _gnutls_session_cert_type_supported(gnutls_session_t,
					gnutls_certificate_type_t);

int _gnutls_dh_set_secret_bits(gnutls_session_t session, uint bits);

int _gnutls_dh_set_peer_public(gnutls_session_t session, mpi_t public);
int _gnutls_dh_set_group(gnutls_session_t session, mpi_t gen, mpi_t prime);

int _gnutls_dh_get_allowed_prime_bits(gnutls_session_t session);
void gnutls_dh_set_prime_bits(gnutls_session_t session, unsigned int bits);
void _gnutls_handshake_internal_state_clear(gnutls_session_t);

int _gnutls_rsa_export_set_pubkey(gnutls_session_t session, mpi_t exp,
				  mpi_t mod);

int _gnutls_session_is_resumable(gnutls_session_t session);
int _gnutls_session_is_export(gnutls_session_t session);

int _gnutls_openpgp_send_fingerprint(gnutls_session_t session);

int _gnutls_PRF(const opaque * secret, int secret_size, const char *label,
		int label_size, opaque * seed, int seed_size,
		int total_bytes, void *ret);

#define DEFAULT_CERT_TYPE GNUTLS_CRT_X509
