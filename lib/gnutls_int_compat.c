#include "gnutls.h"

/* This file contains functions needed only for binary compatibility
 * with previous versions.
 */
/* #define GNUTLS_BACKWARDS_COMPATIBLE */


#ifdef GNUTLS_BACKWARDS_COMPATIBLE

/* used in 0.3.x */
int gnutls_anon_set_server_cred( GNUTLS_ANON_SERVER_CREDENTIALS res, int dh_bits) {
	return 0;
}

/* used in 0.3.x */
int gnutls_check_pending( GNUTLS_STATE state) {
	return gnutls_record_check_pending( state);
}

/* used in 0.3.x */
void gnutls_x509pki_set_dh_bits(GNUTLS_STATE state, int bits) {
	gnutls_dh_set_bits( state, bits);
}

/* used in 0.3.x */
int gnutls_anon_server_get_dh_bits(GNUTLS_STATE state)
{
	return gnutls_dh_get_bits( state);
}

/* used in 0.3.x */
int gnutls_anon_client_get_dh_bits(GNUTLS_STATE state)
{
	return gnutls_dh_get_bits( state);
}

/* used in 0.3.x */
int gnutls_set_max_handshake_data_buffer_size( GNUTLS_STATE state) {
	return 0;
}

GNUTLS_BulkCipherAlgorithm gnutls_cipher_get_algo( GNUTLS_STATE state) {
	return gnutls_cipher_get( state);
}
GNUTLS_KXAlgorithm 	    gnutls_kx_get_algo( GNUTLS_STATE state) {
	return gnutls_kx_get( state);
}

GNUTLS_MACAlgorithm	    gnutls_mac_get_algo( GNUTLS_STATE state) {
	return gnutls_mac_get( state);
}

GNUTLS_CompressionMethod   gnutls_compression_get_algo( GNUTLS_STATE state) {
	return gnutls_compression_get( state);
}

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
