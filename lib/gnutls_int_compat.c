#include <gnutls/gnutls.h>

/* This file contains functions needed only for binary compatibility
 * with previous versions.
 */
#define GNUTLS_BACKWARDS_COMPATIBLE 

#ifdef GNUTLS_BACKWARDS_COMPATIBLE

#undef gnutls_handshake_set_exportable_detection
void gnutls_handshake_set_exportable_detection(gnutls_session session, int det)
{
	return;
}

#undef gnutls_state_get_ptr
void* gnutls_state_get_ptr(gnutls_session session) 
{
	return gnutls_session_get_ptr( session);
}

#undef gnutls_state_set_ptr
void gnutls_state_set_ptr(gnutls_session session, void* ptr) 
{
	return gnutls_state_set_ptr( session, ptr);
}

#undef gnutls_init
int gnutls_init(gnutls_session * session, gnutls_connection_end con_end)
{
	return gnutls_session_init( session, con_end);
}

#undef _gnutls_deinit
void _gnutls_deinit(gnutls_session session)
{
	_gnutls_session_deinit( session);
}

#undef gnutls_deinit
void gnutls_deinit(gnutls_session session)
{
	gnutls_session_deinit( session);
}

#undef gnutls_cert_type_get
gnutls_certificate_type gnutls_cert_type_get( gnutls_session session) {
	return gnutls_certificate_type_get( session);
}

#undef gnutls_cert_type_set_priority
int gnutls_cert_type_set_priority( gnutls_session session, const int* list) {
	return gnutls_certificate_type_set_priority( session, list);
}

#undef gnutls_cert_type_get_name
const char *gnutls_cert_type_get_name( gnutls_certificate_type type)
{
	return gnutls_certificate_type_get_name( type);
}

#undef gnutls_b64_encode_fmt
int gnutls_b64_encode_fmt( const char* msg, const gnutls_datum *data, char* result, int* result_size) 
{
	return gnutls_pem_base64_encode( msg, data, result, result_size);
}

#undef gnutls_b64_encode_fmt2
int gnutls_b64_encode_fmt2( const char* msg, const gnutls_datum *data, gnutls_datum* result) 
{
	return gnutls_pem_base64_encode_alloc( msg, data, result);
}

#undef gnutls_b64_decode_fmt
int gnutls_b64_decode_fmt( const gnutls_datum *b64_data, char* result, int* result_size) 
{
	return gnutls_pem_base64_decode( NULL, b64_data, result, result_size);
}

#undef gnutls_b64_decode_fmt2
int gnutls_b64_decode_fmt2( const gnutls_datum *b64_data, gnutls_datum* result) 
{
	return gnutls_pem_base64_decode_alloc( NULL, b64_data, result);
}

/* nothing here */

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
