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

/* nothing here */

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
