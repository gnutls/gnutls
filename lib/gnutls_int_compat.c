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

/* nothing here */

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
