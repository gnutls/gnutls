#include <gnutls/gnutls.h>

/* This file contains functions needed only for binary compatibility
 * with previous versions.
 */
#define GNUTLS_BACKWARDS_COMPATIBLE 

#ifdef GNUTLS_BACKWARDS_COMPATIBLE

void gnutls_handshake_set_exportable_detection(GNUTLS_STATE state, int det)
{
	return;
}

/* nothing here */

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
