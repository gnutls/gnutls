#include "gnutls.h"

/* This file contains functions needed only for binary compatibility
 * with previous versions.
 */
/* #define GNUTLS_BACKWARDS_COMPATIBLE */


#ifdef GNUTLS_BACKWARDS_COMPATIBLE

int gnutls_x509_extract_subject_alt_name( const gnutls_datum *
	cert, int seq, char* ret, int *ret_size) {
	
	return gnutls_x509_extract_certificate_subject_alt_name( cert, seq, ret, ret_size);
}

int gnutls_db_set_name( GNUTLS_STATE state, const char* filename) {
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int gnutls_db_clean( GNUTLS_STATE state) {
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/* nothing here */

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
