#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>
#include <libtasn1.h>
#include <gnutls_ui.h>

#define MAX_PARAMS_SIZE 6 /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define MAX_PARAMETER_SIZE 1200
#define DSA_PRIVATE_PARAMS 5
#define DSA_PUBLIC_PARAMS 4
#define RSA_PRIVATE_PARAMS 6
#define RSA_PUBLIC_PARAMS 2

#if MAX_PARAMS_SIZE - RSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PARAMS
#endif

#if MAX_PARAMS_SIZE - DSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PARAMS
#endif

typedef struct gnutls_cert {
	MPI params[MAX_PARAMS_SIZE];	/* the size of params depends on the public 
				 * key algorithm 
				 * RSA: [0] is modulus
				 *      [1] is public exponent
				 * DSA: [0] is p
				 *      [1] is q
				 *      [2] is g
				 *      [3] is public key
				 */
	int params_size; /* holds the size of MPI params */
	
	gnutls_pk_algorithm subject_pk_algorithm;

	gnutls_datum   signature;

	time_t	   expiration_time;
	time_t	   activation_time;

	int	   version; /* 1,2,3 
 	                     */
 	
 	uint16	   keyUsage; /* bits from X509KEY_* 
 	                      */
 	
	int        CA;    /* 0 if the certificate does not belong to
	                   * a certificate authority. 1 otherwise.
	                   */

			/* holds the type (PGP, X509)
			 */
	gnutls_certificate_type     cert_type;
	
	gnutls_datum raw; /* the raw certificate */
} gnutls_cert;

typedef struct {
	MPI params[MAX_PARAMS_SIZE];/* the size of params depends on the public 
				 * key algorithm 
				 */
				/*
				 * RSA: [0] is modulus
				 *      [1] is public exponent
				 *	[2] is private exponent
				 *	[3] is prime1 (p)
				 *	[4] is prime2 (q)
				 *	[5] is coefficient (u == inverse of p mod q)
				 * DSA: [0] is p
				 *      [1] is q
				 *      [2] is g
				 *      [3] is y (public key)
				 *      [4] is x (private key)
				 */
	int params_size; /* holds the number of params */

	gnutls_pk_algorithm pk_algorithm;

	gnutls_datum raw; /* the raw key */
} gnutls_private_key;

struct gnutls_session_int; /* because gnutls_session is not defined when this file is included */

int _gnutls_cert_supported_kx( const gnutls_cert* cert, gnutls_kx_algorithm **alg, int *alg_size);
gnutls_pk_algorithm _gnutls_map_pk_get_pk(gnutls_kx_algorithm kx_algorithm);

void _gnutls_free_cert(gnutls_cert cert);

#endif
