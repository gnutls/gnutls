#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>
#include <libasn1.h>
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
	
	PKAlgorithm subject_pk_algorithm;

	gnutls_datum   signature;

	time_t	   expiration_time;
	time_t	   activation_time;

	int	   version; /* 1,2,3 
 	                     */
 	
 	uint16	   keyUsage; /* bits from X509KEY_* 
 	                      */
 	
	int        valid; /* 0 if the certificate looks good.
	                   */

	int        CA;    /* 0 if the certificate does not belong to
	                   * a certificate authority. 1 otherwise.
	                   */

			/* holds the type (PGP, X509)
			 */
	CertificateType     cert_type;
	
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

	PKAlgorithm pk_algorithm;

	gnutls_datum raw; /* the raw key */
} gnutls_private_key;

struct GNUTLS_STATE_INT; /* because GNUTLS_STATE is not defined when this file is included */

int _gnutls_cert_supported_kx( const gnutls_cert* cert, KXAlgorithm **alg, int *alg_size);
PKAlgorithm _gnutls_map_pk_get_pk(KXAlgorithm kx_algorithm);

void _gnutls_free_cert(gnutls_cert cert);

#endif
