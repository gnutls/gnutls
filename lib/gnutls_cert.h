#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>
#include <x509_asn1.h>
#include <gnutls_ui.h>

#define MAX_PARAMS_SIZE 5 /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define MAX_PARAMETER_SIZE 1200
#define DSA_PARAMS 5
#define RSA_PARAMS 3

#if MAX_PARAMS_SIZE - RSA_PARAMS < 0
# error INCREASE RSA_PARAMS
#endif

#if MAX_PARAMS_SIZE - DSA_PARAMS < 0
# error INCREASE DSA_PARAMS
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
	PKAlgorithm subject_pk_algorithm;

	opaque	   signature[1024];
	int	   signature_size;
	
	time_t	   expiration_time;
	time_t	   activation_time;

	int	   version; /* 1,2,3 
 	                     */
 	
 	uint8	   keyUsage; /* bits from X509KEY_* 
 	                      */
 	
	int        valid; /* 0 if the certificate looks good.
	                   */

	int        CA;    /* 0 if the certificate does not belong to
	                   * a certificate authority. 1 otherwise.
	                   */

			/* holds the type (PGP, X509)
			 */
	CertType     cert_type;
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
				 * DSA: [0] is p
				 *      [1] is q
				 *      [2] is g
				 *      [3] is y (public key)
				 *      [4] is x (private key)
				 */

	PKAlgorithm pk_algorithm;

	gnutls_datum raw; /* the raw key */
} gnutls_private_key;

struct GNUTLS_STATE_INT; /* because GNUTLS_STATE is not defined when this file is included */

int _gnutls_cert_supported_kx( const gnutls_cert* cert, KXAlgorithm **alg, int *alg_size);
PKAlgorithm _gnutls_map_pk_get_pk(KXAlgorithm kx_algorithm);
int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(int k, char* data);
int _gnutls_get_name_type( node_asn *rasn, char *root, gnutls_dn * dn);
void gnutls_free_cert(gnutls_cert cert);
int _gnutls_check_x509pki_key_usage( const gnutls_cert * cert, KXAlgorithm alg);
int _gnutls_get_version(node_asn * c2, char *root);
time_t _gnutls_get_time(node_asn * c2, char *root, char *when);

#endif
