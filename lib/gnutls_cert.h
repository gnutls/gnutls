#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>
#include <libtasn1.h>
#include <gnutls_ui.h>
#include "x509/x509.h"

#define MAX_PUBLIC_PARAMS_SIZE 4 /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PUBLIC_PARAMS 4
#define RSA_PUBLIC_PARAMS 2

/* For key Usage, test as:
 * if (st.keyUsage & KEY_DIGITAL_SIGNATURE) ...
 */
#define KEY_DIGITAL_SIGNATURE 		256
#define KEY_NON_REPUDIATION		128
#define KEY_KEY_ENCIPHERMENT		64
#define KEY_DATA_ENCIPHERMENT		32
#define KEY_KEY_AGREEMENT		16
#define KEY_KEY_CERT_SIGN		8
#define KEY_CRL_SIGN			4
#define KEY_ENCIPHER_ONLY		2
#define KEY_DECIPHER_ONLY		1

typedef struct gnutls_cert {
	GNUTLS_MPI params[MAX_PUBLIC_PARAMS_SIZE];	/* the size of params depends on the public 
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

 	unsigned int keyUsage; /* bits from KEY_* 
				  */

	unsigned int version; 	
			/* holds the type (PGP, X509)
			 */
	gnutls_certificate_type     cert_type;
	
	gnutls_datum raw;
	
} gnutls_cert;

typedef struct gnutls_privkey_int {
	GNUTLS_MPI params[MAX_PRIV_PARAMS_SIZE];/* the size of params depends on the public 
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
} gnutls_privkey;

struct gnutls_session_int; /* because gnutls_session is not defined when this file is included */

typedef enum ConvFlags { 
	CERT_NO_COPY=2, 
	CERT_ONLY_PUBKEY=4,
	CERT_ONLY_EXTENSIONS=16
} ConvFlags;

int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gcert, const gnutls_datum *derCert,
	int flags);
int _gnutls_x509_crt2gnutls_cert(gnutls_cert * gcert, gnutls_x509_crt cert,
	unsigned int flags);
int _gnutls_cert_get_dn(gnutls_cert * cert, gnutls_datum * odn);

void _gnutls_privkey_deinit(gnutls_privkey *key);
void _gnutls_cert_deinit(gnutls_cert *cert);

int _gnutls_selected_cert_supported_kx(struct gnutls_session_int* session, 
	gnutls_kx_algorithm ** alg, int *alg_size);
int _gnutls_cert2gnutls_cert(gnutls_cert * gcert, gnutls_certificate_type type,
        const gnutls_datum *raw_cert, int flags /* OR of ConvFlags */);
int _gnutls_key2gnutls_key(gnutls_privkey * key, gnutls_certificate_type type,
	const gnutls_datum *raw_key, int key_enc /* DER or PEM */);
                                      
#endif
