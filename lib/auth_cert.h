#ifndef AUTH_X509_H
# define AUTH_X509_H
# include "gnutls_cert.h"
# include "gnutls_auth.h"

/* This structure may be complex but, it's the only way to
 * support a server that has multiple certificates
 */
typedef struct {

	gnutls_cert ** cert_list; 
			/* contains a list of a list of certificates.
			 * eg (X509): [0] certificate1, certificate11, certificate111 
			 * (if more than one, one certificate certifies the one before)
			 *       [1] certificate2, certificate22, ...
			 */
	int * cert_list_length;
			/* contains the number of the certificates in a
			 * row (should be 1 for OpenPGP keys).
			 */
	int ncerts;     /* contains the number of columns in cert_list.
	                 * This is the same with the number of pkeys.
			 */

	gnutls_private_key * pkey; 
			       /* private keys. It contains ncerts private
				* keys. pkey[i] corresponds to certificate in
				* cert_list[i][0].
				*/

	/* OpenPGP specific stuff */

	gnutls_datum keyring;
    
	/* X509 specific stuff */

	gnutls_cert * x509_ca_list;
	int x509_ncas;	/* number of CAs in the ca_list 
			 */

			/* holds a sequence of the
			 * RDNs of the CAs above.
			 * This is better than
			 * generating it every time.
			 */
	gnutls_datum	x509_rdn_sequence;
} CERTIFICATE_CREDENTIALS_INT;

/* typedef CERTIFICATE_CREDENTIALS_INT * CERTIFICATE_CREDENTIALS; */
#define GNUTLS_CERTIFICATE_CREDENTIALS CERTIFICATE_CREDENTIALS_INT*

typedef struct CERTIFICATE_AUTH_INFO_INT {
	int		  certificate_requested; /* if the peer requested certificate
						  * this is non zero;
						  */
	int		  dh_bits; /* bits of the DH (if DHE_RSA is used) */
	gnutls_datum*	  raw_certificate_list; /* holds the raw certificate of the
					         * peer.
					         */
	int 		  ncerts; /* holds the size of the list above */
} *CERTIFICATE_AUTH_INFO;

typedef struct CERTIFICATE_AUTH_INFO_INT CERTIFICATE_AUTH_INFO_INT;

/* AUTH X509 functions */
int _gnutls_gen_cert_server_certificate(GNUTLS_STATE, opaque **);
int _gnutls_gen_cert_client_certificate(GNUTLS_STATE, opaque **);
int _gnutls_gen_cert_client_cert_vrfy(GNUTLS_STATE, opaque **);
int _gnutls_gen_cert_server_cert_req(GNUTLS_STATE, opaque **);
int _gnutls_proc_cert_cert_req(GNUTLS_STATE, opaque *, int);
int _gnutls_proc_cert_client_cert_vrfy(GNUTLS_STATE, opaque *, int);
int _gnutls_proc_cert_server_certificate(GNUTLS_STATE, opaque *, int);
int _gnutls_find_apr_cert( GNUTLS_STATE state, gnutls_cert** apr_cert_list, int *apr_cert_list_length, gnutls_private_key** apr_pkey);
int _gnutls_find_dn( gnutls_datum* odn, gnutls_cert* cert);
const gnutls_cert* _gnutls_server_find_cert( struct GNUTLS_STATE_INT*, PKAlgorithm);
int _gnutls_server_find_cert_list_index( struct GNUTLS_STATE_INT*, gnutls_cert ** cert_list, int cert_list_length, PKAlgorithm);

#define _gnutls_proc_cert_client_certificate _gnutls_proc_cert_server_certificate

#endif

