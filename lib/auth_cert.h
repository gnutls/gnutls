#ifndef AUTH_X509_H
# define AUTH_X509_H
# include "gnutls_cert.h"
# include "gnutls_auth.h"
# include "x509/x509.h"

/* This structure may be complex, but it's the only way to
 * support a server that has multiple certificates
 */
typedef struct {
	gnutls_dh_params dh_params;
	gnutls_rsa_params rsa_params;

	gnutls_cert ** cert_list; 
			/* contains a list of a list of certificates.
			 * eg (X509): [0] certificate1, certificate11, certificate111 
			 * (if more than one, one certificate certifies the one before)
			 *       [1] certificate2, certificate22, ...
			 */
	uint * cert_list_length;
			/* contains the number of the certificates in a
			 * row (should be 1 for OpenPGP keys).
			 */
	uint ncerts;/* contains the number of columns in cert_list.
	                 * This is the same with the number of pkeys.
			 */

	gnutls_privkey * pkey; 
			       /* private keys. It contains ncerts private
				* keys. pkey[i] corresponds to certificate in
				* cert_list[i][0].
				*/

	/* OpenPGP specific stuff */

	gnutls_datum keyring;
	char *	     pgp_key_server;
	int	     pgp_key_server_port;

	char *	     pgp_trustdb;
	    
	/* X509 specific stuff */

	gnutls_x509_crt * x509_ca_list;
	uint x509_ncas;	/* number of CAs in the ca_list 
			 */

	gnutls_x509_crl * x509_crl_list;
	uint x509_ncrls;/* number of CRLs in the crl_list 
			 */
			 
	unsigned int    verify_flags; /* flags to be used at 
				       * certificate verification.
				       */

			/* holds a sequence of the
			 * RDNs of the CAs above.
			 * This is better than
			 * generating on every handshake.
			 */
	gnutls_datum	x509_rdn_sequence;
} CERTIFICATE_CREDENTIALS_INT;

/* typedef CERTIFICATE_CREDENTIALS_INT * CERTIFICATE_CREDENTIALS; */
#define gnutls_certificate_credentials CERTIFICATE_CREDENTIALS_INT*

typedef struct CERTIFICATE_AUTH_INFO_INT {
	int		  certificate_requested; /* if the peer requested certificate
						  * this is non zero;
						  */
	int		  dh_secret_bits; /* bits of the DH (if DHE_RSA is used) */
	int		  dh_prime_bits;
	int		  dh_peer_public_bits; 

	int		  rsa_export_modulus_bits;
	gnutls_datum*	  raw_certificate_list; /* holds the raw certificate of the
					         * peer.
					         */
	unsigned int	  ncerts; /* holds the size of the list above */
} *CERTIFICATE_AUTH_INFO;

typedef struct CERTIFICATE_AUTH_INFO_INT CERTIFICATE_AUTH_INFO_INT;

/* AUTH X509 functions */
int _gnutls_gen_cert_server_certificate(gnutls_session, opaque **);
int _gnutls_gen_cert_client_certificate(gnutls_session, opaque **);
int _gnutls_gen_cert_client_cert_vrfy(gnutls_session, opaque **);
int _gnutls_gen_cert_server_cert_req(gnutls_session, opaque **);
int _gnutls_proc_cert_cert_req(gnutls_session, opaque *, size_t);
int _gnutls_proc_cert_client_cert_vrfy(gnutls_session, opaque *, size_t);
int _gnutls_proc_cert_server_certificate(gnutls_session, opaque *, size_t);
int _gnutls_get_selected_cert( gnutls_session session, gnutls_cert** apr_cert_list, int *apr_cert_list_length, gnutls_privkey** apr_pkey);

int _gnutls_server_select_cert( struct gnutls_session_int*, gnutls_pk_algorithm);
void _gnutls_selected_certs_deinit( gnutls_session session);
void _gnutls_selected_certs_set( gnutls_session session,
        gnutls_cert* certs, int ncerts, gnutls_privkey* key,
        int need_free);

#define _gnutls_proc_cert_client_certificate _gnutls_proc_cert_server_certificate

#endif

