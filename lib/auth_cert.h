#ifndef AUTH_X509_H
# define AUTH_X509_H
# include "gnutls_cert.h"
# include "gnutls_auth.h"
# include "auth_dh_common.h"
# include "x509/x509.h"
#include "../libextra/openpgp/openpgp.h"

typedef struct retr_st {
	gnutls_certificate_type type;
	union cert {
		gnutls_x509_crt* x509;
		gnutls_openpgp_key pgp;
	} cert;
	uint ncerts;

	union key {
		gnutls_x509_privkey x509;
		gnutls_openpgp_privkey pgp;
	} key;
	
	uint deinit_all;
} gnutls_retr_st;

typedef int gnutls_certificate_client_retrieve_function(gnutls_session,
	const gnutls_datum* req_ca_rdn, int nreqs,
	const gnutls_pk_algorithm* pk_algos, int pk_algos_length,
	gnutls_retr_st *);

typedef int gnutls_certificate_server_retrieve_function(
   struct gnutls_session_int*, gnutls_retr_st*);

/* This structure may be complex, but it's the only way to
 * support a server that has multiple certificates
 */
typedef struct {
	gnutls_dh_params dh_params;
	gnutls_rsa_params rsa_params;
	/* this callback is used to retrieve the DH or RSA
	 * parameters.
	 */
	gnutls_params_function * params_func;

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

	gnutls_certificate_client_retrieve_function*	client_get_cert_callback;
	gnutls_certificate_server_retrieve_function*	server_get_cert_callback;
} CERTIFICATE_CREDENTIALS_INT;

/* typedef CERTIFICATE_CREDENTIALS_INT * CERTIFICATE_CREDENTIALS; */
#define gnutls_certificate_credentials CERTIFICATE_CREDENTIALS_INT*

typedef struct rsa_info_st_int {
	opaque	modulus[64];
	size_t	modulus_size;
	opaque	exponent[64];
	size_t	exponent_size;
} rsa_info_st;

typedef struct CERTIFICATE_AUTH_INFO_INT {
	int		  certificate_requested; /* if the peer requested certificate
						  * this is non zero;
						  */
	dh_info_st	  dh;

	rsa_info_st	  rsa_export;
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

gnutls_rsa_params _gnutls_certificate_get_rsa_params(const gnutls_certificate_credentials sc,
	gnutls_session session);
gnutls_dh_params _gnutls_certificate_get_dh_params(const gnutls_certificate_credentials sc,
	gnutls_session session);

#endif

