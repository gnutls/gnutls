#ifndef AUTH_X509_H
# define AUTH_X509_H
# include "gnutls_cert.h"

/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT rsa_auth_struct;

/* This structure may be complex but, it's the only way to
 * support a server that has multiple certificates
 */
typedef struct {
	gnutls_cert ** cert_list; 
			/* contains a list of a list of certificates.
			 * eg:   [0] certificate1, certificate11, certificate111 
			 * (if more than one, one certificate certifies the one before)
			 *       [1] certificate2, certificate22, ...
			 */
	int * cert_list_length;
			/* contains the number of the certificates in a
			 * row.
			 */
	int ncerts;     /* contains the number of columns in cert_list.
			 */
	gnutls_private_key * pkey;   /* private keys. It contains ncerts private
				* keys. pkey[i] corresponds to certificate in
				* cert_list[i][0].
				*/
	gnutls_cert * ca_list;
	int ncas;	/* number of CAs in the ca_list 
			 */
} X509PKI_CREDENTIALS;

typedef struct {
	gnutls_DN	  peer_dn;
	gnutls_DN	  issuer_dn;
	CertificateStatus peer_certificate_status;
} X509PKI_CLIENT_AUTH_INFO;



#endif

