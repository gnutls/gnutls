/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT rsa_auth_struct;

/* This structure may be complex but, it's the only way to
 * support a server that has multiple certificates
 */
typedef struct {
	gnutls_datum ** cert_list; 
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
	gnutls_datum * pkey;   /* private keys. It contains ncerts private
				* keys. pkey[i] corresponds to certificate in
				* cert_list[i][0].
				*/
} X509PKI_SERVER_CREDENTIALS;

typedef struct {
	opaque dnsname[256];
} X509PKI_CLIENT_CREDENTIALS;

typedef struct {
	opaque dnsname[256];  /* the client may send us the 
			       * hostname he thinks he connected to.
			       */
} X509PKI_AUTH_INFO;
