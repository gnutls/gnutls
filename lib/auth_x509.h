/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT x509pki_auth_struct;

typedef struct {
	gnutls_datum * cert_list;
	int cert_list_size;
	gnutls_datum pkey; /* private key */
} X509PKI_SERVER_CREDENTIALS;

typedef struct {
	int dh_bits;
} X509PKI_AUTH_INFO;
