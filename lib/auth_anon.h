/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT anon_auth_struct;

typedef struct {
	int bits;
} DH_ANON_SERVER_CREDENTIALS;

typedef struct {
	int bits;
} DH_ANON_AUTH_INFO;
