/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT anon_auth_struct;

typedef struct {
	int dh_bits;
} ANON_SERVER_CREDENTIALS_INT;

#define ANON_SERVER_CREDENTIALS ANON_SERVER_CREDENTIALS_INT*

typedef struct {
	int dh_bits;
} ANON_CLIENT_AUTH_INFO;

typedef ANON_CLIENT_AUTH_INFO ANON_SERVER_AUTH_INFO;
