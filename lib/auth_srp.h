/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT srp_auth_struct;

typedef struct {
	char* username;
	char* password;
} SRP_CLIENT_CREDENTIALS;

typedef struct {
	char* password_file;
} SRP_SERVER_CREDENTIALS;
