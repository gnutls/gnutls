/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT srp_auth_struct;

typedef struct {
	char* username;
	char* password;
} SRP_CLIENT_CREDENTIALS;

typedef struct {
	char* password_file;
	char* password_conf_file;
} SRP_SERVER_CREDENTIALS;

/* these structures should not use allocated data */
typedef struct {
	char username[256];
} SRP_AUTH_INFO;

int gen_srp_server_hello(GNUTLS_KEY, opaque **);
int proc_srp_server_hello(GNUTLS_KEY, const opaque *, int);
