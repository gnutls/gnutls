/* this is not to be included by gnutls_anon.c */
extern MOD_AUTH_STRUCT srp_auth_struct;

typedef struct {
	char* username;
	char* password;
} SRP_CLIENT_CREDENTIALS_INT;

#define SRP_CLIENT_CREDENTIALS SRP_CLIENT_CREDENTIALS_INT*

typedef struct {
	char* password_file;
	char* password_conf_file;
} SRP_SERVER_CREDENTIALS_INT;

#define SRP_SERVER_CREDENTIALS SRP_SERVER_CREDENTIALS_INT*

/* these structures should not use allocated data */
typedef struct {
	char username[256];
} SRP_SERVER_AUTH_INFO;

int gen_srp_server_hello(GNUTLS_KEY, opaque **);
int proc_srp_server_hello(GNUTLS_KEY, const opaque *, int);
