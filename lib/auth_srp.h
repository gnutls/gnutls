#include <gnutls_auth.h>

typedef struct {
	char* username;
	char* password;
} SRP_CLIENT_CREDENTIALS_INT;

#define GNUTLS_SRP_CLIENT_CREDENTIALS SRP_CLIENT_CREDENTIALS_INT*

typedef struct {
	char** password_file;
	char** password_conf_file;
	int password_files;
} SRP_SERVER_CREDENTIALS_INT;

#define GNUTLS_SRP_SERVER_CREDENTIALS SRP_SERVER_CREDENTIALS_INT*

/* these structures should not use allocated data */
typedef struct SRP_SERVER_AUTH_INFO_INT {
	char username[MAX_SRP_USERNAME];
} *SRP_SERVER_AUTH_INFO;

int proc_srp_server_hello(GNUTLS_STATE state, const opaque * data, int data_size);
int gen_srp_server_hello(GNUTLS_STATE state, opaque ** data);

typedef struct  SRP_SERVER_AUTH_INFO_INT  SRP_SERVER_AUTH_INFO_INT;
