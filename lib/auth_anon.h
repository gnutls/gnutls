/* this is not to be included by gnutls_anon.c */
#include <gnutls_auth.h>

typedef struct {
	gnutls_dh_params dh_params;
} ANON_SERVER_CREDENTIALS_INT;
#define GNUTLS_ANON_SERVER_CREDENTIALS ANON_SERVER_CREDENTIALS_INT*

#define GNUTLS_ANON_CLIENT_CREDENTIALS void*

typedef struct ANON_CLIENT_AUTH_INFO_INT {
	int dh_prime_bits;
	int dh_secret_bits;
	int dh_peer_public_bits;
} *ANON_CLIENT_AUTH_INFO;

typedef ANON_CLIENT_AUTH_INFO ANON_SERVER_AUTH_INFO;

typedef struct ANON_CLIENT_AUTH_INFO_INT ANON_CLIENT_AUTH_INFO_INT;
typedef ANON_CLIENT_AUTH_INFO_INT ANON_SERVER_AUTH_INFO_INT;
