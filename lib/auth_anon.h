/* this is not to be included by gnutls_anon.c */
#include <gnutls_auth.h>
#include <auth_dh_common.h>

typedef struct {
	gnutls_dh_params dh_params;
	/* this callback is used to retrieve the DH or RSA
	 * parameters.
	 */
	gnutls_params_function * params_func;
} ANON_SERVER_CREDENTIALS_INT;
#define gnutls_anon_server_credentials ANON_SERVER_CREDENTIALS_INT*

#define gnutls_anon_client_credentials void*

typedef struct ANON_CLIENT_AUTH_INFO_INT {
	dh_info_st dh;
} *ANON_CLIENT_AUTH_INFO;

typedef ANON_CLIENT_AUTH_INFO ANON_SERVER_AUTH_INFO;

typedef struct ANON_CLIENT_AUTH_INFO_INT ANON_CLIENT_AUTH_INFO_INT;
typedef ANON_CLIENT_AUTH_INFO_INT ANON_SERVER_AUTH_INFO_INT;

gnutls_dh_params _gnutls_anon_get_dh_params(const gnutls_anon_server_credentials sc,
	gnutls_session session);
