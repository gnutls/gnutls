/* this is not to be included by gnutls_anon.c */
#include <gnutls_auth.h>
#include <auth_dh_common.h>

typedef struct {
    gnutls_dh_params_t dh_params;
    /* this callback is used to retrieve the DH or RSA
     * parameters.
     */
    gnutls_params_function *params_func;
} anon_server_credentials_st;
#define gnutls_anon_server_credentials_t anon_server_credentials_st*

#define gnutls_anon_client_credentials_t void*

typedef struct anon_client_auth_info_st {
    dh_info_st dh;
} *anon_client_auth_info_t;

typedef anon_client_auth_info_t anon_server_auth_info_t;
typedef anon_client_auth_info_t anon_auth_info_t;

typedef struct anon_client_auth_info_st anon_client_auth_info_st;
typedef anon_client_auth_info_st anon_server_auth_info_st;

gnutls_dh_params_t _gnutls_anon_get_dh_params(const
					      gnutls_anon_server_credentials_t
					      sc,
					      gnutls_session_t session);
