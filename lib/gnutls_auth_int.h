void gnutls_credentials_clear(gnutls_session_t session);
int gnutls_credentials_set(gnutls_session_t session,
			   gnutls_credentials_type_t type, void *cred);
const void *_gnutls_get_cred(gnutls_key_st key, gnutls_credentials_type_t kx,
			     int *err);
const void *_gnutls_get_kx_cred(gnutls_session_t session,
				gnutls_kx_algorithm_t algo, int *err);
int _gnutls_generate_session_key(gnutls_key_st key);
gnutls_credentials_type_t gnutls_auth_get_type(gnutls_session_t session);
void *_gnutls_get_auth_info(gnutls_session_t session);
int _gnutls_auth_info_set(gnutls_session_t session,
			  gnutls_credentials_type_t type, int size,
			  int allow_change);
