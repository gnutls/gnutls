int gnutls_clear_creds( GNUTLS_STATE state);
int gnutls_set_kx_cred( GNUTLS_STATE state, int kx, AUTH_CRED* cred);
AUTH_CRED *gnutls_get_kx_cred( GNUTLS_STATE state, int kx);

