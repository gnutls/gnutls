int gnutls_clear_creds( GNUTLS_STATE state);
int gnutls_set_kx_cred( GNUTLS_STATE state, int kx, void* cred);
void *_gnutls_get_kx_cred( GNUTLS_KEY key, int kx, int* err);

