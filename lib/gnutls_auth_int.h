int gnutls_clear_creds( GNUTLS_STATE state);
int gnutls_cred_set( GNUTLS_STATE state, CredType type, void* cred);
const void *_gnutls_get_cred( GNUTLS_KEY key, CredType kx, int* err);
const void *_gnutls_get_kx_cred( GNUTLS_KEY key, KXAlgorithm algo, int *err);
int _gnutls_generate_key(GNUTLS_KEY key);
CredType gnutls_auth_get_type( GNUTLS_STATE state);
void* _gnutls_get_auth_info( GNUTLS_STATE state);
