int gnutls_clear_creds( GNUTLS_STATE state);
int gnutls_set_cred( GNUTLS_STATE state, CredType type, void* cred);
const void *_gnutls_get_cred( GNUTLS_KEY key, CredType kx, int* err);
const void *_gnutls_get_kx_cred( GNUTLS_KEY key, KXAlgorithm algo, int *err);
int _gnutls_generate_key(GNUTLS_KEY key);
CredType gnutls_get_auth_info_type( GNUTLS_STATE);
