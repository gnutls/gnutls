int gnutls_set_cache_expiration( GNUTLS_STATE state, int seconds);
int gnutls_set_db_name( GNUTLS_STATE state, char* filename);
int _gnutls_server_register_current_session( GNUTLS_STATE state);
int _gnutls_server_restore_session( GNUTLS_STATE state, uint8* session_id, int session_id_size);
int gnutls_clean_db( GNUTLS_STATE state);
int _gnutls_db_remove_session( GNUTLS_STATE state, uint8* session_id, int session_id_size);
