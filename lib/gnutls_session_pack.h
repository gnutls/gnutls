int _gnutls_session_pack( GNUTLS_STATE state, gnutls_datum* packed_session);
int _gnutls_session_unpack( GNUTLS_STATE state, const gnutls_datum* packed_session);
int _gnutls_session_size(GNUTLS_STATE state);
