int _gnutls_session_pack(gnutls_session_t session,
			 gnutls_datum_t * packed_session);
int _gnutls_session_unpack(gnutls_session_t session,
			   const gnutls_datum_t * packed_session);
uint _gnutls_session_size(gnutls_session_t session);
