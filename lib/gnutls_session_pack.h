int _gnutls_session_pack(gnutls_session session,
			 gnutls_datum * packed_session);
int _gnutls_session_unpack(gnutls_session session,
			   const gnutls_datum * packed_session);
uint _gnutls_session_size(gnutls_session session);
