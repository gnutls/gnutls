ssize_t _gnutls_send_int(gnutls_session_t session, content_type_t type,
			 handshake_t htype, const void *data,
			 size_t sizeofdata);
ssize_t _gnutls_recv_int(gnutls_session_t session, content_type_t type,
			 handshake_t, opaque * data, size_t sizeofdata);
ssize_t _gnutls_send_change_cipher_spec(gnutls_session_t session,
					int again);
void gnutls_transport_set_lowat(gnutls_session_t session, int num);
