ssize_t _gnutls_send_int( gnutls_session session, content_type_t type, 
	HandshakeType htype, const void* data, size_t sizeofdata);
ssize_t _gnutls_recv_int( gnutls_session session, content_type_t type, 
	HandshakeType, opaque* data, size_t sizeofdata);
ssize_t _gnutls_send_change_cipher_spec( gnutls_session session, int again);
void gnutls_transport_set_lowat(gnutls_session session, int num);
