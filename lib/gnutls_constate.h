int _gnutls_connection_state_init(gnutls_session_t session);
int _gnutls_read_connection_state_init(gnutls_session_t session);
int _gnutls_write_connection_state_init(gnutls_session_t session);
int _gnutls_set_write_cipher(gnutls_session_t session,
			     gnutls_cipher_algorithm_t algo);
int _gnutls_set_write_mac(gnutls_session_t session,
			  gnutls_mac_algorithm_t algo);
int _gnutls_set_read_cipher(gnutls_session_t session,
			    gnutls_cipher_algorithm_t algo);
int _gnutls_set_read_mac(gnutls_session_t session,
			 gnutls_mac_algorithm_t algo);
int _gnutls_set_read_compression(gnutls_session_t session,
				 gnutls_compression_method_t algo);
int _gnutls_set_write_compression(gnutls_session_t session,
				  gnutls_compression_method_t algo);
int _gnutls_set_kx(gnutls_session_t session, gnutls_kx_algorithm_t algo);
