int _gnutls_connection_state_init(gnutls_session session);
int _gnutls_read_connection_state_init(gnutls_session session);
int _gnutls_write_connection_state_init(gnutls_session session);
int _gnutls_set_write_cipher(gnutls_session session,
			     gnutls_cipher_algorithm algo);
int _gnutls_set_write_mac(gnutls_session session,
			  gnutls_mac_algorithm algo);
int _gnutls_set_read_cipher(gnutls_session session,
			    gnutls_cipher_algorithm algo);
int _gnutls_set_read_mac(gnutls_session session,
			 gnutls_mac_algorithm algo);
int _gnutls_set_read_compression(gnutls_session session,
				 gnutls_compression_method algo);
int _gnutls_set_write_compression(gnutls_session session,
				  gnutls_compression_method algo);
int _gnutls_set_kx(gnutls_session session, gnutls_kx_algorithm algo);
