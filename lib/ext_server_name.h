int _gnutls_server_name_recv_params(gnutls_session_t session,
				    const opaque * data, size_t data_size);
int _gnutls_server_name_send_params(gnutls_session_t session, opaque * data,
				    size_t);

int gnutls_get_server_name(gnutls_session_t session, void *data,
			   int *data_length, int *type, int indx);

int gnutls_set_server_name(gnutls_session_t session,
			   gnutls_server_name_type_t type,
			   const void *name, int name_length);
