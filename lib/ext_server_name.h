int _gnutls_server_name_recv_params( gnutls_session session, const opaque* data, size_t data_size);
int _gnutls_server_name_send_params( gnutls_session session, opaque* data, size_t);

int gnutls_get_server_name(gnutls_session session, void* data, int* data_length,
				       int *type, int index);

int gnutls_set_server_name(gnutls_session session,
			       gnutls_server_name_type type,
			       const void *name, int name_length);

