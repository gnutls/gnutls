int _gnutls_gen_dh_common_client_kx(gnutls_session, opaque **);
int _gnutls_proc_dh_common_client_kx(gnutls_session session, opaque * data,
				  size_t _data_size, GNUTLS_MPI p, GNUTLS_MPI g);
int _gnutls_dh_common_print_server_kx( gnutls_session, GNUTLS_MPI g, 
	GNUTLS_MPI p, opaque** data);
int _gnutls_proc_dh_common_server_kx( gnutls_session session, opaque* data, 
	size_t _data_size);
