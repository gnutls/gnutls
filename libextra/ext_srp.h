#ifdef ENABLE_SRP

int _gnutls_srp_recv_params( gnutls_session state, const opaque* data, int data_size);
int _gnutls_srp_send_params( gnutls_session state, opaque* data, int);

#endif
