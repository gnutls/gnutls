#ifdef ENABLE_SRP

int _gnutls_srp_recv_params( gnutls_session state, const opaque* data, size_t data_size);
int _gnutls_srp_send_params( gnutls_session state, opaque* data, size_t);

#endif
