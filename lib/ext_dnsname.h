int _gnutls_name_ind_recv_params( GNUTLS_STATE state, const opaque* data, int data_size);
int _gnutls_name_ind_send_params( GNUTLS_STATE state, opaque** data);

const void* gnutls_ext_get_name_ind( GNUTLS_STATE state, GNUTLS_NAME_IND ind);
int gnutls_ext_set_name_ind( GNUTLS_STATE state, GNUTLS_NAME_IND ind, const void* name);


