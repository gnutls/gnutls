/* Maps record size to numbers according to the
 * extensions draft.
 */
int _gnutls_num2cert_type( int num);
int _gnutls_cert_type2num( int record_size);
int _gnutls_cert_type_recv_params( GNUTLS_STATE state, const opaque* data, int data_size);
int _gnutls_cert_type_send_params( GNUTLS_STATE state, opaque** data);
