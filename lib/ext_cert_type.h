/* Maps record size to numbers according to the
 * extensions draft.
 */
int _gnutls_cert_type_recv_params(gnutls_session_t session,
				  const opaque * data, size_t data_size);
int _gnutls_cert_type_send_params(gnutls_session_t session, opaque * data,
				  size_t);
