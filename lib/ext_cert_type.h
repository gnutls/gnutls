/* Maps record size to numbers according to the
 * extensions draft.
 */
int _gnutls_cert_type_recv_params(gnutls_session session,
				  const opaque * data, size_t data_size);
int _gnutls_cert_type_send_params(gnutls_session session, opaque * data,
				  size_t);
