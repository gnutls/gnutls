/* Maps record size to numbers according to the
 * extensions draft.
 */
int _gnutls_mre_num2record(int num);
int _gnutls_mre_record2num(uint16 record_size);
int _gnutls_max_record_recv_params(gnutls_session session,
				   const opaque * data, size_t data_size);
int _gnutls_max_record_send_params(gnutls_session session, opaque * data,
				   size_t);
