#ifndef GNUTLS_LIB_ACCELERATED_KTLS_H
#define GNUTLS_LIB_ACCELERATED_KTLS_H

#include "gnutls_int.h"

enum{
	KTLS_RECV = 1,
	KTLS_SEND,
	KTLS_DUPLEX,
};

int _gnutls_ktls_enable(gnutls_session_t session);
int _gnutls_ktls_set_keys(gnutls_session_t session);
int _gnutls_ktls_send_control_msg(gnutls_session_t session, unsigned char record_type,
		const void *data, size_t data_size);
#define _gnutls_ktls_send(x, y, z) _gnutls_ktls_send_control_msg(x, GNUTLS_APPLICATION_DATA, y, z);
int _gnutls_ktls_recv_control_msg(gnutls_session_t session, unsigned char *record_type,
		void *data, size_t data_size);
int _gnutls_ktls_recv_int(gnutls_session_t session, content_type_t type, void *data, size_t data_size);
#define _gnutls_ktls_recv(x, y, z) _gnutls_ktls_recv_int(x, GNUTLS_APPLICATION_DATA, y, z)

#endif /* GNUTLS_LIB_ACCELERATED_KTLS_H */
