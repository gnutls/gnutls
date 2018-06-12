#ifndef EXT_PRE_SHARED_KEY_H
#define EXT_PRE_SHARED_KEY_H

#include "auth/psk.h"
#include <hello_ext.h>
#include "tls13/session_ticket.h"

#define PRE_SHARED_KEY_TLS_ID 41

extern const hello_ext_entry_st ext_pre_shared_key;

inline static
unsigned _gnutls_have_psk_credentials(const gnutls_psk_client_credentials_t cred, gnutls_session_t session)
{
	if ((cred->get_function || cred->username.data) && session->internals.priorities->have_psk)
		return 1;
	else
		return 0;
}

#endif
