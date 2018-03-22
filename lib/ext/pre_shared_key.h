#ifndef EXT_PRE_SHARED_KEY_H
#define EXT_PRE_SHARED_KEY_H

#include "auth/psk.h"
#include <hello_ext.h>

extern const hello_ext_entry_st ext_pre_shared_key;

inline static
unsigned _gnutls_have_psk_credentials(const gnutls_psk_client_credentials_t cred)
{
	if (cred->get_function || cred->username.data)
		return 1;
	else
		return 0;
}

#endif
