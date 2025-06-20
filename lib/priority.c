/*
 * Copyright (C) 2004-2015 Free Software Foundation, Inc.
 * Copyright (C) 2015-2019 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "algorithms.h"
#include "errors.h"
#include "num.h"
#include <gnutls/x509.h>
#include <c-ctype.h>
#include "hello_ext.h"
#include <c-strcase.h>
#include "fips.h"
#include <errno.h>
#include "ext/compress_certificate.h"
#include "ext/srp.h"
#include <gnutls/gnutls.h>
#include "profiles.h"
#include "c-strcase.h"
#include "inih/ini.h"
#include "locks.h"
#include "profiles.h"
#include "name_val_array.h"

#define MAX_ELEMENTS GNUTLS_MAX_ALGORITHM_NUM

#define ENABLE_PROFILE(c, profile)                                \
	do {                                                      \
		c->additional_verify_flags &= 0x00ffffff;         \
		c->additional_verify_flags |=                     \
			GNUTLS_PROFILE_TO_VFLAGS(profile);        \
		c->level = _gnutls_profile_to_sec_level(profile); \
	} while (0)

/* This function is used by the test suite */
char *_gnutls_resolve_priorities(const char *priorities);

/* This variable points to either a constant value (DEFAULT_PRIORITY_STRING or
 * externally assigned) or heap-allocated
 * system_wide_config.default_priority_string. We can't move this to the
 * system_wide_config struct, because this variable is part of (private) ABI
 * exported for testing.
 */
const char *_gnutls_default_priority_string = DEFAULT_PRIORITY_STRING;

static void prio_remove(priority_st *priority_list, unsigned int algo);
static void prio_add(priority_st *priority_list, unsigned int algo);
static void break_list(char *etag, char *broken_etag[MAX_ELEMENTS], int *size);

typedef void(bulk_rmadd_func)(priority_st *priority_list, const int *);

inline static void _set_priority(priority_st *st, const int *list)
{
	int num = 0, i;

	while (list[num] != 0)
		num++;
	if (num > MAX_ALGOS)
		num = MAX_ALGOS;
	st->num_priorities = num;

	for (i = 0; i < num; i++) {
		st->priorities[i] = list[i];
	}

	return;
}

inline static void _add_priority(priority_st *st, const int *list)
{
	int num, i, j, init;

	init = i = st->num_priorities;

	for (num = 0; list[num] != 0; ++num) {
		if (i + 1 > MAX_ALGOS) {
			return;
		}

		for (j = 0; j < init; j++) {
			if (st->priorities[j] == (unsigned)list[num]) {
				break;
			}
		}

		if (j == init) {
			st->priorities[i++] = list[num];
			st->num_priorities++;
		}
	}

	return;
}

static void _clear_priorities(priority_st *st, const int *list)
{
	memset(st, 0, sizeof(*st));
}

static void _clear_given_priorities(priority_st *st, const int *list)
{
	unsigned i;

	for (i = 0; list[i] != 0; i++) {
		prio_remove(st, list[i]);
	}
}

static const int _supported_groups_dh[] = {
	GNUTLS_GROUP_FFDHE2048, GNUTLS_GROUP_FFDHE3072, GNUTLS_GROUP_FFDHE4096,
	GNUTLS_GROUP_FFDHE6144, GNUTLS_GROUP_FFDHE8192, 0
};

static const int _supported_groups_ecdh[] = { GNUTLS_GROUP_SECP256R1,
					      GNUTLS_GROUP_SECP384R1,
					      GNUTLS_GROUP_SECP521R1,
					      GNUTLS_GROUP_X25519, /* RFC 8422 */
					      GNUTLS_GROUP_X448, /* RFC 8422 */
					      0 };

static const int _supported_groups_gost[] = {
#ifdef ENABLE_GOST
	GNUTLS_GROUP_GC256A,
	GNUTLS_GROUP_GC256B,
	GNUTLS_GROUP_GC256C,
	GNUTLS_GROUP_GC256D,
	GNUTLS_GROUP_GC512A,
	GNUTLS_GROUP_GC512B,
	GNUTLS_GROUP_GC512C,
#endif
	0
};

static const int _supported_groups_normal[] = {
	GNUTLS_GROUP_SECP256R1, GNUTLS_GROUP_SECP384R1, GNUTLS_GROUP_SECP521R1,
	GNUTLS_GROUP_X25519, /* RFC 8422 */
	GNUTLS_GROUP_X448, /* RFC 8422 */

	/* These should stay last as our default behavior
	 * is to send key shares for two top types (GNUTLS_KEY_SHARE_TOP2)
	 * and we wouldn't want to have these sent by all clients
	 * by default as they are quite expensive CPU-wise. */
	GNUTLS_GROUP_FFDHE2048, GNUTLS_GROUP_FFDHE3072, GNUTLS_GROUP_FFDHE4096,
	GNUTLS_GROUP_FFDHE6144, GNUTLS_GROUP_FFDHE8192, 0
};

static const int *supported_groups_normal = _supported_groups_normal;

static const int _supported_groups_secure128[] = {
	GNUTLS_GROUP_SECP256R1, GNUTLS_GROUP_SECP384R1, GNUTLS_GROUP_SECP521R1,
	GNUTLS_GROUP_X25519, /* RFC 8422 */
	GNUTLS_GROUP_X448, /* RFC 8422 */
	GNUTLS_GROUP_FFDHE2048, GNUTLS_GROUP_FFDHE3072, GNUTLS_GROUP_FFDHE4096,
	GNUTLS_GROUP_FFDHE6144, GNUTLS_GROUP_FFDHE8192, 0
};

static const int *supported_groups_secure128 = _supported_groups_secure128;

static const int _supported_groups_suiteb128[] = { GNUTLS_GROUP_SECP256R1,
						   GNUTLS_GROUP_SECP384R1, 0 };

static const int *supported_groups_suiteb128 = _supported_groups_suiteb128;

static const int _supported_groups_suiteb192[] = { GNUTLS_GROUP_SECP384R1, 0 };

static const int *supported_groups_suiteb192 = _supported_groups_suiteb192;

static const int _supported_groups_secure192[] = { GNUTLS_GROUP_SECP384R1,
						   GNUTLS_GROUP_SECP521R1,
						   GNUTLS_GROUP_FFDHE8192, 0 };

static const int *supported_groups_secure192 = _supported_groups_secure192;

static const int protocol_priority[] = { GNUTLS_TLS1_3,
					 GNUTLS_TLS1_2,
					 GNUTLS_TLS1_1,
					 GNUTLS_TLS1_0,
					 GNUTLS_DTLS1_2,
					 GNUTLS_DTLS1_0,
					 0 };

/* contains all the supported TLS protocols, intended to be used for eliminating them
 */
static const int stream_protocol_priority[] = { GNUTLS_TLS1_3, GNUTLS_TLS1_2,
						GNUTLS_TLS1_1, GNUTLS_TLS1_0,
						0 };

/* contains all the supported DTLS protocols, intended to be used for eliminating them
 */
static const int dgram_protocol_priority[] = { GNUTLS_DTLS1_2, GNUTLS_DTLS1_0,
					       GNUTLS_DTLS0_9, 0 };

static const int dtls_protocol_priority[] = { GNUTLS_DTLS1_2, GNUTLS_DTLS1_0,
					      0 };

static const int _protocol_priority_suiteb[] = { GNUTLS_TLS1_2, 0 };

static const int *protocol_priority_suiteb = _protocol_priority_suiteb;

static const int _kx_priority_performance[] = { GNUTLS_KX_RSA,
#ifdef ENABLE_ECDHE
						GNUTLS_KX_ECDHE_ECDSA,
						GNUTLS_KX_ECDHE_RSA,
#endif
#ifdef ENABLE_DHE
						GNUTLS_KX_DHE_RSA,
#endif
						0 };

static const int *kx_priority_performance = _kx_priority_performance;

static const int _kx_priority_pfs[] = {
#ifdef ENABLE_ECDHE
	GNUTLS_KX_ECDHE_ECDSA, GNUTLS_KX_ECDHE_RSA,
#endif
#ifdef ENABLE_DHE
	GNUTLS_KX_DHE_RSA,
#endif
	0
};

static const int *kx_priority_pfs = _kx_priority_pfs;

static const int _kx_priority_suiteb[] = { GNUTLS_KX_ECDHE_ECDSA, 0 };

static const int *kx_priority_suiteb = _kx_priority_suiteb;

static const int _kx_priority_secure[] = {
/* The ciphersuites that offer forward secrecy take
	 * precedence
	 */
#ifdef ENABLE_ECDHE
	GNUTLS_KX_ECDHE_ECDSA, GNUTLS_KX_ECDHE_RSA,
#endif
	GNUTLS_KX_RSA,
/* KX-RSA is now ahead of DHE-RSA and DHE-DSS due to the compatibility
	 * issues the DHE ciphersuites have. That is, one cannot enforce a specific
	 * security level without dropping the connection.
	 */
#ifdef ENABLE_DHE
	GNUTLS_KX_DHE_RSA,
#endif
	/* GNUTLS_KX_ANON_DH: Man-in-the-middle prone, don't add!
	 */
	0
};

static const int *kx_priority_secure = _kx_priority_secure;

static const int _kx_priority_gost[] = {
#ifdef ENABLE_GOST
	GNUTLS_KX_VKO_GOST_12,
#endif
	0,
};

static const int *kx_priority_gost = _kx_priority_gost;

static const int _cipher_priority_performance_default[] = {
	GNUTLS_CIPHER_AES_128_GCM,	 GNUTLS_CIPHER_AES_256_GCM,
	GNUTLS_CIPHER_CHACHA20_POLY1305, GNUTLS_CIPHER_AES_128_CCM,
	GNUTLS_CIPHER_AES_256_CCM,	 GNUTLS_CIPHER_AES_128_CBC,
	GNUTLS_CIPHER_AES_256_CBC,	 0
};

static const int _cipher_priority_performance_no_aesni[] = {
	GNUTLS_CIPHER_CHACHA20_POLY1305, GNUTLS_CIPHER_AES_128_GCM,
	GNUTLS_CIPHER_AES_256_GCM,	 GNUTLS_CIPHER_AES_128_CCM,
	GNUTLS_CIPHER_AES_256_CCM,	 GNUTLS_CIPHER_AES_128_CBC,
	GNUTLS_CIPHER_AES_256_CBC,	 0
};

/* If GCM and AES acceleration is available then prefer
 * them over anything else. Overall we prioritise AEAD
 * over legacy ciphers, and 256-bit over 128 (for future
 * proof).
 */
static const int _cipher_priority_normal_default[] = {
	GNUTLS_CIPHER_AES_256_GCM, GNUTLS_CIPHER_CHACHA20_POLY1305,
	GNUTLS_CIPHER_AES_256_CCM,

	GNUTLS_CIPHER_AES_256_CBC,

	GNUTLS_CIPHER_AES_128_GCM, GNUTLS_CIPHER_AES_128_CCM,

	GNUTLS_CIPHER_AES_128_CBC, 0
};

static const int cipher_priority_performance_fips[] = {
	GNUTLS_CIPHER_AES_128_GCM,
	GNUTLS_CIPHER_AES_128_CCM,
	GNUTLS_CIPHER_AES_256_GCM,
	GNUTLS_CIPHER_AES_256_CCM,

	GNUTLS_CIPHER_AES_128_CBC,
	GNUTLS_CIPHER_AES_256_CBC,
	0
};

static const int cipher_priority_normal_fips[] = {
	GNUTLS_CIPHER_AES_256_GCM, GNUTLS_CIPHER_AES_256_CCM,
	GNUTLS_CIPHER_AES_256_CBC,

	GNUTLS_CIPHER_AES_128_GCM, GNUTLS_CIPHER_AES_128_CBC,
	GNUTLS_CIPHER_AES_128_CCM, 0
};

static const int _cipher_priority_suiteb128[] = { GNUTLS_CIPHER_AES_256_GCM,
						  GNUTLS_CIPHER_AES_128_GCM,
						  0 };

static const int *cipher_priority_suiteb128 = _cipher_priority_suiteb128;

static const int _cipher_priority_suiteb192[] = { GNUTLS_CIPHER_AES_256_GCM,
						  0 };

static const int *cipher_priority_suiteb192 = _cipher_priority_suiteb192;

static const int _cipher_priority_secure128[] = {
	GNUTLS_CIPHER_AES_256_GCM, GNUTLS_CIPHER_CHACHA20_POLY1305,
	GNUTLS_CIPHER_AES_256_CBC, GNUTLS_CIPHER_AES_256_CCM,

	GNUTLS_CIPHER_AES_128_GCM, GNUTLS_CIPHER_AES_128_CBC,
	GNUTLS_CIPHER_AES_128_CCM, 0
};

static const int *cipher_priority_secure128 = _cipher_priority_secure128;

static const int _cipher_priority_secure192[] = {
	GNUTLS_CIPHER_AES_256_GCM, GNUTLS_CIPHER_CHACHA20_POLY1305,
	GNUTLS_CIPHER_AES_256_CBC, GNUTLS_CIPHER_AES_256_CCM, 0
};

static const int *cipher_priority_secure192 = _cipher_priority_secure192;

static const int _sign_priority_default[] = {
	GNUTLS_SIGN_MLDSA44,
	GNUTLS_SIGN_MLDSA65,
	GNUTLS_SIGN_MLDSA87,

	GNUTLS_SIGN_RSA_SHA256,
	GNUTLS_SIGN_RSA_PSS_SHA256,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA256,
	GNUTLS_SIGN_ECDSA_SHA256,
	GNUTLS_SIGN_ECDSA_SECP256R1_SHA256,

	GNUTLS_SIGN_EDDSA_ED25519,

	GNUTLS_SIGN_RSA_SHA384,
	GNUTLS_SIGN_RSA_PSS_SHA384,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA384,
	GNUTLS_SIGN_ECDSA_SHA384,
	GNUTLS_SIGN_ECDSA_SECP384R1_SHA384,

	GNUTLS_SIGN_EDDSA_ED448,

	GNUTLS_SIGN_RSA_SHA512,
	GNUTLS_SIGN_RSA_PSS_SHA512,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA512,

	GNUTLS_SIGN_ECDSA_SHA512,
	GNUTLS_SIGN_ECDSA_SECP521R1_SHA512,

	GNUTLS_SIGN_RSA_SHA1,
	GNUTLS_SIGN_ECDSA_SHA1,

	0
};

static const int *sign_priority_default = _sign_priority_default;

static const int _sign_priority_suiteb128[] = {
	GNUTLS_SIGN_ECDSA_SHA256, GNUTLS_SIGN_ECDSA_SECP256R1_SHA256,
	GNUTLS_SIGN_ECDSA_SHA384, GNUTLS_SIGN_ECDSA_SECP384R1_SHA384, 0
};

static const int *sign_priority_suiteb128 = _sign_priority_suiteb128;

static const int _sign_priority_suiteb192[] = {
	GNUTLS_SIGN_ECDSA_SHA384, GNUTLS_SIGN_ECDSA_SECP384R1_SHA384, 0
};

static const int *sign_priority_suiteb192 = _sign_priority_suiteb192;

static const int _sign_priority_secure128[] = {
	GNUTLS_SIGN_RSA_SHA256,
	GNUTLS_SIGN_RSA_PSS_SHA256,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA256,
	GNUTLS_SIGN_ECDSA_SHA256,
	GNUTLS_SIGN_ECDSA_SECP256R1_SHA256,

	GNUTLS_SIGN_EDDSA_ED25519,

	GNUTLS_SIGN_RSA_SHA384,
	GNUTLS_SIGN_RSA_PSS_SHA384,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA384,
	GNUTLS_SIGN_ECDSA_SHA384,
	GNUTLS_SIGN_ECDSA_SECP384R1_SHA384,

	GNUTLS_SIGN_EDDSA_ED448,

	GNUTLS_SIGN_RSA_SHA512,
	GNUTLS_SIGN_RSA_PSS_SHA512,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA512,
	GNUTLS_SIGN_ECDSA_SHA512,
	GNUTLS_SIGN_ECDSA_SECP521R1_SHA512,

	0
};

static const int *sign_priority_secure128 = _sign_priority_secure128;

static const int _sign_priority_secure192[] = {
	GNUTLS_SIGN_RSA_SHA384,
	GNUTLS_SIGN_RSA_PSS_SHA384,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA384,
	GNUTLS_SIGN_ECDSA_SHA384,
	GNUTLS_SIGN_ECDSA_SECP384R1_SHA384,
	GNUTLS_SIGN_EDDSA_ED448,
	GNUTLS_SIGN_RSA_SHA512,
	GNUTLS_SIGN_RSA_PSS_SHA512,
	GNUTLS_SIGN_RSA_PSS_RSAE_SHA512,
	GNUTLS_SIGN_ECDSA_SHA512,
	GNUTLS_SIGN_ECDSA_SECP521R1_SHA512,

	0
};

static const int *sign_priority_secure192 = _sign_priority_secure192;

static const int _sign_priority_gost[] = {
#ifdef ENABLE_GOST
	GNUTLS_SIGN_GOST_256, GNUTLS_SIGN_GOST_512,
#endif
	0
};

static const int *sign_priority_gost = _sign_priority_gost;

static const int mac_priority_normal_default[] = { GNUTLS_MAC_SHA1,
						   GNUTLS_MAC_AEAD, 0 };

static const int mac_priority_normal_fips[] = { GNUTLS_MAC_SHA1,
						GNUTLS_MAC_AEAD, 0 };

static const int *cipher_priority_performance =
	_cipher_priority_performance_default;
static const int *cipher_priority_normal = _cipher_priority_normal_default;
static const int *mac_priority_normal = mac_priority_normal_default;

static const int _cipher_priority_gost[] = {
#ifdef ENABLE_GOST
	GNUTLS_CIPHER_GOST28147_TC26Z_CNT,
#endif
	0
};

static const int *cipher_priority_gost = _cipher_priority_gost;

static const int _mac_priority_gost[] = {
#ifdef ENABLE_GOST
	GNUTLS_MAC_GOST28147_TC26Z_IMIT,
#endif
	0
};

static const int *mac_priority_gost = _mac_priority_gost;

/* if called with replace the default priorities with the FIPS140 ones */
void _gnutls_priority_update_fips(void)
{
	cipher_priority_performance = cipher_priority_performance_fips;
	cipher_priority_normal = cipher_priority_normal_fips;
	mac_priority_normal = mac_priority_normal_fips;
}

void _gnutls_priority_update_non_aesni(void)
{
	/* if we have no AES acceleration in performance mode
	 * prefer fast stream ciphers */
	if (_gnutls_fips_mode_enabled() == 0) {
		cipher_priority_performance =
			_cipher_priority_performance_no_aesni;
	}
}

static const int _mac_priority_suiteb[] = { GNUTLS_MAC_AEAD, 0 };

static const int *mac_priority_suiteb = _mac_priority_suiteb;

static const int _mac_priority_secure128[] = { GNUTLS_MAC_SHA1, GNUTLS_MAC_AEAD,
					       0 };

static const int *mac_priority_secure128 = _mac_priority_secure128;

static const int _mac_priority_secure192[] = { GNUTLS_MAC_AEAD, 0 };

static const int *mac_priority_secure192 = _mac_priority_secure192;

static const int cert_type_priority_default[] = { GNUTLS_CRT_X509, 0 };

static const int cert_type_priority_all[] = { GNUTLS_CRT_X509, GNUTLS_CRT_RAWPK,
					      0 };

typedef void(rmadd_func)(priority_st *priority_list, unsigned int alg);

static void prio_remove(priority_st *priority_list, unsigned int algo)
{
	unsigned int i;

	for (i = 0; i < priority_list->num_priorities; i++) {
		if (priority_list->priorities[i] == algo) {
			priority_list->num_priorities--;
			if ((priority_list->num_priorities - i) > 0)
				memmove(&priority_list->priorities[i],
					&priority_list->priorities[i + 1],
					(priority_list->num_priorities -
					 i) * sizeof(priority_list
							     ->priorities[0]));
			priority_list
				->priorities[priority_list->num_priorities] = 0;
			break;
		}
	}

	return;
}

static void prio_add(priority_st *priority_list, unsigned int algo)
{
	unsigned int i, l = priority_list->num_priorities;

	if (l >= MAX_ALGOS)
		return; /* can't add it anyway */

	for (i = 0; i < l; ++i) {
		if (algo == priority_list->priorities[i])
			return; /* if it exists */
	}

	priority_list->priorities[l] = algo;
	priority_list->num_priorities++;

	return;
}

/**
 * gnutls_priority_set:
 * @session: is a #gnutls_session_t type.
 * @priority: is a #gnutls_priority_t type.
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * and macs. Note that this function is expected to be called once
 * per session; when called multiple times (e.g., before a re-handshake,
 * the caller should make sure that any new settings are not incompatible
 * with the original session).
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code on error.
 **/
int gnutls_priority_set(gnutls_session_t session, gnutls_priority_t priority)
{
	int ret;

	if (priority == NULL || priority->protocol.num_priorities == 0 ||
	    priority->cs.size == 0)
		return gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);

	/* set the current version to the first in the chain, if this is
	 * the call before the initial handshake. During a re-handshake
	 * we do not set the version to avoid overriding the currently
	 * negotiated version. */
	if (!session->internals.handshake_in_progress &&
	    !session->internals.initial_negotiation_completed) {
		ret = _gnutls_set_current_version(
			session, priority->protocol.priorities[0]);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* At this point the provided priorities passed the sanity tests */

	if (session->internals.priorities)
		gnutls_priority_deinit(session->internals.priorities);

	gnutls_atomic_increment(&priority->usage_cnt);
	session->internals.priorities = priority;

	if (priority->no_tickets != 0) {
		session->internals.flags |= GNUTLS_NO_TICKETS;
	}

	if (priority->no_tickets_tls12 != 0) {
		/* when PFS is explicitly requested, disable session tickets for TLS 1.2 */
		session->internals.flags |= GNUTLS_NO_TICKETS_TLS12;
	}

	if (priority->no_status_request)
		session->internals.flags |= GNUTLS_NO_STATUS_REQUEST;

	ADD_PROFILE_VFLAGS(session, priority->additional_verify_flags);

	/* mirror variables */
#undef COPY_TO_INTERNALS
#define COPY_TO_INTERNALS(xx) session->internals.xx = priority->_##xx
	COPY_TO_INTERNALS(allow_large_records);
	COPY_TO_INTERNALS(allow_small_records);
	COPY_TO_INTERNALS(no_etm);
	COPY_TO_INTERNALS(no_ext_master_secret);
	COPY_TO_INTERNALS(allow_key_usage_violation);
	COPY_TO_INTERNALS(dumbfw);
	COPY_TO_INTERNALS(dh_prime_bits);

	return 0;
}

#define LEVEL_NONE "NONE"
#define LEVEL_NORMAL "NORMAL"
#define LEVEL_PFS "PFS"
#define LEVEL_PERFORMANCE "PERFORMANCE"
#define LEVEL_SECURE128 "SECURE128"
#define LEVEL_SECURE192 "SECURE192"
#define LEVEL_SECURE256 "SECURE256"
#define LEVEL_SUITEB128 "SUITEB128"
#define LEVEL_SUITEB192 "SUITEB192"
#define LEVEL_LEGACY "LEGACY"
#define LEVEL_SYSTEM "SYSTEM"

struct priority_groups_st {
	const char *name;
	const char *alias;
	const int **proto_list;
	const int **cipher_list;
	const int **mac_list;
	const int **kx_list;
	const int **sign_list;
	const int **group_list;
	unsigned profile;
	int sec_param;
	bool no_tickets;
	bool no_tickets_tls12;
};

static const struct priority_groups_st pgroups[] = {
	{ .name = LEVEL_NORMAL,
	  .cipher_list = &cipher_priority_normal,
	  .mac_list = &mac_priority_normal,
	  .kx_list = &kx_priority_secure,
	  .sign_list = &sign_priority_default,
	  .group_list = &supported_groups_normal,
	  .profile = GNUTLS_PROFILE_LOW,
	  .sec_param = GNUTLS_SEC_PARAM_WEAK },
	{ .name = LEVEL_PFS,
	  .cipher_list = &cipher_priority_normal,
	  .mac_list = &mac_priority_secure128,
	  .kx_list = &kx_priority_pfs,
	  .sign_list = &sign_priority_default,
	  .group_list = &supported_groups_normal,
	  .profile = GNUTLS_PROFILE_LOW,
	  .sec_param = GNUTLS_SEC_PARAM_WEAK,
	  .no_tickets_tls12 = 1 },
	{ .name = LEVEL_SECURE128,
	  .alias = "SECURE",
	  .cipher_list = &cipher_priority_secure128,
	  .mac_list = &mac_priority_secure128,
	  .kx_list = &kx_priority_secure,
	  .sign_list = &sign_priority_secure128,
	  .group_list = &supported_groups_secure128,
	  /* The profile should have been HIGH but if we don't allow
	  * SHA-1 (80-bits) as signature algorithm we are not able
	  * to connect anywhere with this level */
	  .profile = GNUTLS_PROFILE_LOW,
	  .sec_param = GNUTLS_SEC_PARAM_LOW },
	{ .name = LEVEL_SECURE192,
	  .alias = LEVEL_SECURE256,
	  .cipher_list = &cipher_priority_secure192,
	  .mac_list = &mac_priority_secure192,
	  .kx_list = &kx_priority_secure,
	  .sign_list = &sign_priority_secure192,
	  .group_list = &supported_groups_secure192,
	  .profile = GNUTLS_PROFILE_HIGH,
	  .sec_param = GNUTLS_SEC_PARAM_HIGH },
	{ .name = LEVEL_SUITEB128,
	  .proto_list = &protocol_priority_suiteb,
	  .cipher_list = &cipher_priority_suiteb128,
	  .mac_list = &mac_priority_suiteb,
	  .kx_list = &kx_priority_suiteb,
	  .sign_list = &sign_priority_suiteb128,
	  .group_list = &supported_groups_suiteb128,
	  .profile = GNUTLS_PROFILE_SUITEB128,
	  .sec_param = GNUTLS_SEC_PARAM_HIGH },
	{ .name = LEVEL_SUITEB192,
	  .proto_list = &protocol_priority_suiteb,
	  .cipher_list = &cipher_priority_suiteb192,
	  .mac_list = &mac_priority_suiteb,
	  .kx_list = &kx_priority_suiteb,
	  .sign_list = &sign_priority_suiteb192,
	  .group_list = &supported_groups_suiteb192,
	  .profile = GNUTLS_PROFILE_SUITEB192,
	  .sec_param = GNUTLS_SEC_PARAM_ULTRA },
	{ .name = LEVEL_LEGACY,
	  .cipher_list = &cipher_priority_normal,
	  .mac_list = &mac_priority_normal,
	  .kx_list = &kx_priority_secure,
	  .sign_list = &sign_priority_default,
	  .group_list = &supported_groups_normal,
	  .sec_param = GNUTLS_SEC_PARAM_VERY_WEAK },
	{ .name = LEVEL_PERFORMANCE,
	  .cipher_list = &cipher_priority_performance,
	  .mac_list = &mac_priority_normal,
	  .kx_list = &kx_priority_performance,
	  .sign_list = &sign_priority_default,
	  .group_list = &supported_groups_normal,
	  .profile = GNUTLS_PROFILE_LOW,
	  .sec_param = GNUTLS_SEC_PARAM_WEAK },
	{
		.name = NULL,
	}
};

#define SET_PROFILE(to_set)                                \
	profile = GNUTLS_VFLAGS_TO_PROFILE(                \
		priority_cache->additional_verify_flags);  \
	if (profile == 0 || profile > to_set) {            \
		priority_cache->additional_verify_flags &= \
			~GNUTLS_VFLAGS_PROFILE_MASK;       \
		priority_cache->additional_verify_flags |= \
			GNUTLS_PROFILE_TO_VFLAGS(to_set);  \
	}

#define SET_LEVEL(to_set)                                       \
	if (priority_cache->level == 0 ||                       \
	    (unsigned)priority_cache->level > (unsigned)to_set) \
	priority_cache->level = to_set

static int check_level(const char *level, gnutls_priority_t priority_cache,
		       int add)
{
	bulk_rmadd_func *func;
	unsigned profile = 0;
	unsigned i;
	int j;
	const cipher_entry_st *centry;

	if (add)
		func = _add_priority;
	else
		func = _set_priority;

	for (i = 0;; i++) {
		if (pgroups[i].name == NULL)
			return 0;

		if (c_strcasecmp(level, pgroups[i].name) == 0 ||
		    (pgroups[i].alias != NULL &&
		     c_strcasecmp(level, pgroups[i].alias) == 0)) {
			if (pgroups[i].proto_list != NULL)
				func(&priority_cache->protocol,
				     *pgroups[i].proto_list);
			func(&priority_cache->_cipher, *pgroups[i].cipher_list);
			func(&priority_cache->_kx, *pgroups[i].kx_list);
			func(&priority_cache->_mac, *pgroups[i].mac_list);
			func(&priority_cache->_sign_algo,
			     *pgroups[i].sign_list);
			func(&priority_cache->_supported_ecc,
			     *pgroups[i].group_list);

			if (pgroups[i].profile != 0) {
				SET_PROFILE(
					pgroups[i].profile); /* set certificate level */
			}
			SET_LEVEL(
				pgroups[i].sec_param); /* set DH params level */
			priority_cache->no_tickets = pgroups[i].no_tickets;
			priority_cache->no_tickets_tls12 =
				pgroups[i].no_tickets_tls12;
			if (priority_cache->have_cbc == 0) {
				for (j = 0; (*pgroups[i].cipher_list)[j] != 0;
				     j++) {
					centry = cipher_to_entry(
						(*pgroups[i].cipher_list)[j]);
					if (centry != NULL &&
					    centry->type == CIPHER_BLOCK) {
						priority_cache->have_cbc = 1;
						break;
					}
				}
			}
			return 1;
		}
	}
}

static void enable_compat(gnutls_priority_t c)
{
	ENABLE_PRIO_COMPAT(c);
}

static void enable_server_key_usage_violations(gnutls_priority_t c)
{
	c->allow_server_key_usage_violation = 1;
}

static void enable_allow_small_records(gnutls_priority_t c)
{
	c->_allow_small_records = 1;
}

static void enable_dumbfw(gnutls_priority_t c)
{
	c->_dumbfw = 1;
}

static void enable_no_extensions(gnutls_priority_t c)
{
	c->no_extensions = 1;
}

static void enable_no_status_request(gnutls_priority_t c)
{
	c->no_status_request = 1;
}

static void enable_no_ext_master_secret(gnutls_priority_t c)
{
	c->_no_ext_master_secret = 1;
}

static void enable_force_ext_master_secret(gnutls_priority_t c)
{
	c->force_ext_master_secret = EMS_REQUIRE;
}

static void enable_no_etm(gnutls_priority_t c)
{
	c->_no_etm = 1;
}

static void enable_force_etm(gnutls_priority_t c)
{
	c->force_etm = 1;
}

static void enable_no_tickets(gnutls_priority_t c)
{
	c->no_tickets = 1;
}

static void enable_no_tickets_tls12(gnutls_priority_t c)
{
	c->no_tickets_tls12 = 1;
}

static void disable_wildcards(gnutls_priority_t c)
{
	c->additional_verify_flags |= GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS;
}

static void enable_profile_very_weak(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_VERY_WEAK);
}

static void enable_profile_low(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_LOW);
}

static void enable_profile_legacy(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_LEGACY);
}

static void enable_profile_medium(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_MEDIUM);
}

static void enable_profile_high(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_HIGH);
}

static void enable_profile_ultra(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_ULTRA);
}

static void enable_profile_future(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_FUTURE);
}

static void enable_profile_suiteb128(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_SUITEB128);
}

static void enable_profile_suiteb192(gnutls_priority_t c)
{
	ENABLE_PROFILE(c, GNUTLS_PROFILE_SUITEB128);
}

static void enable_safe_renegotiation(gnutls_priority_t c)
{
	c->sr = SR_SAFE;
}

static void enable_unsafe_renegotiation(gnutls_priority_t c)
{
	c->sr = SR_UNSAFE;
}

static void enable_partial_safe_renegotiation(gnutls_priority_t c)
{
	c->sr = SR_PARTIAL;
}

static void disable_safe_renegotiation(gnutls_priority_t c)
{
	c->sr = SR_DISABLED;
}

static void enable_fallback_scsv(gnutls_priority_t c)
{
	c->fallback = 1;
}

static void enable_latest_record_version(gnutls_priority_t c)
{
	c->min_record_version = 0;
}

static void enable_ssl3_record_version(gnutls_priority_t c)
{
	c->min_record_version = 1;
}

static void enable_verify_allow_rsa_md5(gnutls_priority_t c)
{
	c->additional_verify_flags |= GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;
}

static void enable_verify_allow_sha1(gnutls_priority_t c)
{
	c->additional_verify_flags |= GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1;
}

static void enable_verify_allow_broken(gnutls_priority_t c)
{
	c->additional_verify_flags |= GNUTLS_VERIFY_ALLOW_BROKEN;
}

static void disable_crl_checks(gnutls_priority_t c)
{
	c->additional_verify_flags |= GNUTLS_VERIFY_DISABLE_CRL_CHECKS;
}

static void enable_server_precedence(gnutls_priority_t c)
{
	c->server_precedence = 1;
}

static void disable_tls13_compat_mode(gnutls_priority_t c)
{
	c->tls13_compat_mode = false;
}

static void enable_no_shuffle_extensions(gnutls_priority_t c)
{
	c->no_shuffle_extensions = 1;
}

static void dummy_func(gnutls_priority_t c)
{
}

#include <priority_options.h>

struct cfg {
	bool allowlisting;
	bool ktls_enabled;
	bool allow_rsa_pkcs1_encrypt;

	name_val_array_t priority_strings;
	char *priority_string;
	char *default_priority_string;
	gnutls_certificate_verification_profiles_t verification_profile;

	gnutls_cipher_algorithm_t ciphers[MAX_ALGOS + 1];
	gnutls_mac_algorithm_t macs[MAX_ALGOS + 1];
	gnutls_group_t groups[MAX_ALGOS + 1];
	gnutls_kx_algorithm_t kxs[MAX_ALGOS + 1];
	gnutls_sign_algorithm_t sigs[MAX_ALGOS + 1];
	gnutls_protocol_t versions[MAX_ALGOS + 1];

	gnutls_digest_algorithm_t hashes[MAX_ALGOS + 1];
	gnutls_ecc_curve_t ecc_curves[MAX_ALGOS + 1];
	gnutls_sign_algorithm_t sigs_for_cert[MAX_ALGOS + 1];

	gnutls_compression_method_t
		cert_comp_algs[MAX_COMPRESS_CERTIFICATE_METHODS + 1];

	char *p11_provider_path;
	char *p11_provider_pin;

	ext_master_secret_t force_ext_master_secret;
	bool force_ext_master_secret_set;
};

static inline void cfg_init(struct cfg *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->allow_rsa_pkcs1_encrypt = true;
}

static inline void cfg_deinit(struct cfg *cfg)
{
	if (cfg->priority_strings) {
		_name_val_array_clear(&cfg->priority_strings);
	}
	gnutls_free(cfg->priority_string);
	gnutls_free(cfg->default_priority_string);
	gnutls_free(cfg->p11_provider_path);
	gnutls_free(cfg->p11_provider_pin);
}

/* Lock for reading and writing system_wide_config */
GNUTLS_RWLOCK(system_wide_config_rwlock);
static struct cfg system_wide_config;

static unsigned fail_on_invalid_config = 0;
static const char *system_priority_file = SYSTEM_PRIORITY_FILE;
static time_t system_priority_last_mod = 0;
static unsigned system_priority_file_loaded = 0;

#define GLOBAL_SECTION "global"
#define CUSTOM_PRIORITY_SECTION "priorities"
#define PROVIDER_SECTION "provider"
#define OVERRIDES_SECTION "overrides"
#define MAX_ALGO_NAME 2048

bool _gnutls_allowlisting_mode(void)
{
	return system_wide_config.allowlisting;
}

static void _clear_default_system_priority(void)
{
	gnutls_free(system_wide_config.default_priority_string);
	system_wide_config.default_priority_string = NULL;

	_gnutls_default_priority_string = DEFAULT_PRIORITY_STRING;
}

gnutls_certificate_verification_profiles_t
_gnutls_get_system_wide_verification_profile(void)
{
	return system_wide_config.verification_profile;
}

/* removes spaces */
static char *clear_spaces(const char *str, char out[MAX_ALGO_NAME])
{
	const char *p = str;
	unsigned i = 0;

	while (c_isspace(*p))
		p++;

	while (!c_isspace(*p) && *p != 0) {
		out[i++] = *p;
		p++;

		if (i >= MAX_ALGO_NAME - 1)
			break;
	}
	out[i] = 0;
	return out;
}

struct ini_ctx {
	struct cfg cfg;

	gnutls_digest_algorithm_t *hashes;
	size_t hashes_size;
	gnutls_sign_algorithm_t *sigs;
	size_t sigs_size;
	gnutls_sign_algorithm_t *sigs_for_cert;
	size_t sigs_for_cert_size;
	gnutls_protocol_t *versions;
	size_t versions_size;
	gnutls_ecc_curve_t *curves;
	size_t curves_size;
};

static inline void ini_ctx_init(struct ini_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	cfg_init(&ctx->cfg);
}

static inline void ini_ctx_deinit(struct ini_ctx *ctx)
{
	cfg_deinit(&ctx->cfg);
	gnutls_free(ctx->hashes);
	gnutls_free(ctx->sigs);
	gnutls_free(ctx->sigs_for_cert);
	gnutls_free(ctx->versions);
	gnutls_free(ctx->curves);
}

static inline void cfg_steal(struct cfg *dst, struct cfg *src)
{
	dst->verification_profile = src->verification_profile;

	dst->priority_strings = src->priority_strings;
	src->priority_strings = NULL;

	dst->priority_string = src->priority_string;
	src->priority_string = NULL;

	dst->default_priority_string = src->default_priority_string;
	src->default_priority_string = NULL;

	dst->p11_provider_path = src->p11_provider_path;
	src->p11_provider_path = NULL;

	dst->p11_provider_pin = src->p11_provider_pin;
	src->p11_provider_pin = NULL;

	dst->allowlisting = src->allowlisting;
	dst->ktls_enabled = src->ktls_enabled;
	dst->allow_rsa_pkcs1_encrypt = src->allow_rsa_pkcs1_encrypt;
	dst->force_ext_master_secret = src->force_ext_master_secret;
	dst->force_ext_master_secret_set = src->force_ext_master_secret_set;
	memcpy(dst->ciphers, src->ciphers, sizeof(src->ciphers));
	memcpy(dst->macs, src->macs, sizeof(src->macs));
	memcpy(dst->groups, src->groups, sizeof(src->groups));
	memcpy(dst->kxs, src->kxs, sizeof(src->kxs));
	memcpy(dst->hashes, src->hashes, sizeof(src->hashes));
	memcpy(dst->ecc_curves, src->ecc_curves, sizeof(src->ecc_curves));
	memcpy(dst->sigs, src->sigs, sizeof(src->sigs));
	memcpy(dst->sigs_for_cert, src->sigs_for_cert,
	       sizeof(src->sigs_for_cert));
	memcpy(dst->cert_comp_algs, src->cert_comp_algs,
	       sizeof(src->cert_comp_algs));
}

/*
 * synchronizing changes from struct cfg to global `lib/algorithms` arrays
 */

/* global side-effect! modifies `flags` in `hash_algorithms[]` */
static inline int /* allowlisting-only */ _cfg_hashes_remark(struct cfg *cfg)
{
	size_t i;
	_gnutls_digest_mark_insecure_all();
	for (i = 0; cfg->hashes[i] != 0; i++) {
		int ret = _gnutls_digest_set_secure(cfg->hashes[i], 1);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}
	return 0;
}

/* global side-effect! modifies `flags` in `sign_algorithms[]` */
static inline int /* allowlisting-only */ _cfg_sigs_remark(struct cfg *cfg)
{
	size_t i;
	_gnutls_sign_mark_insecure_all(_INSECURE);
	for (i = 0; cfg->sigs[i] != 0; i++) {
		int ret = _gnutls_sign_set_secure(cfg->sigs[i],
						  _INSECURE_FOR_CERTS);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}
	for (i = 0; cfg->sigs_for_cert[i] != 0; i++) {
		int ret =
			_gnutls_sign_set_secure(cfg->sigs_for_cert[i], _SECURE);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}
	return 0;
}

/* global side-effect! modifies `supported` in `sup_versions[]` */
static inline int /* allowlisting-only */ _cfg_versions_remark(struct cfg *cfg)
{
	size_t i;
	_gnutls_version_mark_disabled_all();
	for (i = 0; cfg->versions[i] != 0; i++) {
		int ret = _gnutls_protocol_set_enabled(cfg->versions[i], 1);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}
	return 0;
}

/* global side-effect! modifies `supported` in `ecc_curves[]` */
static inline int /* allowlisting-only */
_cfg_ecc_curves_remark(struct cfg *cfg)
{
	size_t i;
	_gnutls_ecc_curve_mark_disabled_all();
	for (i = 0; cfg->ecc_curves[i] != 0; i++) {
		int ret = _gnutls_ecc_curve_set_enabled(cfg->ecc_curves[i], 1);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}
	return 0;
}

/*
 * setting arrays of struct cfg: from other arrays
 */

static inline int /* allowlisting-only */
cfg_hashes_set_array(struct cfg *cfg, gnutls_digest_algorithm_t *src,
		     size_t len)
{
	if (unlikely(len >= MAX_ALGOS)) {
		return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR);
	}
	if (len) {
		memcpy(cfg->hashes, src,
		       sizeof(gnutls_digest_algorithm_t) * len);
	}
	cfg->hashes[len] = 0;
	return _cfg_hashes_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_sigs_set_arrays(struct cfg *cfg, gnutls_sign_algorithm_t *src, size_t len,
		    gnutls_sign_algorithm_t *src_for_cert, size_t len_for_cert)
{
	if (unlikely(len >= MAX_ALGOS)) {
		return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR);
	}
	if (unlikely(len_for_cert >= MAX_ALGOS)) {
		return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR);
	}
	if (len) {
		memcpy(cfg->sigs, src, sizeof(gnutls_sign_algorithm_t) * len);
	}
	if (len_for_cert) {
		memcpy(cfg->sigs_for_cert, src_for_cert,
		       sizeof(gnutls_sign_algorithm_t) * len_for_cert);
	}
	cfg->sigs[len] = 0;
	cfg->sigs_for_cert[len_for_cert] = 0;
	return _cfg_sigs_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_versions_set_array(struct cfg *cfg, gnutls_protocol_t *src, size_t len)
{
	if (unlikely(len >= MAX_ALGOS)) {
		return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR);
	}
	if (len) {
		memcpy(cfg->versions, src, sizeof(gnutls_protocol_t) * len);
	}
	cfg->versions[len] = 0;
	return _cfg_versions_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_ecc_curves_set_array(struct cfg *cfg, gnutls_ecc_curve_t *src, size_t len)
{
	if (unlikely(len >= MAX_ALGOS)) {
		return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR);
	}
	if (len) {
		memcpy(cfg->ecc_curves, src, sizeof(gnutls_ecc_curve_t) * len);
	}
	cfg->ecc_curves[len] = 0;
	return _cfg_ecc_curves_remark(cfg);
}

/*
 * appending to arrays of struct cfg
 */

/* polymorphic way to DRY this operation. other possible approaches:
 * 1. just unmacro (long)
 * 2. cast to ints and write a function operating on ints
 *    (hacky, every call is +4 lines, needs a portable static assert)
 * 3. macro whole functions, not just this operation (harder to find/read)
 */
#define APPEND_TO_NULL_TERMINATED_ARRAY(dst, element)                      \
	do {                                                               \
		size_t i;                                                  \
		for (i = 0; dst[i] != 0; i++) {                            \
			if (dst[i] == element) {                           \
				return 0;                                  \
			}                                                  \
		}                                                          \
		if (unlikely(i >= MAX_ALGOS)) {                            \
			return gnutls_assert_val(GNUTLS_A_INTERNAL_ERROR); \
		}                                                          \
		dst[i] = element;                                          \
		dst[i + 1] = 0;                                            \
	} while (0)

static inline int /* allowlisting-only */
cfg_hashes_add(struct cfg *cfg, gnutls_digest_algorithm_t dig)
{
	_gnutls_debug_log("cfg: enabling digest algorithm %s\n",
			  gnutls_digest_get_name(dig));
	APPEND_TO_NULL_TERMINATED_ARRAY(cfg->hashes, dig);
	return _cfg_hashes_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_sigs_add(struct cfg *cfg, gnutls_sign_algorithm_t sig)
{
	_gnutls_debug_log("cfg: enabling signature algorithm "
			  "(for non-certificate usage) "
			  "%s\n",
			  gnutls_sign_get_name(sig));
	APPEND_TO_NULL_TERMINATED_ARRAY(cfg->sigs, sig);
	return _cfg_sigs_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_sigs_for_cert_add(struct cfg *cfg, gnutls_sign_algorithm_t sig)
{
	_gnutls_debug_log("cfg: enabling signature algorithm"
			  "(for certificate usage) "
			  "%s\n",
			  gnutls_sign_get_name(sig));
	APPEND_TO_NULL_TERMINATED_ARRAY(cfg->sigs_for_cert, sig);
	return _cfg_sigs_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_versions_add(struct cfg *cfg, gnutls_protocol_t prot)
{
	_gnutls_debug_log("cfg: enabling version %s\n",
			  gnutls_protocol_get_name(prot));
	APPEND_TO_NULL_TERMINATED_ARRAY(cfg->versions, prot);
	return _cfg_versions_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_ecc_curves_add(struct cfg *cfg, gnutls_ecc_curve_t curve)
{
	_gnutls_debug_log("cfg: enabling curve %s\n",
			  gnutls_ecc_curve_get_name(curve));
	APPEND_TO_NULL_TERMINATED_ARRAY(cfg->ecc_curves, curve);
	return _cfg_ecc_curves_remark(cfg);
}

#undef APPEND_TO_NULL_TERMINATED_ARRAY

/*
 * removing from arrays of struct cfg
 */

/* polymorphic way to DRY this removal, see APPEND_TO_NULL_TERMINATED_ARRAY */
#define REMOVE_FROM_NULL_TERMINATED_ARRAY(dst, element)         \
	do {                                                    \
		size_t i, j;                                    \
		for (i = 0; dst[i] != 0; i++) {                 \
			if (dst[i] == element) {                \
				for (j = i; dst[j] != 0; j++) { \
					dst[j] = dst[j + 1];    \
				}                               \
			}                                       \
		}                                               \
	} while (0)

static inline int /* allowlisting-only */
cfg_hashes_remove(struct cfg *cfg, gnutls_digest_algorithm_t dig)
{
	_gnutls_debug_log("cfg: disabling digest algorithm %s\n",
			  gnutls_digest_get_name(dig));
	REMOVE_FROM_NULL_TERMINATED_ARRAY(cfg->hashes, dig);
	return _cfg_hashes_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_sigs_remove(struct cfg *cfg, gnutls_sign_algorithm_t sig)
{
	_gnutls_debug_log("cfg: disabling signature algorithm "
			  "(for non-certificate usage) "
			  "%s\n",
			  gnutls_sign_get_name(sig));
	REMOVE_FROM_NULL_TERMINATED_ARRAY(cfg->sigs, sig);
	return _cfg_sigs_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_sigs_for_cert_remove(struct cfg *cfg, gnutls_sign_algorithm_t sig)
{
	_gnutls_debug_log("cfg: disabling signature algorithm"
			  "(for certificate usage) "
			  "%s\n",
			  gnutls_sign_get_name(sig));
	REMOVE_FROM_NULL_TERMINATED_ARRAY(cfg->sigs_for_cert, sig);
	return _cfg_sigs_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_versions_remove(struct cfg *cfg, gnutls_protocol_t prot)
{
	_gnutls_debug_log("cfg: disabling version %s\n",
			  gnutls_protocol_get_name(prot));
	REMOVE_FROM_NULL_TERMINATED_ARRAY(cfg->versions, prot);
	return _cfg_versions_remark(cfg);
}

static inline int /* allowlisting-only */
cfg_ecc_curves_remove(struct cfg *cfg, gnutls_ecc_curve_t curve)
{
	_gnutls_debug_log("cfg: disabling curve %s\n",
			  gnutls_ecc_curve_get_name(curve));
	REMOVE_FROM_NULL_TERMINATED_ARRAY(cfg->ecc_curves, curve);
	return _cfg_ecc_curves_remark(cfg);
}

static inline int cfg_apply(struct cfg *cfg, struct ini_ctx *ctx)
{
	size_t i;
	int ret;

	cfg_steal(cfg, &ctx->cfg);

	if (cfg->default_priority_string) {
		_gnutls_default_priority_string = cfg->default_priority_string;
	}

	if (cfg->allowlisting) {
		/* also updates `flags` of global `hash_algorithms[]` */
		ret = cfg_hashes_set_array(cfg, ctx->hashes, ctx->hashes_size);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
		/* also updates `flags` of global `sign_algorithms[]` */
		ret = cfg_sigs_set_arrays(cfg, ctx->sigs, ctx->sigs_size,
					  ctx->sigs_for_cert,
					  ctx->sigs_for_cert_size);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
		/* also updates `supported` field of global `sup_versions[]` */
		ret = cfg_versions_set_array(cfg, ctx->versions,
					     ctx->versions_size);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
		/* also updates `supported` field of global `ecc_curves[]` */
		ret = cfg_ecc_curves_set_array(cfg, ctx->curves,
					       ctx->curves_size);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	} else {
		/* updates same global arrays as above, but doesn't store
		 * the algorithms into the `struct cfg` as allowlisting does.
		 * blocklisting doesn't allow relaxing the restrictions */
		for (i = 0; i < ctx->hashes_size; i++) {
			ret = _gnutls_digest_mark_insecure(ctx->hashes[i]);
			if (unlikely(ret < 0)) {
				return ret;
			}
		}
		for (i = 0; i < ctx->sigs_size; i++) {
			ret = _gnutls_sign_mark_insecure(ctx->sigs[i],
							 _INSECURE);
			if (unlikely(ret < 0)) {
				return ret;
			}
		}
		for (i = 0; i < ctx->sigs_for_cert_size; i++) {
			ret = _gnutls_sign_mark_insecure(ctx->sigs_for_cert[i],
							 _INSECURE_FOR_CERTS);
			if (unlikely(ret < 0)) {
				return ret;
			}
		}
		for (i = 0; i < ctx->versions_size; i++) {
			ret = _gnutls_version_mark_disabled(ctx->versions[i]);
			if (unlikely(ret < 0)) {
				return ret;
			}
		}
		for (i = 0; i < ctx->curves_size; i++) {
			ret = _gnutls_ecc_curve_mark_disabled(ctx->curves[i]);
			if (unlikely(ret < 0)) {
				return ret;
			}
		}
	}

	return 0;
}

/* This function parses the global section of the configuration file.
 */
static int global_ini_handler(void *ctx, const char *section, const char *name,
			      const char *value)
{
	char *p;
	char str[MAX_ALGO_NAME];
	struct cfg *cfg = ctx;

	if (section != NULL && c_strcasecmp(section, GLOBAL_SECTION) == 0) {
		if (c_strcasecmp(name, "override-mode") == 0) {
			p = clear_spaces(value, str);
			if (c_strcasecmp(p, "allowlist") == 0) {
				cfg->allowlisting = true;
			} else if (c_strcasecmp(p, "blocklist") == 0) {
				cfg->allowlisting = false;
			} else {
				_gnutls_debug_log(
					"cfg: unknown override mode %s\n", p);
				if (fail_on_invalid_config)
					return 0;
			}
		} else if (c_strcasecmp(name, "ktls") == 0) {
			p = clear_spaces(value, str);
			if (c_strcasecmp(p, "true") == 0) {
				cfg->ktls_enabled = true;
			} else if (c_strcasecmp(p, "false") == 0) {
				cfg->ktls_enabled = false;
			} else {
				_gnutls_debug_log("cfg: unknown ktls mode %s\n",
						  p);
				if (fail_on_invalid_config)
					return 0;
			}
		} else {
			_gnutls_debug_log("unknown parameter %s\n", name);
			if (fail_on_invalid_config)
				return 0;
		}
	}

	return 1;
}

static bool override_allowed(bool allowlisting, const char *name)
{
	static const struct {
		const char *allowlist_name;
		const char *blocklist_name;
	} names[] = { { "secure-hash", "insecure-hash" },
		      { "secure-sig", "insecure-sig" },
		      { "secure-sig-for-cert", "insecure-sig-for-cert" },
		      { "enabled-version", "disabled-version" },
		      { "enabled-curve", "disabled-curve" },
		      { "tls-enabled-cipher", "tls-disabled-cipher" },
		      { "tls-enabled-group", "tls-disabled-group" },
		      { "tls-enabled-kx", "tls-disabled-kx" },
		      { "tls-enabled-mac", "tls-disabled-mac" } };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (c_strcasecmp(name, allowlisting ?
					       names[i].blocklist_name :
					       names[i].allowlist_name) == 0)
			return false;
	}

	return true;
}

/* This function parses a gnutls configuration file.  Updating internal settings
 * according to the parsed configuration is done by cfg_apply.
 */
static int cfg_ini_handler(void *_ctx, const char *section, const char *name,
			   const char *value)
{
	char *p;
	int ret;
	unsigned i;
	char str[MAX_ALGO_NAME];
	struct ini_ctx *ctx = _ctx;
	struct cfg *cfg = &ctx->cfg;

	/* Note that we intentionally overwrite the value above; inih does
	 * not use that value after we handle it. */

	/* Parse sections */
	if (section == NULL || section[0] == 0 ||
	    c_strcasecmp(section, CUSTOM_PRIORITY_SECTION) == 0) {
		_gnutls_debug_log("cfg: adding priority: %s -> %s\n", name,
				  value);

		ret = _name_val_array_append(&cfg->priority_strings, name,
					     value);
		if (ret < 0)
			return 0;
	} else if (c_strcasecmp(section, PROVIDER_SECTION) == 0) {
		if (c_strcasecmp(name, "path") == 0) {
			gnutls_free(cfg->p11_provider_path);
			cfg->p11_provider_path = NULL;
			p = clear_spaces(value, str);
			_gnutls_debug_log(
				"cfg: adding pkcs11 provider path %s\n", p);
			if (strlen(p) > 0) {
				cfg->p11_provider_path = gnutls_strdup(p);
				if (cfg->p11_provider_path == NULL) {
					_gnutls_debug_log(
						"cfg: failed setting pkcs11 provider path\n");
					return 0;
				}
			} else {
				_gnutls_debug_log(
					"cfg: empty pkcs11 provider path, using default\n");
				if (fail_on_invalid_config)
					return 0;
			}
		} else if (c_strcasecmp(name, "pin") == 0) {
			gnutls_free(cfg->p11_provider_pin);
			cfg->p11_provider_pin = NULL;
			p = clear_spaces(value, str);
			_gnutls_debug_log("cfg: adding pkcs11 provider pin\n");
			if (strlen(p) > 0) {
				cfg->p11_provider_pin = gnutls_strdup(p);
				if (cfg->p11_provider_pin == NULL) {
					_gnutls_debug_log(
						"cfg: failed setting pkcs11 provider pin\n");
					return 0;
				}
			} else {
				_gnutls_debug_log(
					"cfg: empty pkcs11 provider pin, using default\n");
				if (fail_on_invalid_config)
					return 0;
			}
		} else {
			_gnutls_debug_log("unknown parameter %s\n", name);
			if (fail_on_invalid_config)
				return 0;
		}
	} else if (c_strcasecmp(section, OVERRIDES_SECTION) == 0) {
		if (!override_allowed(cfg->allowlisting, name)) {
			_gnutls_debug_log(
				"cfg: %s is not allowed in this mode\n", name);
			if (fail_on_invalid_config)
				return 0;
		} else if (c_strcasecmp(name, "default-priority-string") == 0) {
			if (cfg->default_priority_string) {
				gnutls_free(cfg->default_priority_string);
				cfg->default_priority_string = NULL;
			}
			p = clear_spaces(value, str);
			_gnutls_debug_log(
				"cfg: setting default-priority-string to %s\n",
				p);
			if (strlen(p) > 0) {
				cfg->default_priority_string = gnutls_strdup(p);
				if (!cfg->default_priority_string) {
					_gnutls_debug_log(
						"cfg: failed setting default-priority-string\n");
					return 0;
				}
			} else {
				_gnutls_debug_log(
					"cfg: empty default-priority-string, using default\n");
				if (fail_on_invalid_config)
					return 0;
			}
		} else if (c_strcasecmp(name, "insecure-hash") == 0 ||
			   c_strcasecmp(name, "secure-hash") == 0) {
			gnutls_digest_algorithm_t dig, *tmp;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: marking hash %s as secure\n", p);
			} else {
				_gnutls_debug_log(
					"cfg: marking hash %s as insecure\n",
					p);
			}

			dig = gnutls_digest_get_id(p);
			if (dig == GNUTLS_DIG_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown hash %s in %s\n", p,
					name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			tmp = _gnutls_reallocarray(
				ctx->hashes, ctx->hashes_size + 1,
				sizeof(gnutls_digest_algorithm_t));
			if (!tmp) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: failed marking hash %s as secure\n",
						p);
				} else {
					_gnutls_debug_log(
						"cfg: failed marking hash %s as insecure\n",
						p);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			ctx->hashes = tmp;
			ctx->hashes[ctx->hashes_size] = dig;
			ctx->hashes_size++;
		} else if (c_strcasecmp(name, "insecure-sig") == 0 ||
			   c_strcasecmp(name, "secure-sig") == 0) {
			gnutls_sign_algorithm_t sig, *tmp;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: marking signature %s as secure\n",
					p);
			} else {
				_gnutls_debug_log(
					"cfg: marking signature %s as insecure\n",
					p);
			}

			sig = gnutls_sign_get_id(p);
			if (sig == GNUTLS_SIGN_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown signature algorithm %s in %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			tmp = _gnutls_reallocarray(
				ctx->sigs, ctx->sigs_size + 1,
				sizeof(gnutls_sign_algorithm_t));
			if (!tmp) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: failed marking signature %s as secure\n",
						p);
				} else {
					_gnutls_debug_log(
						"cfg: failed marking signature %s as insecure\n",
						p);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			ctx->sigs = tmp;
			ctx->sigs[ctx->sigs_size] = sig;
			ctx->sigs_size++;
		} else if (c_strcasecmp(name, "insecure-sig-for-cert") == 0 ||
			   c_strcasecmp(name, "secure-sig-for-cert") == 0) {
			gnutls_sign_algorithm_t sig, *tmp;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: marking signature %s as secure for certs\n",
					p);
			} else {
				_gnutls_debug_log(
					"cfg: marking signature %s as insecure for certs\n",
					p);
			}

			sig = gnutls_sign_get_id(p);
			if (sig == GNUTLS_SIGN_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown signature algorithm %s in %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			tmp = _gnutls_reallocarray(
				ctx->sigs_for_cert, ctx->sigs_for_cert_size + 1,
				sizeof(gnutls_sign_algorithm_t));
			if (!tmp) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: failed marking signature %s as secure for certs\n",
						p);
				} else {
					_gnutls_debug_log(
						"cfg: failed marking signature %s as insecure for certs\n",
						p);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			ctx->sigs_for_cert = tmp;
			ctx->sigs_for_cert[ctx->sigs_for_cert_size] = sig;
			ctx->sigs_for_cert_size++;
		} else if (c_strcasecmp(name, "disabled-version") == 0 ||
			   c_strcasecmp(name, "enabled-version") == 0) {
			gnutls_protocol_t prot, *tmp;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log("cfg: enabling version %s\n",
						  p);
			} else {
				_gnutls_debug_log("cfg: disabling version %s\n",
						  p);
			}

			prot = gnutls_protocol_get_id(p);
			if (prot == GNUTLS_VERSION_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown version %s in %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			tmp = _gnutls_reallocarray(ctx->versions,
						   ctx->versions_size + 1,
						   sizeof(gnutls_protocol_t));
			if (!tmp) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: failed enabling version %s\n",
						p);
				} else {
					_gnutls_debug_log(
						"cfg: failed disabling version %s\n",
						p);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			ctx->versions = tmp;
			ctx->versions[ctx->versions_size] = prot;
			ctx->versions_size++;
		} else if (c_strcasecmp(name, "disabled-curve") == 0 ||
			   c_strcasecmp(name, "enabled-curve") == 0) {
			gnutls_ecc_curve_t curve, *tmp;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log("cfg: enabling curve %s\n",
						  p);
			} else {
				_gnutls_debug_log("cfg: disabling curve %s\n",
						  p);
			}

			curve = gnutls_ecc_curve_get_id(p);
			if (curve == GNUTLS_ECC_CURVE_INVALID) {
				_gnutls_debug_log(
					"cfg: found unknown curve %s in %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			tmp = _gnutls_reallocarray(ctx->curves,
						   ctx->curves_size + 1,
						   sizeof(gnutls_ecc_curve_t));
			if (!tmp) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: failed enabling curve %s\n",
						p);
				} else {
					_gnutls_debug_log(
						"cfg: failed disabling curve %s\n",
						p);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			ctx->curves = tmp;
			ctx->curves[ctx->curves_size] = curve;
			ctx->curves_size++;
		} else if (c_strcasecmp(name, "min-verification-profile") ==
			   0) {
			gnutls_certificate_verification_profiles_t profile;
			profile =
				gnutls_certificate_verification_profile_get_id(
					value);

			if (profile == GNUTLS_PROFILE_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown profile %s in %s\n",
					value, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			cfg->verification_profile = profile;
		} else if (c_strcasecmp(name, "tls-disabled-cipher") == 0 ||
			   c_strcasecmp(name, "tls-enabled-cipher") == 0) {
			gnutls_cipher_algorithm_t algo;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: enabling cipher %s for TLS\n", p);
			} else {
				_gnutls_debug_log(
					"cfg: disabling cipher %s for TLS\n",
					p);
			}

			algo = gnutls_cipher_get_id(p);
			if (algo == GNUTLS_CIPHER_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: unknown algorithm %s listed at %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			i = 0;
			while (cfg->ciphers[i] != 0)
				i++;

			if (i > MAX_ALGOS - 1) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: too many (%d) enabled ciphers from %s\n",
						i, name);
				} else {
					_gnutls_debug_log(
						"cfg: too many (%d) disabled ciphers from %s\n",
						i, name);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			cfg->ciphers[i] = algo;
			cfg->ciphers[i + 1] = 0;

		} else if (c_strcasecmp(name, "tls-disabled-mac") == 0 ||
			   c_strcasecmp(name, "tls-enabled-mac") == 0) {
			gnutls_mac_algorithm_t algo;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: enabling MAC %s for TLS\n", p);
			} else {
				_gnutls_debug_log(
					"cfg: disabling MAC %s for TLS\n", p);
			}

			algo = gnutls_mac_get_id(p);
			if (algo == 0) {
				_gnutls_debug_log(
					"cfg: unknown algorithm %s listed at %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			i = 0;
			while (cfg->macs[i] != 0)
				i++;

			if (i > MAX_ALGOS - 1) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: too many (%d) enabled MACs from %s\n",
						i, name);
				} else {
					_gnutls_debug_log(
						"cfg: too many (%d) disabled MACs from %s\n",
						i, name);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			cfg->macs[i] = algo;
			cfg->macs[i + 1] = 0;
		} else if (c_strcasecmp(name, "tls-disabled-group") == 0 ||
			   c_strcasecmp(name, "tls-enabled-group") == 0) {
			gnutls_group_t algo;

			p = clear_spaces(value, str);

			if (c_strncasecmp(p, "GROUP-", 6) == 0)
				p += 6;

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: enabling group %s for TLS\n", p);
			} else {
				_gnutls_debug_log(
					"cfg: disabling group %s for TLS\n", p);
			}

			algo = _gnutls_group_get_id(p);
			if (algo == 0) {
				_gnutls_debug_log(
					"cfg: unknown group %s listed at %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			i = 0;
			while (cfg->groups[i] != 0)
				i++;

			if (i > MAX_ALGOS - 1) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: too many (%d) enabled groups from %s\n",
						i, name);
				} else {
					_gnutls_debug_log(
						"cfg: too many (%d) disabled groups from %s\n",
						i, name);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			cfg->groups[i] = algo;
			cfg->groups[i + 1] = 0;
		} else if (c_strcasecmp(name, "tls-disabled-kx") == 0 ||
			   c_strcasecmp(name, "tls-enabled-kx") == 0) {
			unsigned algo;

			p = clear_spaces(value, str);

			if (cfg->allowlisting) {
				_gnutls_debug_log(
					"cfg: enabling key exchange %s for TLS\n",
					p);
			} else {
				_gnutls_debug_log(
					"cfg: disabling key exchange %s for TLS\n",
					p);
			}

			algo = gnutls_kx_get_id(p);
			if (algo == 0) {
				_gnutls_debug_log(
					"cfg: unknown key exchange %s listed at %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			i = 0;
			while (cfg->kxs[i] != 0)
				i++;

			if (i > MAX_ALGOS - 1) {
				if (cfg->allowlisting) {
					_gnutls_debug_log(
						"cfg: too many (%d) enabled key exchanges from %s\n",
						i, name);
				} else {
					_gnutls_debug_log(
						"cfg: too many (%d) disabled key exchanges from %s\n",
						i, name);
				}
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
			cfg->kxs[i] = algo;
			cfg->kxs[i + 1] = 0;
		} else if (c_strcasecmp(name, "tls-session-hash") == 0) {
			if (c_strcasecmp(value, "request") == 0) {
				cfg->force_ext_master_secret = EMS_REQUEST;
				cfg->force_ext_master_secret_set = true;
			} else if (c_strcasecmp(value, "require") == 0) {
				cfg->force_ext_master_secret = EMS_REQUIRE;
				cfg->force_ext_master_secret_set = true;
			} else {
				_gnutls_debug_log(
					"cfg: unknown value for %s: %s\n", name,
					value);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
		} else if (c_strcasecmp(name, "cert-compression-alg") == 0) {
			gnutls_compression_method_t method;

			p = clear_spaces(value, str);

			method = gnutls_compression_get_id(p);
			if (method == GNUTLS_COMP_UNKNOWN) {
				_gnutls_debug_log(
					"cfg: found unknown compression"
					" method %s in %s\n",
					p, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			i = 0;
			while (cfg->cert_comp_algs[i] != 0)
				i++;

			if (i >= MAX_COMPRESS_CERTIFICATE_METHODS) {
				_gnutls_debug_log(
					"cfg: too many (%d) compression"
					" methods from %s\n",
					i, name);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}

			cfg->cert_comp_algs[i] = method;
			cfg->cert_comp_algs[i + 1] = 0;
		} else if (c_strcasecmp(name, "allow-rsa-pkcs1-encrypt") == 0) {
			p = clear_spaces(value, str);
			if (c_strcasecmp(p, "true") == 0) {
				cfg->allow_rsa_pkcs1_encrypt = true;
			} else if (c_strcasecmp(p, "false") == 0) {
				cfg->allow_rsa_pkcs1_encrypt = false;
			} else {
				_gnutls_debug_log(
					"cfg: unknown RSA PKCS1 encryption mode %s\n",
					p);
				if (fail_on_invalid_config)
					return 0;
				goto exit;
			}
		} else {
			_gnutls_debug_log("unknown parameter %s\n", name);
			if (fail_on_invalid_config)
				return 0;
		}
	} else if (c_strcasecmp(section, GLOBAL_SECTION) != 0) {
		_gnutls_debug_log("cfg: unknown section %s\n", section);
		if (fail_on_invalid_config)
			return 0;
	}

exit:
	return 1;
}

static int /* not locking system_wide_config */
construct_system_wide_priority_string(gnutls_buffer_st *buf)
{
	int ret;
	size_t i;

	_gnutls_buffer_init(buf);

	ret = _gnutls_buffer_append_str(buf, "NONE");
	if (ret < 0) {
		_gnutls_buffer_clear(buf);
		return ret;
	}

	for (i = 0; system_wide_config.kxs[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf, gnutls_kx_get_name(system_wide_config.kxs[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}

	for (i = 0; system_wide_config.groups[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+GROUP-");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf,
			gnutls_group_get_name(system_wide_config.groups[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}

	for (i = 0; system_wide_config.ciphers[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf,
			gnutls_cipher_get_name(system_wide_config.ciphers[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}

	for (i = 0; system_wide_config.macs[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf, gnutls_mac_get_name(system_wide_config.macs[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}

	for (i = 0; system_wide_config.sigs[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+SIGN-");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf, gnutls_sign_get_name(system_wide_config.sigs[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}

	for (i = 0; system_wide_config.versions[i] != 0; i++) {
		ret = _gnutls_buffer_append_str(buf, ":+VERS-");
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}

		ret = _gnutls_buffer_append_str(
			buf, gnutls_protocol_get_name(
				     system_wide_config.versions[i]));
		if (ret < 0) {
			_gnutls_buffer_clear(buf);
			return ret;
		}
	}
	return 0;
}

static int /* not locking system_wide_config */
update_system_wide_priority_string(void)
{
	/* doesn't do locking, _gnutls_update_system_priorities does */
	gnutls_buffer_st buf;
	int ret;

	ret = construct_system_wide_priority_string(&buf);
	if (ret < 0) {
		_gnutls_debug_log("cfg: unable to construct "
				  "system-wide priority string: %s",
				  gnutls_strerror(ret));
		_gnutls_buffer_clear(&buf);
		return ret;
	}

	gnutls_free(system_wide_config.priority_string);
	system_wide_config.priority_string = gnutls_strdup((char *)buf.data);
	_gnutls_buffer_clear(&buf);

	return 0;
}

/* Returns false on parse error, otherwise true.
 * The system_wide_config must be locked for writing.
 */
static inline bool load_system_priority_file(void)
{
	int err;
	FILE *fp;
	struct ini_ctx ctx;

	cfg_init(&system_wide_config);

	fp = fopen(system_priority_file, "re");
	if (fp == NULL) {
		_gnutls_debug_log("cfg: unable to open: %s: %d\n",
				  system_priority_file, errno);
		return true;
	}

	/* Parsing the configuration file needs to be done in 2 phases:
	 * first parsing the [global] section
	 * and then the other sections,
	 * because the [global] section modifies the parsing behavior.
	 */
	ini_ctx_init(&ctx);
	err = ini_parse_file(fp, global_ini_handler, &ctx);
	if (!err) {
		if (fseek(fp, 0L, SEEK_SET) < 0) {
			_gnutls_debug_log("cfg: unable to rewind: %s\n",
					  system_priority_file);
			if (fail_on_invalid_config)
				exit(1);
		}
		err = ini_parse_file(fp, cfg_ini_handler, &ctx);
	}
	fclose(fp);
	if (err) {
		ini_ctx_deinit(&ctx);
		_gnutls_debug_log("cfg: unable to parse: %s: %d\n",
				  system_priority_file, err);
		return false;
	}
	cfg_apply(&system_wide_config, &ctx);
	ini_ctx_deinit(&ctx);
	return true;
}

static int _gnutls_update_system_priorities(bool defer_system_wide)
{
	int ret;
	bool config_parse_error = false;
	struct stat sb;
	gnutls_buffer_st buf;

	ret = gnutls_rwlock_rdlock(&system_wide_config_rwlock);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (stat(system_priority_file, &sb) < 0) {
		_gnutls_debug_log("cfg: unable to access: %s: %d\n",
				  system_priority_file, errno);

		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
		if (ret < 0)
			goto out;
		/* If system-wide config is unavailable, apply the defaults */
		cfg_init(&system_wide_config);
		goto out;
	}

	if (system_priority_file_loaded &&
	    system_priority_last_mod == sb.st_mtime) {
		_gnutls_debug_log("cfg: system priority %s has not changed\n",
				  system_priority_file);
		if (system_wide_config.priority_string)
			goto out; /* nothing to do */
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);

	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* Another thread could have successfully re-read system-wide config,
	 * skip re-reading if the mtime it has used is exactly the same.
	 */
	if (system_priority_file_loaded)
		system_priority_file_loaded =
			(system_priority_last_mod == sb.st_mtime);

	if (!system_priority_file_loaded) {
		config_parse_error = !load_system_priority_file();
		if (config_parse_error)
			goto out;
		_gnutls_debug_log("cfg: loaded system config %s mtime %lld\n",
				  system_priority_file,
				  (unsigned long long)sb.st_mtime);
	}

	if (system_wide_config.allowlisting) {
		if (defer_system_wide) {
			/* try constructing a priority string,
			 * but don't apply it yet, at this point
			 * we're only interested in whether we can */
			ret = construct_system_wide_priority_string(&buf);
			_gnutls_buffer_clear(&buf);
			_gnutls_debug_log("cfg: deferred setting "
					  "system-wide priority string\n");
		} else {
			ret = update_system_wide_priority_string();
			_gnutls_debug_log("cfg: finalized "
					  "system-wide priority string\n");
		}
		if (ret < 0) {
			_gnutls_debug_log(
				"cfg: unable to build priority string: %s\n",
				gnutls_strerror(ret));
			if (fail_on_invalid_config)
				exit(1);
			goto out;
		}
	}

	system_priority_file_loaded = 1;
	system_priority_last_mod = sb.st_mtime;

out:
	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);

	if (config_parse_error && fail_on_invalid_config)
		exit(1);

	return ret;
}

void _gnutls_prepare_to_load_system_priorities(void)
{
	const char *p;
	int ret;

	p = secure_getenv("GNUTLS_SYSTEM_PRIORITY_FILE");
	if (p != NULL)
		system_priority_file = p;

	p = secure_getenv("GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID");
	if (p != NULL && p[0] == '1' && p[1] == 0)
		fail_on_invalid_config = 1;

	ret = _gnutls_update_system_priorities(true /* defer_system_wide */);
	if (ret < 0) {
		_gnutls_debug_log("failed to update system priorities: %s\n",
				  gnutls_strerror(ret));
	}
}

void _gnutls_unload_system_priorities(void)
{
	_name_val_array_clear(&system_wide_config.priority_strings);
	gnutls_free(system_wide_config.priority_string);
	_clear_default_system_priority();
	system_priority_last_mod = 0;
}

/**
 * gnutls_get_system_config_file:
 *
 * Returns the filename of the system wide configuration
 * file to be loaded by the library.
 *
 * Returns: a constant pointer to the config file path
 *
 * Since: 3.6.9
 **/
const char *gnutls_get_system_config_file(void)
{
	return system_priority_file;
}

#define S(str) ((str != NULL) ? str : "")

/* Returns the new priorities if a priority string prefixed
 * with '@' is provided, or just a copy of the provided
 * priorities, appended with any additional present in
 * the priorities string.
 *
 * The returned string must be released using gnutls_free().
 */
char *_gnutls_resolve_priorities(const char *priorities)
{
	const char *p = priorities;
	char *additional = NULL;
	char *resolved = NULL;
	const char *ss, *ss_next;
	unsigned ss_len, ss_next_len;
	size_t n, n2 = 0;
	int ret;

	while (c_isspace(*p)) {
		p++;
	}

	/* Cannot reduce further. */
	if (*p != '@') {
		return gnutls_strdup(p);
	}

	ss = p + 1;
	additional = strchr(ss, ':');
	if (additional) {
		additional++;
	}

	/* Always try to refresh the cached data, to allow it to be
	 * updated without restarting all applications.
	 */
	ret = _gnutls_update_system_priorities(false /* defer_system_wide */);
	if (ret < 0) {
		_gnutls_debug_log("failed to update system priorities: %s\n",
				  gnutls_strerror(ret));
	}

	do {
		ss_next = strchr(ss, ',');
		if (ss_next) {
			if (additional && ss_next > additional) {
				ss_next = NULL;
			} else {
				ss_next++;
			}
		}

		if (ss_next) {
			ss_len = ss_next - ss - 1;
			ss_next_len = additional - ss_next - 1;
		} else if (additional) {
			ss_len = additional - ss - 1;
			ss_next_len = 0;
		} else {
			ss_len = strlen(ss);
			ss_next_len = 0;
		}

		ret = gnutls_rwlock_rdlock(&system_wide_config_rwlock);
		if (ret < 0) {
			_gnutls_debug_log(
				"cannot read system priority strings: %s\n",
				gnutls_strerror(ret));
			break;
		}
		if (system_wide_config.allowlisting &&
		    ss_len == sizeof(LEVEL_SYSTEM) - 1 &&
		    strncmp(LEVEL_SYSTEM, ss, ss_len) == 0) {
			p = system_wide_config.priority_string;
		} else {
			p = _name_val_array_value(
				system_wide_config.priority_strings, ss,
				ss_len);
		}

		_gnutls_debug_log("resolved '%.*s' to '%s', next '%.*s'\n",
				  ss_len, ss, S(p), ss_next_len, S(ss_next));

		if (p) {
			n = strlen(p);
			if (additional) {
				n2 = strlen(additional);
			}

			resolved = gnutls_malloc(n + n2 + 1 + 1);
			if (resolved) {
				memcpy(resolved, p, n);
				if (additional) {
					resolved[n] = ':';
					memcpy(&resolved[n + 1], additional,
					       n2);
					resolved[n + n2 + 1] = 0;
				} else {
					resolved[n] = 0;
				}
			}
		}

		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);

		ss = ss_next;
	} while (ss && !resolved);

	if (resolved) {
		_gnutls_debug_log("selected priority string: %s\n", resolved);
	} else {
		_gnutls_debug_log("unable to resolve %s\n", priorities);
	}

	return resolved;
}

static void add_ec(gnutls_priority_t priority_cache)
{
	const gnutls_group_entry_st *ge;
	unsigned i;

	for (i = 0; i < priority_cache->_supported_ecc.num_priorities; i++) {
		ge = _gnutls_id_to_group(
			priority_cache->_supported_ecc.priorities[i]);
		if (ge != NULL &&
		    priority_cache->groups.size <
			    sizeof(priority_cache->groups.entry) /
				    sizeof(priority_cache->groups.entry[0])) {
			/* do not add groups which do not correspond to enabled ciphersuites */
			if (!ge->curve)
				continue;
			priority_cache->groups
				.entry[priority_cache->groups.size++] = ge;
		}
	}
}

static void add_dh(gnutls_priority_t priority_cache)
{
	const gnutls_group_entry_st *ge;
	unsigned i;

	for (i = 0; i < priority_cache->_supported_ecc.num_priorities; i++) {
		ge = _gnutls_id_to_group(
			priority_cache->_supported_ecc.priorities[i]);
		if (ge != NULL &&
		    priority_cache->groups.size <
			    sizeof(priority_cache->groups.entry) /
				    sizeof(priority_cache->groups.entry[0])) {
			/* do not add groups which do not correspond to enabled ciphersuites */
			if (!ge->prime)
				continue;
			priority_cache->groups
				.entry[priority_cache->groups.size++] = ge;
			priority_cache->groups.have_ffdhe = 1;
		}
	}
}

static void add_hybrid(gnutls_priority_t priority_cache)
{
	const gnutls_group_entry_st *ge;
	unsigned i;

	for (i = 0; i < priority_cache->_supported_ecc.num_priorities; i++) {
		ge = _gnutls_id_to_group(
			priority_cache->_supported_ecc.priorities[i]);
		if (ge != NULL &&
		    priority_cache->groups.size <
			    sizeof(priority_cache->groups.entry) /
				    sizeof(priority_cache->groups.entry[0])) {
			/* do not add groups which do not correspond to enabled ciphersuites */
			if (!IS_GROUP_HYBRID(ge))
				continue;
			priority_cache->groups
				.entry[priority_cache->groups.size++] = ge;
		}
	}
}

/* This function was originally precalculating ciphersuite-specific items, however
 * it has now extended to much more than that. It provides a consistency check to
 * set parameters, and in cases it applies policy specific items.
 */
static int set_ciphersuite_list(gnutls_priority_t priority_cache)
{
	unsigned i, j, z;
	const gnutls_cipher_suite_entry_st *ce;
	const gnutls_sign_entry_st *se;
	unsigned have_ec = 0;
	unsigned have_dh = 0;
	unsigned have_hybrid = 0;
	unsigned tls_sig_sem = 0;
	const version_entry_st *tlsmax = NULL, *vers;
	const version_entry_st *dtlsmax = NULL;
	const version_entry_st *tlsmin = NULL;
	const version_entry_st *dtlsmin = NULL;
	unsigned have_tls13 = 0, have_srp = 0;
	unsigned have_pre_tls12 = 0, have_tls12 = 0;
	unsigned have_psk = 0, have_null = 0, have_rsa_psk = 0;
	gnutls_digest_algorithm_t prf_digest;
	int ret = 0;

	/* have_psk indicates that a PSK key exchange compatible
	 * with TLS1.3 is enabled. */

	priority_cache->cs.size = 0;
	priority_cache->sigalg.size = 0;
	priority_cache->groups.size = 0;
	priority_cache->groups.have_ffdhe = 0;

	/* The following requires a lock so there are no inconsistencies in the
	 * members of system_wide_config loaded from the config file. */
	ret = gnutls_rwlock_rdlock(&system_wide_config_rwlock);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	/* in blocklisting mode, apply system wide disablement of key exchanges,
	 * groups, MACs, and ciphers. */
	if (!system_wide_config.allowlisting) {
		/* disable key exchanges which are globally disabled */
		z = 0;
		while (system_wide_config.kxs[z] != 0) {
			for (i = j = 0; i < priority_cache->_kx.num_priorities;
			     i++) {
				if (priority_cache->_kx.priorities[i] !=
				    system_wide_config.kxs[z])
					priority_cache->_kx.priorities[j++] =
						priority_cache->_kx
							.priorities[i];
			}
			priority_cache->_kx.num_priorities = j;
			z++;
		}

		/* disable groups which are globally disabled */
		z = 0;
		while (system_wide_config.groups[z] != 0) {
			for (i = j = 0;
			     i < priority_cache->_supported_ecc.num_priorities;
			     i++) {
				if (priority_cache->_supported_ecc
					    .priorities[i] !=
				    system_wide_config.groups[z])
					priority_cache->_supported_ecc
						.priorities[j++] =
						priority_cache->_supported_ecc
							.priorities[i];
			}
			priority_cache->_supported_ecc.num_priorities = j;
			z++;
		}

		/* disable ciphers which are globally disabled */
		z = 0;
		while (system_wide_config.ciphers[z] != 0) {
			for (i = j = 0;
			     i < priority_cache->_cipher.num_priorities; i++) {
				if (priority_cache->_cipher.priorities[i] !=
				    system_wide_config.ciphers[z])
					priority_cache->_cipher.priorities[j++] =
						priority_cache->_cipher
							.priorities[i];
			}
			priority_cache->_cipher.num_priorities = j;
			z++;
		}

		/* disable MACs which are globally disabled */
		z = 0;
		while (system_wide_config.macs[z] != 0) {
			for (i = j = 0; i < priority_cache->_mac.num_priorities;
			     i++) {
				if (priority_cache->_mac.priorities[i] !=
				    system_wide_config.macs[z])
					priority_cache->_mac.priorities[j++] =
						priority_cache->_mac
							.priorities[i];
			}
			priority_cache->_mac.num_priorities = j;
			z++;
		}
	}

	for (j = 0; j < priority_cache->_cipher.num_priorities; j++) {
		if (priority_cache->_cipher.priorities[j] ==
		    GNUTLS_CIPHER_NULL) {
			have_null = 1;
			break;
		}
	}

	for (i = 0; i < priority_cache->_kx.num_priorities; i++) {
		if (IS_SRP_KX(priority_cache->_kx.priorities[i])) {
			have_srp = 1;
		} else if (_gnutls_kx_is_psk(
				   priority_cache->_kx.priorities[i])) {
			if (priority_cache->_kx.priorities[i] ==
			    GNUTLS_KX_RSA_PSK)
				have_rsa_psk = 1;
			else
				have_psk = 1;
		}
	}

	/* disable TLS versions which are added but are unsupported */
	for (i = j = 0; i < priority_cache->protocol.num_priorities; i++) {
		vers = version_to_entry(priority_cache->protocol.priorities[i]);
		if (!vers || vers->supported ||
		    (system_wide_config.allowlisting &&
		     vers->supported_revertible))
			priority_cache->protocol.priorities[j++] =
				priority_cache->protocol.priorities[i];
	}
	priority_cache->protocol.num_priorities = j;

	/* if we have NULL ciphersuites, SRP, or RSA-PSK enabled remove TLS1.3+
	 * protocol versions; they cannot be negotiated under TLS1.3. */
	if (have_null || have_srp || have_rsa_psk ||
	    priority_cache->no_extensions) {
		for (i = j = 0; i < priority_cache->protocol.num_priorities;
		     i++) {
			vers = version_to_entry(
				priority_cache->protocol.priorities[i]);
			if (!vers || !vers->tls13_sem)
				priority_cache->protocol.priorities[j++] =
					priority_cache->protocol.priorities[i];
		}
		priority_cache->protocol.num_priorities = j;
	}

	for (i = 0; i < priority_cache->protocol.num_priorities; i++) {
		vers = version_to_entry(priority_cache->protocol.priorities[i]);
		if (!vers)
			continue;

		if (vers->transport == GNUTLS_STREAM) { /* TLS */
			tls_sig_sem |= vers->tls_sig_sem;
			if (vers->tls13_sem)
				have_tls13 = 1;

			if (vers->id == GNUTLS_TLS1_2)
				have_tls12 = 1;
			else if (vers->id < GNUTLS_TLS1_2)
				have_pre_tls12 = 1;

			if (tlsmax == NULL || vers->age > tlsmax->age)
				tlsmax = vers;
			if (tlsmin == NULL || vers->age < tlsmin->age)
				tlsmin = vers;
		} else { /* dtls */
			tls_sig_sem |= vers->tls_sig_sem;

			/* we need to introduce similar handling to above
			 * when DTLS1.3 is supported */

			if (dtlsmax == NULL || vers->age > dtlsmax->age)
				dtlsmax = vers;
			if (dtlsmin == NULL || vers->age < dtlsmin->age)
				dtlsmin = vers;
		}
	}

	/* DTLS or TLS protocols must be present */
	if ((!tlsmax || !tlsmin) && (!dtlsmax || !dtlsmin)) {
		ret = gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);
		goto out;
	}

	priority_cache->have_psk = have_psk;

	/* if we are have TLS1.3+ do not enable any key exchange algorithms,
	 * the protocol doesn't require any. */
	if (tlsmin && tlsmin->tls13_sem && !have_psk) {
		if (!dtlsmin || (dtlsmin && dtlsmin->tls13_sem))
			priority_cache->_kx.num_priorities = 0;
	}

	/* Add TLS 1.3 ciphersuites (no KX) */
	for (j = 0; j < priority_cache->_cipher.num_priorities; j++) {
		for (z = 0; z < priority_cache->_mac.num_priorities; z++) {
			ce = cipher_suite_get(
				0, priority_cache->_cipher.priorities[j],
				priority_cache->_mac.priorities[z]);
			if (ce == NULL)
				continue;

			prf_digest = MAC_TO_DIG(ce->prf);
			if (prf_digest == GNUTLS_DIG_UNKNOWN)
				continue;
			if (_gnutls_digest_is_insecure(prf_digest))
				continue;

			if (priority_cache->cs.size == MAX_CIPHERSUITE_SIZE)
				continue;

			priority_cache->cs.entry[priority_cache->cs.size++] =
				ce;

			if (!have_hybrid) {
				have_hybrid = 1;
				add_hybrid(priority_cache);
			}
		}
	}

	for (i = 0; i < priority_cache->_kx.num_priorities; i++) {
		for (j = 0; j < priority_cache->_cipher.num_priorities; j++) {
			for (z = 0; z < priority_cache->_mac.num_priorities;
			     z++) {
				ce = cipher_suite_get(
					priority_cache->_kx.priorities[i],
					priority_cache->_cipher.priorities[j],
					priority_cache->_mac.priorities[z]);
				if (ce == NULL)
					continue;

				prf_digest = MAC_TO_DIG(ce->prf);
				if (prf_digest == GNUTLS_DIG_UNKNOWN)
					continue;
				if (_gnutls_digest_is_insecure(prf_digest))
					continue;

				if (priority_cache->cs.size ==
				    MAX_CIPHERSUITE_SIZE)
					continue;
				priority_cache->cs
					.entry[priority_cache->cs.size++] = ce;
				if (!have_ec &&
				    (_gnutls_kx_is_ecc(ce->kx_algorithm) ||
				     _gnutls_kx_is_vko_gost(ce->kx_algorithm))) {
					have_ec = 1;
					add_ec(priority_cache);
				}
				if (!have_dh &&
				    _gnutls_kx_is_dhe(ce->kx_algorithm)) {
					have_dh = 1;
					add_dh(priority_cache);
				}
			}
		}
	}

	if (have_tls13 && (!have_ec || !have_dh || !have_hybrid)) {
		/* scan groups to determine have_{ec,dh,hybrid} */
		for (i = 0; i < priority_cache->_supported_ecc.num_priorities;
		     i++) {
			const gnutls_group_entry_st *ge;
			ge = _gnutls_id_to_group(
				priority_cache->_supported_ecc.priorities[i]);
			if (ge) {
				if (ge->curve && !have_ec) {
					add_ec(priority_cache);
					have_ec = 1;
				} else if (ge->prime && !have_dh) {
					add_dh(priority_cache);
					have_dh = 1;
				} else if (IS_GROUP_HYBRID(ge) &&
					   !have_hybrid) {
					add_hybrid(priority_cache);
					have_hybrid = 1;
				}

				if (have_dh && have_ec && have_hybrid)
					break;
			}
		}
	}

	for (i = 0; i < priority_cache->_sign_algo.num_priorities; i++) {
		se = _gnutls_sign_to_entry(
			priority_cache->_sign_algo.priorities[i]);
		if (se != NULL &&
		    priority_cache->sigalg.size <
			    sizeof(priority_cache->sigalg.entry) /
				    sizeof(priority_cache->sigalg.entry[0])) {
			/* if the signature algorithm semantics is not
			 * compatible with the protocol's, or the algorithm is
			 * marked as insecure, then skip. */
			if ((se->aid.tls_sem & tls_sig_sem) == 0 ||
			    !_gnutls_sign_is_secure2(
				    se,
				    system_wide_config.allowlisting ?
					    GNUTLS_SIGN_FLAG_ALLOW_INSECURE_REVERTIBLE :
					    0)) {
				continue;
			}
			priority_cache->sigalg
				.entry[priority_cache->sigalg.size++] = se;
		}
	}

	_gnutls_debug_log(
		"added %d protocols, %d ciphersuites, %d sig algos and %d groups into priority list\n",
		priority_cache->protocol.num_priorities,
		priority_cache->cs.size, priority_cache->sigalg.size,
		priority_cache->groups.size);

	if (priority_cache->sigalg.size == 0) {
		/* no signature algorithms; eliminate TLS 1.2 or DTLS 1.2 and later */
		priority_st newp;
		newp.num_priorities = 0;

		/* we need to eliminate TLS 1.2 or DTLS 1.2 and later protocols */
		for (i = 0; i < priority_cache->protocol.num_priorities; i++) {
			if (priority_cache->protocol.priorities[i] <
			    GNUTLS_TLS1_2) {
				newp.priorities[newp.num_priorities++] =
					priority_cache->protocol.priorities[i];
			} else if (priority_cache->protocol.priorities[i] >=
					   GNUTLS_DTLS_VERSION_MIN &&
				   priority_cache->protocol.priorities[i] <
					   GNUTLS_DTLS1_2) {
				newp.priorities[newp.num_priorities++] =
					priority_cache->protocol.priorities[i];
			}
		}
		memcpy(&priority_cache->protocol, &newp, sizeof(newp));
	}

	if (unlikely(priority_cache->protocol.num_priorities == 0)) {
		ret = gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);
		goto out;
	}
#ifndef ENABLE_SSL3
	else if (unlikely(priority_cache->protocol.num_priorities == 1 &&
			  priority_cache->protocol.priorities[0] ==
				  GNUTLS_SSL3)) {
		ret = gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);
		goto out;
	}
#endif

	if (unlikely(priority_cache->cs.size == 0)) {
		ret = gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);
		goto out;
	}

	/* when TLS 1.3 is available we must have groups set; additionally
	 * we require TLS1.2 to be enabled if TLS1.3 is asked for, and
	 * a pre-TLS1.2 protocol is there; that is because servers which
	 * do not support TLS1.3 will negotiate TLS1.2 if seen a TLS1.3 handshake */
	if (unlikely((!have_psk && tlsmax && tlsmax->id >= GNUTLS_TLS1_3 &&
		      priority_cache->groups.size == 0)) ||
	    (!have_tls12 && have_pre_tls12 && have_tls13)) {
		for (i = j = 0; i < priority_cache->protocol.num_priorities;
		     i++) {
			vers = version_to_entry(
				priority_cache->protocol.priorities[i]);
			if (!vers || vers->transport != GNUTLS_STREAM ||
			    !vers->tls13_sem)
				priority_cache->protocol.priorities[j++] =
					priority_cache->protocol.priorities[i];
		}
		priority_cache->protocol.num_priorities = j;
	}

	/* ensure that the verification profile is not lower from the configured */
	if (system_wide_config.verification_profile) {
		gnutls_sec_param_t level = priority_cache->level;
		gnutls_sec_param_t system_wide_level =
			_gnutls_profile_to_sec_level(
				system_wide_config.verification_profile);

		if (level < system_wide_level) {
			ENABLE_PROFILE(priority_cache,
				       system_wide_config.verification_profile);
		}
	}

out:
	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
}

/**
 * gnutls_priority_init2:
 * @priority_cache: is a #gnutls_priority_t type.
 * @priorities: is a string describing priorities (may be %NULL)
 * @err_pos: In case of an error this will have the position in the string the error occurred
 * @flags: zero or %GNUTLS_PRIORITY_INIT_DEF_APPEND
 *
 * Sets priorities for the ciphers, key exchange methods, and macs.
 * The @priority_cache should be deinitialized
 * using gnutls_priority_deinit().
 *
 * The #priorities option allows you to specify a colon
 * separated list of the cipher priorities to enable.
 * Some keywords are defined to provide quick access
 * to common preferences.
 *
 * When @flags is set to %GNUTLS_PRIORITY_INIT_DEF_APPEND then the @priorities
 * specified will be appended to the default options.
 *
 * Unless there is a special need, use the "NORMAL" keyword to
 * apply a reasonable security level, or "NORMAL:%%COMPAT" for compatibility.
 *
 * "PERFORMANCE" means all the "secure" ciphersuites are enabled,
 * limited to 128 bit ciphers and sorted by terms of speed
 * performance.
 *
 * "LEGACY" the NORMAL settings for GnuTLS 3.2.x or earlier. There is
 * no verification profile set, and the allowed DH primes are considered
 * weak today.
 *
 * "NORMAL" means all "secure" ciphersuites. The 256-bit ciphers are
 * included as a fallback only.  The ciphers are sorted by security
 * margin.
 *
 * "PFS" means all "secure" ciphersuites that support perfect forward secrecy.
 * The 256-bit ciphers are included as a fallback only.
 * The ciphers are sorted by security margin.
 *
 * "SECURE128" means all "secure" ciphersuites of security level 128-bit
 * or more.
 *
 * "SECURE192" means all "secure" ciphersuites of security level 192-bit
 * or more.
 *
 * "SUITEB128" means all the NSA SuiteB ciphersuites with security level
 * of 128.
 *
 * "SUITEB192" means all the NSA SuiteB ciphersuites with security level
 * of 192.
 *
 * "NONE" means nothing is enabled.  This disables everything, including protocols.
 *
 * "@@KEYWORD1,KEYWORD2,..." The system administrator imposed settings.
 * The provided keyword(s) will be expanded from a configuration-time
 * provided file - default is: /etc/gnutls/config.
 * Any attributes that follow it, will be appended to the expanded
 * string. If multiple keywords are provided, separated by commas,
 * then the first keyword that exists in the configuration file
 * will be used. At least one of the keywords must exist, or this
 * function will return an error. Typical usage would be to specify
 * an application specified keyword first, followed by "SYSTEM" as
 * a default fallback. e.g., "@LIBVIRT,SYSTEM:!-VERS-SSL3.0" will
 * first try to find a config file entry matching "LIBVIRT", but if
 * that does not exist will use the entry for "SYSTEM". If "SYSTEM"
 * does not exist either, an error will be returned. In all cases,
 * the SSL3.0 protocol will be disabled. The system priority file
 * entries should be formatted as "KEYWORD=VALUE", e.g.,
 * "SYSTEM=NORMAL:+ARCFOUR-128".
 *
 * Special keywords are "!", "-" and "+".
 * "!" or "-" appended with an algorithm will remove this algorithm.
 * "+" appended with an algorithm will add this algorithm.
 *
 * Check the GnuTLS manual section "Priority strings" for detailed
 * information.
 *
 * Examples:
 *
 * "NONE:+VERS-TLS-ALL:+MAC-ALL:+RSA:+AES-128-CBC:+SIGN-ALL:+COMP-NULL"
 *
 * "NORMAL:+ARCFOUR-128" means normal ciphers plus ARCFOUR-128.
 *
 * "SECURE128:-VERS-SSL3.0" means that only secure ciphers are
 * and enabled, SSL3.0 is disabled.
 *
 * "NONE:+VERS-TLS-ALL:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL:+SIGN-RSA-SHA1",
 *
 * "NONE:+VERS-TLS-ALL:+AES-128-CBC:+ECDHE-RSA:+SHA1:+COMP-NULL:+SIGN-RSA-SHA1:+CURVE-SECP256R1",
 *
 * "SECURE256:+SECURE128",
 *
 * Note that "NORMAL:%%COMPAT" is the most compatible mode.
 *
 * A %NULL @priorities string indicates the default priorities to be
 * used (this is available since GnuTLS 3.3.0).
 *
 * Returns: On syntax error %GNUTLS_E_INVALID_REQUEST is returned,
 * %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.6.3
 **/
int gnutls_priority_init2(gnutls_priority_t *priority_cache,
			  const char *priorities, const char **err_pos,
			  unsigned flags)
{
	gnutls_buffer_st buf;
	const char *ep;
	int ret;

	*priority_cache = NULL;
	if (flags & GNUTLS_PRIORITY_INIT_DEF_APPEND) {
		if (priorities == NULL)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		if (err_pos)
			*err_pos = priorities;

		_gnutls_buffer_init(&buf);

		ret = _gnutls_buffer_append_str(
			&buf, _gnutls_default_priority_string);
		if (ret < 0) {
			_gnutls_buffer_clear(&buf);
			return gnutls_assert_val(ret);
		}

		ret = _gnutls_buffer_append_str(&buf, ":");
		if (ret < 0) {
			_gnutls_buffer_clear(&buf);
			return gnutls_assert_val(ret);
		}

		ret = _gnutls_buffer_append_str(&buf, priorities);
		if (ret < 0) {
			_gnutls_buffer_clear(&buf);
			return gnutls_assert_val(ret);
		}

		ret = gnutls_priority_init(priority_cache,
					   (const char *)buf.data, &ep);
		if (ret < 0 && ep != (const char *)buf.data && ep != NULL) {
			ptrdiff_t diff = (ptrdiff_t)ep - (ptrdiff_t)buf.data;
			unsigned hlen =
				strlen(_gnutls_default_priority_string) + 1;

			if (err_pos && diff > hlen) {
				*err_pos = priorities + diff - hlen;
			}
		}
		_gnutls_buffer_clear(&buf);
		return ret;
	} else {
		return gnutls_priority_init(priority_cache, priorities,
					    err_pos);
	}
}

#define PRIO_MATCH(name) \
	c_strncasecmp(&broken_list[i][1], name, sizeof(name) - 1)

/**
 * gnutls_priority_init:
 * @priority_cache: is a #gnutls_priority_t type.
 * @priorities: is a string describing priorities (may be %NULL)
 * @err_pos: In case of an error this will have the position in the string the error occurred
 *
 * For applications that do not modify their crypto settings per release, consider
 * using gnutls_priority_init2() with %GNUTLS_PRIORITY_INIT_DEF_APPEND flag
 * instead. We suggest to use centralized crypto settings handled by the GnuTLS
 * library, and applications modifying the default settings to their needs.
 *
 * This function is identical to gnutls_priority_init2() with zero
 * flags.
 *
 * A %NULL @priorities string indicates the default priorities to be
 * used (this is available since GnuTLS 3.3.0).
 *
 * Returns: On syntax error %GNUTLS_E_INVALID_REQUEST is returned,
 * %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int gnutls_priority_init(gnutls_priority_t *priority_cache,
			 const char *priorities, const char **err_pos)
{
	char *broken_list[MAX_ELEMENTS];
	int broken_list_size = 0, i = 0, j;
	char *darg = NULL;
	unsigned ikeyword_set = 0;
	int algo;
	int ret;
	rmadd_func *fn;
	bulk_rmadd_func *bulk_fn;
	bulk_rmadd_func *bulk_given_fn;
	const cipher_entry_st *centry;
	unsigned resolved_match = 1;

	if (err_pos)
		*err_pos = priorities;

	*priority_cache = gnutls_calloc(1, sizeof(struct gnutls_priority_st));
	if (*priority_cache == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* for now unsafe renegotiation is default on everyone. To be removed
	 * when we make it the default.
	 */
	(*priority_cache)->sr = SR_PARTIAL;
	/* For now TLS 1.3 middlebox compatibility mode is enabled by default.
	 * This will eventually be disabled by default and moved to the %COMPAT
	 * setting.
	 */
	(*priority_cache)->tls13_compat_mode = true;
	(*priority_cache)->min_record_version = 1;
	gnutls_atomic_init(&(*priority_cache)->usage_cnt);

	if (_gnutls_fips_mode_enabled()) {
		(*priority_cache)->force_ext_master_secret = EMS_REQUIRE;
	} else {
		(*priority_cache)->force_ext_master_secret = EMS_REQUEST;
	}

	if (system_wide_config.allowlisting && !priorities) {
		priorities = "@" LEVEL_SYSTEM;
	}
	if (priorities == NULL) {
		priorities = _gnutls_default_priority_string;
		resolved_match = 0;
	}

	darg = _gnutls_resolve_priorities(priorities);
	if (darg == NULL) {
		gnutls_assert();
		goto error;
	}

	if (strcmp(darg, priorities) != 0)
		resolved_match = 0;

	break_list(darg, broken_list, &broken_list_size);
	/* This is our default set of protocol version, certificate types.
	 */
	if (c_strcasecmp(broken_list[0], LEVEL_NONE) != 0) {
		_set_priority(&(*priority_cache)->protocol, protocol_priority);
		_set_priority(&(*priority_cache)->client_ctype,
			      cert_type_priority_default);
		_set_priority(&(*priority_cache)->server_ctype,
			      cert_type_priority_default);
		_set_priority(&(*priority_cache)->_sign_algo,
			      sign_priority_default);
		_set_priority(&(*priority_cache)->_supported_ecc,
			      supported_groups_normal);
		i = 0;
	} else {
		ikeyword_set = 1;
		i = 1;
	}

	for (; i < broken_list_size; i++) {
		if (check_level(broken_list[i], *priority_cache,
				ikeyword_set) != 0) {
			ikeyword_set = 1;
			continue;
		} else if (broken_list[i][0] == '!' ||
			   broken_list[i][0] == '+' ||
			   broken_list[i][0] == '-') {
			if (broken_list[i][0] == '+') {
				fn = prio_add;
				bulk_fn = _add_priority;
				bulk_given_fn = _add_priority;
			} else {
				fn = prio_remove;
				bulk_fn = _clear_priorities;
				bulk_given_fn = _clear_given_priorities;
			}

			if (broken_list[i][0] == '+' &&
			    check_level(&broken_list[i][1], *priority_cache,
					1) != 0) {
				continue;
			} else if ((algo = gnutls_mac_get_id(
					    &broken_list[i][1])) !=
				   GNUTLS_MAC_UNKNOWN) {
				fn(&(*priority_cache)->_mac, algo);
			} else if ((centry = cipher_name_to_entry(
					    &broken_list[i][1])) != NULL) {
				if (_gnutls_cipher_exists(centry->id)) {
					fn(&(*priority_cache)->_cipher,
					   centry->id);
					if (centry->type == CIPHER_BLOCK)
						(*priority_cache)->have_cbc = 1;
				}
			} else if ((algo = _gnutls_kx_get_id(
					    &broken_list[i][1])) !=
				   GNUTLS_KX_UNKNOWN) {
				if (algo != GNUTLS_KX_INVALID)
					fn(&(*priority_cache)->_kx, algo);
			} else if (PRIO_MATCH("VERS-") == 0) {
				if (PRIO_MATCH("VERS-TLS-ALL") == 0) {
					bulk_given_fn(
						&(*priority_cache)->protocol,
						stream_protocol_priority);
				} else if (PRIO_MATCH("VERS-DTLS-ALL") == 0) {
					bulk_given_fn(
						&(*priority_cache)->protocol,
						(bulk_given_fn ==
						 _add_priority) ?
							dtls_protocol_priority :
							dgram_protocol_priority);
				} else if (PRIO_MATCH("VERS-ALL") == 0) {
					bulk_fn(&(*priority_cache)->protocol,
						protocol_priority);
				} else {
					if ((algo = gnutls_protocol_get_id(
						     &broken_list[i][6])) !=
					    GNUTLS_VERSION_UNKNOWN) {
						fn(&(*priority_cache)->protocol,
						   algo);
					} else
						goto error;
				}
			} /* now check if the element is something like -ALGO */
			else if (PRIO_MATCH("COMP-") == 0) {
				/* ignore all compression methods */
				continue;
			} /* now check if the element is something like -ALGO */
			else if (PRIO_MATCH("CURVE-") == 0) {
				if (PRIO_MATCH("CURVE-ALL") == 0) {
					bulk_fn(&(*priority_cache)
							 ->_supported_ecc,
						supported_groups_normal);
				} else {
					if ((algo = gnutls_ecc_curve_get_id(
						     &broken_list[i][7])) !=
					    GNUTLS_ECC_CURVE_INVALID)
						fn(&(*priority_cache)
							    ->_supported_ecc,
						   algo);
					else
						goto error;
				}
			} else if (PRIO_MATCH("GROUP-") == 0) {
				if (PRIO_MATCH("GROUP-ALL") == 0) {
					bulk_fn(&(*priority_cache)
							 ->_supported_ecc,
						supported_groups_normal);
				} else if (PRIO_MATCH("GROUP-DH-ALL") == 0) {
					bulk_given_fn(&(*priority_cache)
							       ->_supported_ecc,
						      _supported_groups_dh);
				} else if (PRIO_MATCH("GROUP-EC-ALL") == 0) {
					bulk_given_fn(&(*priority_cache)
							       ->_supported_ecc,
						      _supported_groups_ecdh);
				} else if (PRIO_MATCH("GROUP-GOST-ALL") == 0) {
					bulk_given_fn(&(*priority_cache)
							       ->_supported_ecc,
						      _supported_groups_gost);
				} else {
					if ((algo = _gnutls_group_get_id(
						     &broken_list[i][7])) !=
					    GNUTLS_GROUP_INVALID)
						fn(&(*priority_cache)
							    ->_supported_ecc,
						   algo);
					else
						goto error;
				}
			} else if (PRIO_MATCH("CTYPE-") == 0) {
				// Certificate types
				if (PRIO_MATCH("CTYPE-ALL") == 0) {
					// Symmetric cert types, all types allowed
					bulk_fn(&(*priority_cache)->client_ctype,
						cert_type_priority_all);
					bulk_fn(&(*priority_cache)->server_ctype,
						cert_type_priority_all);
				} else if (PRIO_MATCH("CTYPE-CLI-") == 0) {
					// Client certificate types
					if (PRIO_MATCH("CTYPE-CLI-ALL") == 0) {
						// All client cert types allowed
						bulk_fn(&(*priority_cache)
								 ->client_ctype,
							cert_type_priority_all);
					} else if ((algo = gnutls_certificate_type_get_id(
							    &broken_list[i]
									[11])) !=
						   GNUTLS_CRT_UNKNOWN) {
						// Specific client cert type allowed
						fn(&(*priority_cache)
							    ->client_ctype,
						   algo);
					} else
						goto error;
				} else if (PRIO_MATCH("CTYPE-SRV-") == 0) {
					// Server certificate types
					if (PRIO_MATCH("CTYPE-SRV-ALL") == 0) {
						// All server cert types allowed
						bulk_fn(&(*priority_cache)
								 ->server_ctype,
							cert_type_priority_all);
					} else if ((algo = gnutls_certificate_type_get_id(
							    &broken_list[i]
									[11])) !=
						   GNUTLS_CRT_UNKNOWN) {
						// Specific server cert type allowed
						fn(&(*priority_cache)
							    ->server_ctype,
						   algo);
					} else
						goto error;
				} else { // Symmetric certificate type
					if ((algo = gnutls_certificate_type_get_id(
						     &broken_list[i][7])) !=
					    GNUTLS_CRT_UNKNOWN) {
						fn(&(*priority_cache)
							    ->client_ctype,
						   algo);
						fn(&(*priority_cache)
							    ->server_ctype,
						   algo);
					} else if (PRIO_MATCH(
							   "CTYPE-OPENPGP") ==
						   0) {
						/* legacy openpgp option - ignore */
						continue;
					} else
						goto error;
				}
			} else if (PRIO_MATCH("SIGN-") == 0) {
				if (PRIO_MATCH("SIGN-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_sign_algo,
						sign_priority_default);
				} else if (PRIO_MATCH("SIGN-GOST-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_sign_algo,
						sign_priority_gost);
				} else {
					if ((algo = gnutls_sign_get_id(
						     &broken_list[i][6])) !=
					    GNUTLS_SIGN_UNKNOWN)
						fn(&(*priority_cache)
							    ->_sign_algo,
						   algo);
					else
						goto error;
				}
			} else if (PRIO_MATCH("MAC-") == 0) {
				if (PRIO_MATCH("MAC-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_mac,
						mac_priority_normal);
				} else if (PRIO_MATCH("MAC-GOST-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_mac,
						mac_priority_gost);
				}
			} else if (PRIO_MATCH("CIPHER-") == 0) {
				if (PRIO_MATCH("CIPHER-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_cipher,
						cipher_priority_normal);
				} else if (PRIO_MATCH("CIPHER-GOST-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_cipher,
						cipher_priority_gost);
				}
			} else if (PRIO_MATCH("KX-") == 0) {
				if (PRIO_MATCH("KX-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_kx,
						kx_priority_secure);
				} else if (PRIO_MATCH("KX-GOST-ALL") == 0) {
					bulk_fn(&(*priority_cache)->_kx,
						kx_priority_gost);
				}
			} else if (PRIO_MATCH("GOST") == 0) {
				bulk_given_fn(
					&(*priority_cache)->_supported_ecc,
					_supported_groups_gost);
				bulk_fn(&(*priority_cache)->_sign_algo,
					sign_priority_gost);
				bulk_fn(&(*priority_cache)->_mac,
					mac_priority_gost);
				bulk_fn(&(*priority_cache)->_cipher,
					cipher_priority_gost);
				bulk_fn(&(*priority_cache)->_kx,
					kx_priority_gost);
			} else
				goto error;
		} else if (broken_list[i][0] == '%') {
			const struct priority_options_st *o;
			/* to add a new option modify
			 * priority_options.gperf */
			o = in_word_set(&broken_list[i][1],
					strlen(&broken_list[i][1]));
			if (o == NULL) {
				goto error;
			}
			o->func(*priority_cache);
		} else
			goto error;
	}

	/* This needs to be done after parsing modifiers, as
	 * tls-session-hash has precedence over modifiers.
	 */
	if (system_wide_config.force_ext_master_secret_set) {
		(*priority_cache)->force_ext_master_secret =
			system_wide_config.force_ext_master_secret;
		(*priority_cache)->_no_ext_master_secret = false;
	}

	ret = set_ciphersuite_list(*priority_cache);
	if (ret < 0) {
		if (err_pos)
			*err_pos = priorities;
		goto error_cleanup;
	}

	gnutls_free(darg);

	return 0;

error:
	if (err_pos != NULL && i < broken_list_size && resolved_match) {
		*err_pos = priorities;
		for (j = 0; j < i; j++) {
			(*err_pos) += strlen(broken_list[j]) + 1;
		}
	}
	ret = GNUTLS_E_INVALID_REQUEST;

error_cleanup:
	gnutls_free(darg);
	gnutls_priority_deinit(*priority_cache);
	*priority_cache = NULL;

	return ret;
}

/**
 * gnutls_priority_deinit:
 * @priority_cache: is a #gnutls_priority_t type.
 *
 * Deinitializes the priority cache.
 **/
void gnutls_priority_deinit(gnutls_priority_t priority_cache)
{
	if (priority_cache == NULL)
		return;

	/* Note that here we care about the following two cases:
	 * 1. Multiple sessions or different threads holding a reference + a global reference
	 * 2. One session holding a reference with a possible global reference
	 *
	 * As such, it will never be that two threads reach the
	 * zero state at the same time, unless the global reference
	 * is cleared too, which is invalid state.
	 */
	if (gnutls_atomic_val(&priority_cache->usage_cnt) == 0) {
		gnutls_atomic_deinit(&priority_cache->usage_cnt);
		gnutls_free(priority_cache);
		return;
	} else {
		gnutls_atomic_decrement(&priority_cache->usage_cnt);
	}
}

/**
 * gnutls_priority_set_direct:
 * @session: is a #gnutls_session_t type.
 * @priorities: is a string describing priorities
 * @err_pos: In case of an error this will have the position in the string the error occurred
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * and macs.  This function avoids keeping a
 * priority cache and is used to directly set string priorities to a
 * TLS session.  For documentation check the gnutls_priority_init().
 *
 * To use a reasonable default, consider using gnutls_set_default_priority(),
 * or gnutls_set_default_priority_append() instead of this function.
 *
 * Returns: On syntax error %GNUTLS_E_INVALID_REQUEST is returned,
 * %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int gnutls_priority_set_direct(gnutls_session_t session, const char *priorities,
			       const char **err_pos)
{
	gnutls_priority_t prio;
	int ret;

	ret = gnutls_priority_init(&prio, priorities, err_pos);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_priority_set(session, prio);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* ensure that the session holds the only reference for the struct */
	gnutls_priority_deinit(prio);

	return 0;
}

/* Breaks a list of "xxx", "yyy", to a character array, of
 * MAX_COMMA_SEP_ELEMENTS size; Note that the given string is modified.
  */
static void break_list(char *list, char *broken_list[MAX_ELEMENTS], int *size)
{
	char *p = list;

	*size = 0;

	do {
		broken_list[*size] = p;

		(*size)++;

		p = strchr(p, ':');
		if (p) {
			*p = 0;
			p++; /* move to next entry and skip white
				 * space.
				 */
			while (*p == ' ')
				p++;
		}
	} while (p != NULL && *size < MAX_ELEMENTS);
}

/**
 * gnutls_set_default_priority:
 * @session: is a #gnutls_session_t type.
 *
 * Sets the default priority on the ciphers, key exchange methods,
 * and macs. This is the recommended method of
 * setting the defaults, in order to promote consistency between applications
 * using GnuTLS, and to allow GnuTLS using applications to update settings
 * in par with the library. For client applications which require
 * maximum compatibility consider calling gnutls_session_enable_compatibility_mode()
 * after this function.
 *
 * For an application to specify additional options to priority string
 * consider using gnutls_set_default_priority_append().
 *
 * To allow a user to override the defaults (e.g., when a user interface
 * or configuration file is available), the functions
 * gnutls_priority_set_direct() or gnutls_priority_set() can
 * be used.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 2.1.4
 **/
int gnutls_set_default_priority(gnutls_session_t session)
{
	return gnutls_priority_set_direct(session, NULL, NULL);
}

/**
 * gnutls_set_default_priority_append:
 * @session: is a #gnutls_session_t type.
 * @add_prio: is a string describing priorities to be appended to default
 * @err_pos: In case of an error this will have the position in the string the error occurred
 * @flags: must be zero
 *
 * Sets the default priority on the ciphers, key exchange methods,
 * and macs with the additional options in @add_prio. This is the recommended method of
 * setting the defaults when only few additional options are to be added. This promotes
 * consistency between applications using GnuTLS, and allows GnuTLS using applications
 * to update settings in par with the library.
 *
 * The @add_prio string should start as a normal priority string, e.g.,
 * '-VERS-TLS-ALL:+VERS-TLS1.3:%%COMPAT' or '%%FORCE_ETM'. That is, it must not start
 * with ':'.
 *
 * To allow a user to override the defaults (e.g., when a user interface
 * or configuration file is available), the functions
 * gnutls_priority_set_direct() or gnutls_priority_set() can
 * be used.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.6.3
 **/
int gnutls_set_default_priority_append(gnutls_session_t session,
				       const char *add_prio,
				       const char **err_pos, unsigned flags)
{
	gnutls_priority_t prio;
	int ret;

	ret = gnutls_priority_init2(&prio, add_prio, err_pos,
				    GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_priority_set(session, prio);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* ensure that the session holds the only reference for the struct */
	gnutls_priority_deinit(prio);

	return 0;
}

/**
 * gnutls_priority_ecc_curve_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available elliptic curves in the priority
 * structure.
 *
 * Deprecated: This function has been replaced by
 * gnutls_priority_group_list() since 3.6.0.
 *
 * Returns: the number of items, or an error code.
 *
 * Since: 3.0
 **/
int gnutls_priority_ecc_curve_list(gnutls_priority_t pcache,
				   const unsigned int **list)
{
	unsigned i;

	if (pcache->_supported_ecc.num_priorities == 0)
		return 0;

	*list = pcache->_supported_ecc.priorities;

	/* to ensure we don't confuse the caller, we do not include
	 * any FFDHE groups. This may return an incomplete list. */
	for (i = 0; i < pcache->_supported_ecc.num_priorities; i++)
		if (pcache->_supported_ecc.priorities[i] > GNUTLS_ECC_CURVE_MAX)
			return i;

	return pcache->_supported_ecc.num_priorities;
}

/**
 * gnutls_priority_group_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available groups in the priority
 * structure.
 *
 * Returns: the number of items, or an error code.
 *
 * Since: 3.6.0
 **/
int gnutls_priority_group_list(gnutls_priority_t pcache,
			       const unsigned int **list)
{
	if (pcache->_supported_ecc.num_priorities == 0)
		return 0;

	*list = pcache->_supported_ecc.priorities;
	return pcache->_supported_ecc.num_priorities;
}

/**
 * gnutls_priority_kx_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available key exchange methods in the priority
 * structure.
 *
 * Returns: the number of items, or an error code.
 * Since: 3.2.3
 **/
int gnutls_priority_kx_list(gnutls_priority_t pcache, const unsigned int **list)
{
	if (pcache->_kx.num_priorities == 0)
		return 0;

	*list = pcache->_kx.priorities;
	return pcache->_kx.num_priorities;
}

/**
 * gnutls_priority_cipher_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available ciphers in the priority
 * structure.
 *
 * Returns: the number of items, or an error code.
 * Since: 3.2.3
 **/
int gnutls_priority_cipher_list(gnutls_priority_t pcache,
				const unsigned int **list)
{
	if (pcache->_cipher.num_priorities == 0)
		return 0;

	*list = pcache->_cipher.priorities;
	return pcache->_cipher.num_priorities;
}

/**
 * gnutls_priority_mac_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available MAC algorithms in the priority
 * structure.
 *
 * Returns: the number of items, or an error code.
 * Since: 3.2.3
 **/
int gnutls_priority_mac_list(gnutls_priority_t pcache,
			     const unsigned int **list)
{
	if (pcache->_mac.num_priorities == 0)
		return 0;

	*list = pcache->_mac.priorities;
	return pcache->_mac.num_priorities;
}

/**
 * gnutls_priority_compression_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available compression method in the priority
 * structure.
 *
 * Returns: the number of methods, or an error code.
 * Since: 3.0
 **/
int gnutls_priority_compression_list(gnutls_priority_t pcache,
				     const unsigned int **list)
{
	static const unsigned int priority[1] = { GNUTLS_COMP_NULL };

	*list = priority;
	return 1;
}

/**
 * gnutls_priority_protocol_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available TLS version numbers in the priority
 * structure.
 *
 * Returns: the number of protocols, or an error code.
 * Since: 3.0
 **/
int gnutls_priority_protocol_list(gnutls_priority_t pcache,
				  const unsigned int **list)
{
	if (pcache->protocol.num_priorities == 0)
		return 0;

	*list = pcache->protocol.priorities;
	return pcache->protocol.num_priorities;
}

/**
 * gnutls_priority_sign_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available signature algorithms in the priority
 * structure.
 *
 * Returns: the number of algorithms, or an error code.
 * Since: 3.0
 **/
int gnutls_priority_sign_list(gnutls_priority_t pcache,
			      const unsigned int **list)
{
	if (pcache->_sign_algo.num_priorities == 0)
		return 0;

	*list = pcache->_sign_algo.priorities;
	return pcache->_sign_algo.num_priorities;
}

/**
 * gnutls_priority_certificate_type_list:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list
 *
 * Get a list of available certificate types in the priority
 * structure.
 *
 * As of version 3.6.4 this function is an alias for
 * gnutls_priority_certificate_type_list2 with the target parameter
 * set to:
 * - GNUTLS_CTYPE_SERVER, if the %SERVER_PRECEDENCE option is set
 * - GNUTLS_CTYPE_CLIENT, otherwise.
 *
 * Returns: the number of certificate types, or an error code.
 * Since: 3.0
 **/
int gnutls_priority_certificate_type_list(gnutls_priority_t pcache,
					  const unsigned int **list)
{
	gnutls_ctype_target_t target = pcache->server_precedence ?
					       GNUTLS_CTYPE_SERVER :
					       GNUTLS_CTYPE_CLIENT;

	return gnutls_priority_certificate_type_list2(pcache, list, target);
}

/**
 * gnutls_priority_certificate_type_list2:
 * @pcache: is a #gnutls_priority_t type.
 * @list: will point to an integer list.
 * @target: is a #gnutls_ctype_target_t type. Valid arguments are
 *   GNUTLS_CTYPE_CLIENT and GNUTLS_CTYPE_SERVER
 *
 * Get a list of available certificate types for the given target
 * in the priority structure.
 *
 * Returns: the number of certificate types, or an error code.
 *
 * Since: 3.6.4
 **/
int gnutls_priority_certificate_type_list2(gnutls_priority_t pcache,
					   const unsigned int **list,
					   gnutls_ctype_target_t target)
{
	switch (target) {
	case GNUTLS_CTYPE_CLIENT:
		if (pcache->client_ctype.num_priorities > 0) {
			*list = pcache->client_ctype.priorities;
			return pcache->client_ctype.num_priorities;
		}
		break;
	case GNUTLS_CTYPE_SERVER:
		if (pcache->server_ctype.num_priorities > 0) {
			*list = pcache->server_ctype.priorities;
			return pcache->server_ctype.num_priorities;
		}
		break;
	default:
		// Invalid target given
		gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	// Found a matching target but non of them had any ctypes set
	return 0;
}

/**
 * gnutls_priority_string_list:
 * @iter: an integer counter starting from zero
 * @flags: one of %GNUTLS_PRIORITY_LIST_INIT_KEYWORDS, %GNUTLS_PRIORITY_LIST_SPECIAL
 *
 * Can be used to iterate all available priority strings.
 * Due to internal implementation details, there are cases where this
 * function can return the empty string. In that case that string should be ignored.
 * When no strings are available it returns %NULL.
 *
 * Returns: a priority string
 * Since: 3.4.0
 **/
const char *gnutls_priority_string_list(unsigned iter, unsigned int flags)
{
	if (flags & GNUTLS_PRIORITY_LIST_INIT_KEYWORDS) {
		if (iter >= (sizeof(pgroups) / sizeof(pgroups[0])) - 1)
			return NULL;
		return pgroups[iter].name;
	} else if (flags & GNUTLS_PRIORITY_LIST_SPECIAL) {
		if (iter >= (sizeof(wordlist) / sizeof(wordlist[0])) - 1)
			return NULL;
		return wordlist[iter].name;
	}
	return NULL;
}

bool _gnutls_config_is_ktls_enabled(void)
{
	return system_wide_config.ktls_enabled;
}

bool _gnutls_config_is_rsa_pkcs1_encrypt_allowed(void)
{
	return system_wide_config.allow_rsa_pkcs1_encrypt;
}

int _gnutls_config_set_certificate_compression_methods(gnutls_session_t session)
{
	int ret;
	size_t n_algs = 0;

	/* Don't override manually set compression methods */
	if (_gnutls_compress_certificate_is_set(session) ||
	    system_wide_config.cert_comp_algs[0] == 0)
		return 0;

	while (system_wide_config.cert_comp_algs[n_algs] != 0)
		n_algs++;

	ret = gnutls_compress_certificate_set_methods(
		session, system_wide_config.cert_comp_algs, n_algs);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

const char *_gnutls_config_get_p11_provider_path(void)
{
	return system_wide_config.p11_provider_path;
}

const char *_gnutls_config_get_p11_provider_pin(void)
{
	return system_wide_config.p11_provider_pin;
}

/*
 * high-level interface for overriding configuration files
 */

static inline bool /* not locking system_wide_config */
system_wide_config_is_malleable(void)
{
	if (!system_wide_config.allowlisting) {
		_gnutls_audit_log(NULL, "allowlisting is not enabled!\n");
		return false;
	}
	if (system_wide_config.priority_string) {
		_gnutls_audit_log(NULL, "priority strings have already been "
					"initialized!\n");
		return false;
	}
	return true;
}

/**
 * gnutls_digest_set_secure:
 * @dig: is a digest algorithm
 * @secure: whether to mark the digest algorithm secure
 *
 * Modify the previous system wide setting that marked @dig as secure
 * or insecure. This only has effect when the algorithm is enabled
 * through the allowlisting mode in the configuration file, or when
 * the setting is modified with a prior call to this function.
 *
 * Since: 3.7.3
 */
int gnutls_digest_set_secure(gnutls_digest_algorithm_t dig, unsigned int secure)
{
#ifndef DISABLE_SYSTEM_CONFIG
	int ret;
	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(ret);
	}
	if (!system_wide_config_is_malleable()) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (secure) {
		ret = cfg_hashes_add(&system_wide_config, dig);
	} else {
		ret = cfg_hashes_remove(&system_wide_config, dig);
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
#else
	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#endif
}

/**
 * gnutls_sign_set_secure:
 * @sign: the sign algorithm
 * @secure: whether to mark the sign algorithm secure
 *
 * Modify the previous system wide setting that marked @sign as secure
 * or insecure.  Calling this function is allowed
 * only if allowlisting mode is set in the configuration file,
 * and only if the system-wide TLS priority string
 * has not been initialized yet.
 * The intended usage is to provide applications with a way
 * to expressly deviate from the distribution or site defaults
 * inherited from the configuration file.
 * The modification is composable with further modifications
 * performed through the priority string mechanism.
 *
 * This function is not thread-safe and is intended to be called
 * in the main thread at the beginning of the process execution.
 *
 * Even when @secure is true, @sign is not marked as secure for the
 * use in certificates.  Use gnutls_sign_set_secure_for_certs() to
 * mark it secure as well for certificates.
 *
 * Returns: 0 on success or negative error code otherwise.
 *
 * Since: 3.7.3
 */
int gnutls_sign_set_secure(gnutls_sign_algorithm_t sign, unsigned int secure)
{
#ifndef DISABLE_SYSTEM_CONFIG
	int ret;
	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(ret);
	}
	if (!system_wide_config_is_malleable()) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (secure) {
		ret = cfg_sigs_add(&system_wide_config, sign);
	} else {
		ret = cfg_sigs_remove(&system_wide_config, sign);
		if (ret < 0) {
			(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
			return ret;
		}
		/* irregularity, distrusting also means distrusting for certs */
		ret = cfg_sigs_for_cert_remove(&system_wide_config, sign);
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
#else
	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#endif
}

/**
 * gnutls_sign_set_secure_for_certs:
 * @sign: the sign algorithm
 * @secure: whether to mark the sign algorithm secure for certificates
 *
 * Modify the previous system wide setting that marked @sign as secure
 * or insecure for the use in certificates.  Calling this function is allowed
 * only if allowlisting mode is set in the configuration file,
 * and only if the system-wide TLS priority string
 * has not been initialized yet.
 * The intended usage is to provide applications with a way
 * to expressly deviate from the distribution or site defaults
 * inherited from the configuration file.
 * The modification is composable with further modifications
 * performed through the priority string mechanism.
 *
 * This function is not thread-safe and is intended to be called
 * in the main thread at the beginning of the process execution.

 * When @secure is true, @sign is marked as secure for any use unlike
 * gnutls_sign_set_secure().  Otherwise, it is marked as insecure only
 * for the use in certificates.  Use gnutls_sign_set_secure() to mark
 * it insecure for any uses.
 *
 * Returns: 0 on success or negative error code otherwise.
 *
 * Since: 3.7.3
 */
int gnutls_sign_set_secure_for_certs(gnutls_sign_algorithm_t sign,
				     unsigned int secure)
{
#ifndef DISABLE_SYSTEM_CONFIG
	int ret;
	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(ret);
	}
	if (!system_wide_config_is_malleable()) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (secure) {
		/* irregularity, trusting for certs means trusting in general */
		ret = cfg_sigs_add(&system_wide_config, sign);
		if (ret < 0) {
			(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
			return ret;
		}
		ret = cfg_sigs_for_cert_add(&system_wide_config, sign);
	} else {
		ret = cfg_sigs_for_cert_remove(&system_wide_config, sign);
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
#else
	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#endif
}

/**
 * gnutls_protocol_set_enabled:
 * @version: is a (gnutls) version number
 * @enabled: whether to enable the protocol
 *
 * Control the previous system-wide setting that marked @version as
 * enabled or disabled.  Calling this function is allowed
 * only if allowlisting mode is set in the configuration file,
 * and only if the system-wide TLS priority string
 * has not been initialized yet.
 * The intended usage is to provide applications with a way
 * to expressly deviate from the distribution or site defaults
 * inherited from the configuration file.
 * The modification is composable with further modifications
 * performed through the priority string mechanism.
 *
 * This function is not thread-safe and is intended to be called
 * in the main thread at the beginning of the process execution.
 *
 * Returns: 0 on success or negative error code otherwise.
 *
 * Since: 3.7.3
 */
int /* allowlisting-only */
/* not thread-safe */
gnutls_protocol_set_enabled(gnutls_protocol_t version, unsigned int enabled)
{
#ifndef DISABLE_SYSTEM_CONFIG
	int ret;
	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(ret);
	}
	if (!system_wide_config_is_malleable()) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (enabled) {
		ret = cfg_versions_add(&system_wide_config, version);
	} else {
		ret = cfg_versions_remove(&system_wide_config, version);
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
#else
	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#endif
}

/**
 * gnutls_ecc_curve_set_enabled:
 * @curve: is an ECC curve
 * @enabled: whether to enable the curve
 *
 * Modify the previous system wide setting that marked @curve as
 * enabled or disabled.  Calling this function is allowed
 * only if allowlisting mode is set in the configuration file,
 * and only if the system-wide TLS priority string
 * has not been initialized yet.
 * The intended usage is to provide applications with a way
 * to expressly deviate from the distribution or site defaults
 * inherited from the configuration file.
 * The modification is composable with further modifications
 * performed through the priority string mechanism.
 *
 * This function is not thread-safe and is intended to be called
 * in the main thread at the beginning of the process execution.
 *
 * Returns: 0 on success or negative error code otherwise.
 *
 * Since: 3.7.3
 */
int gnutls_ecc_curve_set_enabled(gnutls_ecc_curve_t curve, unsigned int enabled)
{
#ifndef DISABLE_SYSTEM_CONFIG
	int ret;
	ret = gnutls_rwlock_wrlock(&system_wide_config_rwlock);
	if (ret < 0) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(ret);
	}
	if (!system_wide_config_is_malleable()) {
		(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (enabled) {
		ret = cfg_ecc_curves_add(&system_wide_config, curve);
	} else {
		ret = cfg_ecc_curves_remove(&system_wide_config, curve);
	}

	(void)gnutls_rwlock_unlock(&system_wide_config_rwlock);
	return ret;
#else
	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#endif
}
