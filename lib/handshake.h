/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 * Copyright (C) 2017 Red Hat, Inc.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "errors.h"
#include "record.h"
#include <assert.h>

/* The following two macros are used in the handshake state machines; the first
 * (IMED_RET) accounts for non-fatal errors and re-entry to current state, while
 * the latter invalidates the handshake on any error (to be used by functions
 * that are not expected to return non-fatal errors).
 */
#define IMED_RET( str, ret, allow_alert) do { \
	if (ret < 0) { \
		/* EAGAIN and INTERRUPTED are always non-fatal */ \
		if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) \
			return ret; \
		if (ret == GNUTLS_E_GOT_APPLICATION_DATA && session->internals.initial_negotiation_completed != 0) \
			return ret; \
		if (session->internals.handshake_suspicious_loops < 16) { \
			if (ret == GNUTLS_E_LARGE_PACKET) { \
				session->internals.handshake_suspicious_loops++; \
				return ret; \
			} \
			/* a warning alert might interrupt handshake */ \
			if (allow_alert != 0 && ret==GNUTLS_E_WARNING_ALERT_RECEIVED) { \
				session->internals.handshake_suspicious_loops++; \
				return ret; \
			} \
		} \
		gnutls_assert(); \
		/* do not allow non-fatal errors at this point */ \
		if (gnutls_error_is_fatal(ret) == 0) ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR); \
		session_invalidate(session); \
		_gnutls_handshake_hash_buffers_clear(session); \
		return ret; \
	} } while (0)

#define IMED_RET_FATAL( str, ret, allow_alert) do { \
	if (ret < 0) { \
		gnutls_assert(); \
		if (gnutls_error_is_fatal(ret) == 0) \
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR); \
		session_invalidate(session); \
		_gnutls_handshake_hash_buffers_clear(session); \
		return ret; \
	} } while (0)

int _gnutls_send_handshake(gnutls_session_t session, mbuffer_st * bufel,
			   gnutls_handshake_description_t type);
int _gnutls_recv_hello_request(gnutls_session_t session, void *data,
			       uint32_t data_size);
int _gnutls_recv_handshake(gnutls_session_t session,
			   gnutls_handshake_description_t type,
			   unsigned int optional, gnutls_buffer_st * buf);

int
_gnutls_send_handshake2(gnutls_session_t session, mbuffer_st * bufel,
		        gnutls_handshake_description_t type, unsigned queue_only);

int _gnutls_generate_session_id(uint8_t * session_id, uint8_t * len);
int _gnutls_gen_server_random(gnutls_session_t session, int version);
void _gnutls_set_client_random(gnutls_session_t session, uint8_t * rnd);

ssize_t _gnutls_send_change_cipher_spec(gnutls_session_t session, int again);

int _gnutls_send_server_hello(gnutls_session_t session, int again);

int _gnutls_find_pk_algos_in_ciphersuites(uint8_t * data, int datalen);
int _gnutls_server_select_suite(gnutls_session_t session, uint8_t * data,
				unsigned int datalen, unsigned int scsv_only);

int _gnutls_negotiate_version(gnutls_session_t session,
			      uint8_t major, uint8_t minor,
			      unsigned allow_tls13);
int _gnutls_user_hello_func(gnutls_session_t session,
			    uint8_t major, uint8_t minor);

void _gnutls_handshake_hash_buffers_clear(gnutls_session_t session);

int _gnutls13_handshake_hash_buffers_synth(gnutls_session_t session,
					   const mac_entry_st *prf,
					   unsigned client);

#define STATE session->internals.handshake_state
#define FINAL_STATE session->internals.handshake_final_state
/* This returns true if we have got there
 * before (and not finished due to an interrupt).
 */
#define AGAIN(target) (STATE==target?1:0)
#define FAGAIN(target) (FINAL_STATE==target?1:0)
#define AGAIN2(state, target) (state==target?1:0)

inline static int handshake_remaining_time(gnutls_session_t session)
{
	if (session->internals.handshake_endtime) {
		struct timespec now;
		gettime(&now);

		if (now.tv_sec < session->internals.handshake_endtime)
			return (session->internals.handshake_endtime -
				now.tv_sec) * 1000;
		else
			return gnutls_assert_val(GNUTLS_E_TIMEDOUT);
	}
	return 0;
}

/* Returns non-zero if the present credentials are sufficient for TLS1.3 negotiation.
 * This is to be used in client side only. On server side, it is allowed to start
 * without credentials.
 */
inline static unsigned have_creds_for_tls13(gnutls_session_t session)
{
	assert(session->security_parameters.entity == GNUTLS_CLIENT);
	if (_gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE) != NULL ||
	    _gnutls_get_cred(session, GNUTLS_CRD_PSK) != NULL)
		return 1;

	return 0;
}

int _gnutls_handshake_get_session_hash(gnutls_session_t session, gnutls_datum_t *shash);

int _gnutls_check_id_for_change(gnutls_session_t session);
int _gnutls_check_if_cert_hash_is_same(gnutls_session_t session, gnutls_certificate_credentials_t cred);

#define EARLY_TRAFFIC_LABEL "c e traffic"
#define EXT_BINDER_LABEL "ext binder"
#define RES_BINDER_LABEL "res binder"
#define EARLY_EXPORTER_MASTER_LABEL "e exp master"
#define HANDSHAKE_CLIENT_TRAFFIC_LABEL "c hs traffic"
#define HANDSHAKE_SERVER_TRAFFIC_LABEL "s hs traffic"
#define DERIVED_LABEL "derived"
#define APPLICATION_CLIENT_TRAFFIC_LABEL "c ap traffic"
#define APPLICATION_SERVER_TRAFFIC_LABEL "s ap traffic"
#define APPLICATION_TRAFFIC_UPDATE "traffic upd"
#define EXPORTER_MASTER_LABEL "exp master"
#define RMS_MASTER_LABEL "res master"
#define EXPORTER_LABEL "exp master"
#define RES_LABEL "res master"

int _gnutls_call_hook_func(gnutls_session_t session,
			   gnutls_handshake_description_t type,
			   int post, unsigned incoming,
			   const uint8_t *data, unsigned data_size);

int _gnutls_run_verify_callback(gnutls_session_t session, unsigned int side);
int _gnutls_recv_finished(gnutls_session_t session);
int _gnutls_send_finished(gnutls_session_t session, int again);

int _gnutls13_handshake_client(gnutls_session_t session);
int _gnutls13_handshake_server(gnutls_session_t session);

int
_gnutls13_recv_hello_retry_request(gnutls_session_t session,
				   gnutls_buffer_st *buf);

int
_gnutls13_recv_async_handshake(gnutls_session_t session);

#endif
