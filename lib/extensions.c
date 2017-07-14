/*
 * Copyright (C) 2001-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson
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

/* Functions that relate to the TLS hello extension parsing.
 * Hello extensions are packets appended in the TLS hello packet, and
 * allow for extra functionality.
 */

#include "gnutls_int.h"
#include "extensions.h"
#include "errors.h"
#include "ext/max_record.h"
#include <ext/server_name.h>
#include <ext/srp.h>
#include <ext/heartbeat.h>
#include <ext/session_ticket.h>
#include <ext/safe_renegotiation.h>
#include <ext/signature.h>
#include <ext/safe_renegotiation.h>
#include <ext/ecc.h>
#include <ext/status_request.h>
#include <ext/ext_master_secret.h>
#include <ext/srtp.h>
#include <ext/alpn.h>
#include <ext/dumbfw.h>
#include <ext/etm.h>
#include <num.h>

static void
unset_ext_data(gnutls_session_t session, const struct extension_entry_st *, unsigned idx);

static int ext_register(extension_entry_st * mod);
static void unset_resumed_ext_data(gnutls_session_t session, const struct extension_entry_st *, unsigned idx);

static extension_entry_st const *extfunc[MAX_EXT_TYPES+1] = {
	&ext_mod_max_record_size,
	&ext_mod_ext_master_secret,
	&ext_mod_etm,
#ifdef ENABLE_OCSP
	&ext_mod_status_request,
#endif
	&ext_mod_server_name,
	&ext_mod_sr,
#ifdef ENABLE_SRP
	&ext_mod_srp,
#endif
#ifdef ENABLE_HEARTBEAT
	&ext_mod_heartbeat,
#endif
#ifdef ENABLE_SESSION_TICKETS
	&ext_mod_session_ticket,
#endif
	&ext_mod_supported_ecc,
	&ext_mod_supported_ecc_pf,
	&ext_mod_sig,
#ifdef ENABLE_DTLS_SRTP
	&ext_mod_srtp,
#endif
#ifdef ENABLE_ALPN
	&ext_mod_alpn,
#endif
	/* This must be the last extension registered.
	 */
	&ext_mod_dumbfw,
	NULL
};

static const extension_entry_st *
_gnutls_ext_ptr(gnutls_session_t session, uint16_t type, gnutls_ext_parse_type_t parse_type)
{
	unsigned i;
	const extension_entry_st *e;

	for (i=0;i<session->internals.rexts_size;i++) {
		if (session->internals.rexts[i].type == type) {
			e = &session->internals.rexts[i];
			goto done;
		}
	}

	for (i = 0; extfunc[i] != NULL; i++) {
		if (extfunc[i]->type == type) {
			e = extfunc[i];
			goto done;
		}
	}

	return NULL;
done:
	if (parse_type == GNUTLS_EXT_ANY || e->parse_type == parse_type) {
		return e;
	} else {
		return NULL;
	}
}


/**
 * gnutls_ext_get_name:
 * @ext: is a TLS extension numeric ID
 *
 * Convert a TLS extension numeric ID to a printable string.
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified cipher, or %NULL.
 **/
const char *gnutls_ext_get_name(unsigned int ext)
{
	size_t i;

	for (i = 0; extfunc[i] != NULL; i++)
		if (extfunc[i]->type == ext)
			return extfunc[i]->name;

	return NULL;
}

/* Checks if the extension @type provided has been requested
 * by us (in client side). In that case it returns zero, 
 * otherwise a negative error value.
 */
int
_gnutls_extension_list_check(gnutls_session_t session, uint16_t type)
{
	unsigned i;

	for (i = 0; i < session->internals.used_exts_size; i++) {
		if (type == session->internals.used_exts[i]->type)
			return 0;
	}

	return GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION;
}

/* Adds the extension we want to send in the extensions list.
 * This list is used in client side to check whether the (later) received
 * extensions are the ones we requested.
 *
 * In server side, this list is used to ensure we don't send
 * extensions that we didn't receive a corresponding value.
 *
 * Returns zero if failed, non-zero on success.
 */
static unsigned _gnutls_extension_list_add(gnutls_session_t session, const struct extension_entry_st *e, unsigned check_dup)
{
	unsigned i;

	if (check_dup) {
		for (i=0;i<session->internals.used_exts_size;i++) {
			if (session->internals.used_exts[i]->type == e->type)
				return 0;
		}
	}

	if (session->internals.used_exts_size < MAX_EXT_TYPES) {
		session->internals.used_exts[session->
						   internals.used_exts_size]
		    = e;
		session->internals.used_exts_size++;
		return 1;
	} else {
		_gnutls_handshake_log
		    ("extensions: Increase MAX_EXT_TYPES\n");
		return 0;
	}
}

void _gnutls_extension_list_add_sr(gnutls_session_t session)
{
	_gnutls_extension_list_add(session, &ext_mod_sr, 1);
}


int
_gnutls_parse_extensions(gnutls_session_t session,
			 gnutls_ext_parse_type_t parse_type,
			 const uint8_t * data, int data_size)
{
	int next, ret;
	int pos = 0;
	uint16_t type;
	const uint8_t *sdata;
	const extension_entry_st *ext;
	uint16_t size;

#ifdef DEBUG
	int i;

	if (session->security_parameters.entity == GNUTLS_CLIENT)
		for (i = 0; i < session->internals.extensions_sent_size;
		     i++) {
			_gnutls_handshake_log
			    ("EXT[%d]: expecting extension '%s'\n",
			     session,
			     gnutls_ext_get_name(session->internals.
							extensions_sent
							[i]));
		}
#endif
	if (data_size == 0)
		return 0;

	DECR_LENGTH_RET(data_size, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
	next = _gnutls_read_uint16(data);
	pos += 2;

	DECR_LENGTH_RET(data_size, next, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	if (next == 0 && data_size == 0) /* field is present, but has zero length? Ignore it. */
		return 0;
	else if (data_size > 0) /* forbid unaccounted data */
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	do {
		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		type = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		if (session->security_parameters.entity == GNUTLS_CLIENT) {
			if ((ret =
			     _gnutls_extension_list_check(session, type)) < 0) {
				_gnutls_debug_log("EXT[%p]: Received unexpected extension '%s/%d'\n", session,
						gnutls_ext_get_name(type), (int)type);
				gnutls_assert();
				return ret;
			}
		}

		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		size = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		DECR_LENGTH_RET(next, size, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		sdata = &data[pos];
		pos += size;

		ext = _gnutls_ext_ptr(session, type, parse_type);
		if (ext == NULL || ext->recv_func == NULL) {
			_gnutls_handshake_log
			    ("EXT[%p]: Ignoring extension '%s/%d'\n", session,
			     gnutls_ext_get_name(type), type);

			continue;
		}

		if (session->security_parameters.entity == GNUTLS_SERVER) {
			ret = _gnutls_extension_list_add(session, ext, 1);
			if (ret == 0)
				return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
		}

		_gnutls_handshake_log
		    ("EXT[%p]: Parsing extension '%s/%d' (%d bytes)\n",
		     session, gnutls_ext_get_name(type), type,
		     size);

		if ((ret = ext->recv_func(session, sdata, size)) < 0) {
			gnutls_assert();
			return ret;
		}
	}
	while (next > 2);

	/* forbid leftovers */
	if (next > 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	return 0;

}

static
int send_extension(gnutls_session_t session, const extension_entry_st *p,
		   gnutls_buffer_st *extdata, gnutls_ext_parse_type_t parse_type)
{
	int size_pos, appended, ret;
	size_t size_prev;

	if (p->send_func == NULL)
		return 0;

	if (parse_type != GNUTLS_EXT_ANY
	    && p->parse_type != parse_type)
		return 0;

	/* ensure we don't send something twice (i.e, overriden extensions in
	 * client), and ensure we are sending only what we received in server. */
	ret = _gnutls_extension_list_check(session, p->type);

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		if (ret < 0) /* not advertized */
			return 0;
	} else {
		if (ret == 0) /* already sent */
			return 0;
	}

	ret = _gnutls_buffer_append_prefix(extdata, 16, p->type);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size_pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size_prev = extdata->length;
	ret = p->send_func(session, extdata);
	if (ret < 0 && ret != GNUTLS_E_INT_RET_0) {
		return gnutls_assert_val(ret);
	}

	/* returning GNUTLS_E_INT_RET_0 means to send an empty
	 * extension of this type.
	 */
	appended = extdata->length - size_prev;

	if (appended > 0 || ret == GNUTLS_E_INT_RET_0) {
		if (ret == GNUTLS_E_INT_RET_0)
			appended = 0;

		/* write the real size */
		_gnutls_write_uint16(appended,
				     &extdata->data[size_pos]);

		/* add this extension to the extension list
		 */
		if (session->security_parameters.entity == GNUTLS_CLIENT)
			_gnutls_extension_list_add(session, p, 0);

		_gnutls_handshake_log
			    ("EXT[%p]: Sending extension %s (%d bytes)\n",
			     session, p->name, appended);
	} else if (appended == 0)
		extdata->length -= 4;	/* reset type and size */

	return 0;
}

int
_gnutls_gen_extensions(gnutls_session_t session,
		       gnutls_buffer_st * extdata,
		       gnutls_ext_parse_type_t parse_type)
{
	int size;
	int pos, ret;
	size_t i, init_size = extdata->length;

	pos = extdata->length;	/* we will store length later on */

	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	for (i=0; i < session->internals.rexts_size; i++) {
		ret = send_extension(session, &session->internals.rexts[i], extdata, parse_type);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* send_extension() ensures we don't send duplicates, in case
	 * of overriden extensions */
	for (i = 0; extfunc[i] != NULL; i++) {
		ret = send_extension(session, extfunc[i], extdata, parse_type);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* remove any initial data, and the size of the header */
	size = extdata->length - init_size - 2;

	if (size > UINT16_MAX) /* sent too many extensions */
		return gnutls_assert_val(GNUTLS_E_HANDSHAKE_TOO_LARGE);

	if (size > 0)
		_gnutls_write_uint16(size, &extdata->data[pos]);
	else if (size == 0)
		extdata->length -= 2;	/* the length bytes */

	return size;
}

/* Global deinit and init of global extensions */
int _gnutls_ext_init(void)
{
	return GNUTLS_E_SUCCESS;
}

void _gnutls_ext_deinit(void)
{
	unsigned i;
	for (i = 0; extfunc[i] != NULL; i++) {
		if (extfunc[i]->free_struct != 0) {
			gnutls_free((void*)extfunc[i]->name);
			gnutls_free((void*)extfunc[i]);
			extfunc[i] = NULL;
		}
	}
}

static
int ext_register(extension_entry_st * mod)
{
	unsigned i = 0;

	while(extfunc[i] != NULL) {
		i++;
	}

	if (i >= MAX_EXT_TYPES-1) {
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	extfunc[i] = mod;
	extfunc[i+1] = NULL;
	return GNUTLS_E_SUCCESS;
}

/* Packing of extension data (for use in resumption) */
static int pack_extension(gnutls_session_t session, const extension_entry_st *extp,
			  gnutls_buffer_st *packed)
{
	int ret;
	int size_offset;
	int cur_size;
	gnutls_ext_priv_data_t data;
	int rval = 0;

	ret =
	    _gnutls_ext_get_session_data(session, extp->type,
					 &data);
	if (ret >= 0 && extp->pack_func != NULL) {
		BUFFER_APPEND_NUM(packed, extp->type);

		size_offset = packed->length;
		BUFFER_APPEND_NUM(packed, 0);

		cur_size = packed->length;

		ret = extp->pack_func(data, packed);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		rval = 1;
		/* write the actual size */
		_gnutls_write_uint32(packed->length - cur_size,
				     packed->data + size_offset);
	}

	return rval;
}

int _gnutls_ext_pack(gnutls_session_t session, gnutls_buffer_st *packed)
{
	unsigned int i;
	int ret;
	int total_exts_pos;
	int exts = 0;

	total_exts_pos = packed->length;
	BUFFER_APPEND_NUM(packed, 0);

	for (i = 0; i < session->internals.used_exts_size; i++) {
		ret = pack_extension(session, session->internals.used_exts[i], packed);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (ret > 0)
			exts++;
	}

	_gnutls_write_uint32(exts, packed->data + total_exts_pos);

	return 0;
}

static void
_gnutls_ext_set_resumed_session_data(gnutls_session_t session,
				     uint16_t type,
				     gnutls_ext_priv_data_t data)
{
	int i;
	const struct extension_entry_st *ext;

	ext = _gnutls_ext_ptr(session, type, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.ext_data[i].type == type
		    || (!session->internals.ext_data[i].resumed_set && !session->internals.ext_data[i].set)) {

			if (session->internals.ext_data[i].resumed_set != 0)
				unset_resumed_ext_data(session, ext, i);

			session->internals.ext_data[i].type = type;
			session->internals.ext_data[i].resumed_priv = data;
			session->internals.ext_data[i].resumed_set = 1;
			return;
		}
	}
}

int _gnutls_ext_unpack(gnutls_session_t session, gnutls_buffer_st * packed)
{
	int i, ret;
	gnutls_ext_priv_data_t data;
	int max_exts = 0;
	uint16_t type;
	int size_for_type, cur_pos;
	const struct extension_entry_st *ext;

	BUFFER_POP_NUM(packed, max_exts);
	for (i = 0; i < max_exts; i++) {
		BUFFER_POP_NUM(packed, type);
		BUFFER_POP_NUM(packed, size_for_type);

		cur_pos = packed->length;

		ext = _gnutls_ext_ptr(session, type, GNUTLS_EXT_ANY);
		if (ext == NULL || ext->unpack_func == NULL) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		ret = ext->unpack_func(packed, &data);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* verify that unpack read the correct bytes */
		cur_pos = cur_pos - packed->length;
		if (cur_pos /* read length */  != size_for_type) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		_gnutls_ext_set_resumed_session_data(session, type, data);
	}

	return 0;

      error:
	return ret;
}

static void
unset_ext_data(gnutls_session_t session, const struct extension_entry_st *ext, unsigned idx)
{
	if (session->internals.ext_data[idx].set == 0)
		return;

	if (ext && ext->deinit_func && session->internals.ext_data[idx].priv != NULL)
		ext->deinit_func(session->internals.ext_data[idx].priv);
	session->internals.ext_data[idx].set = 0;
}

void
_gnutls_ext_unset_session_data(gnutls_session_t session,
				uint16_t type)
{
	int i;
	const struct extension_entry_st *ext;

	ext = _gnutls_ext_ptr(session, type, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.ext_data[i].type == type) {
			unset_ext_data(session, ext, i);
			return;
		}
	}
}

static void unset_resumed_ext_data(gnutls_session_t session, const struct extension_entry_st *ext, unsigned idx)
{
	if (session->internals.ext_data[idx].resumed_set == 0)
		return;

	if (ext && ext->deinit_func && session->internals.ext_data[idx].resumed_priv) {
		ext->deinit_func(session->internals.ext_data[idx].resumed_priv);
	}
	session->internals.ext_data[idx].resumed_set = 0;
}

/* Deinitializes all data that are associated with TLS extensions.
 */
void _gnutls_ext_free_session_data(gnutls_session_t session)
{
	unsigned int i;
	const struct extension_entry_st *ext;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (!session->internals.ext_data[i].set && !session->internals.ext_data[i].resumed_set)
			continue;

		ext = _gnutls_ext_ptr(session, session->internals.ext_data[i].type, GNUTLS_EXT_ANY);

		unset_ext_data(session, ext, i);
		unset_resumed_ext_data(session, ext, i);
	}
}

/* This function allows an extension to store data in the current session
 * and retrieve them later on. We use functions instead of a pointer to a
 * private pointer, to allow API additions by individual extensions.
 */
void
_gnutls_ext_set_session_data(gnutls_session_t session, uint16_t type,
			     gnutls_ext_priv_data_t data)
{
	unsigned int i;
	const struct extension_entry_st *ext;

	ext = _gnutls_ext_ptr(session, type, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.ext_data[i].type == type ||
		    (!session->internals.ext_data[i].set && !session->internals.ext_data[i].resumed_set)) {

			if (session->internals.ext_data[i].set != 0) {
				unset_ext_data(session, ext, i);
			}
			session->internals.ext_data[i].type = type;
			session->internals.ext_data[i].priv = data;
			session->internals.ext_data[i].set = 1;
			return;
		}
	}
}

int
_gnutls_ext_get_session_data(gnutls_session_t session,
			     uint16_t type, gnutls_ext_priv_data_t * data)
{
	int i;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.ext_data[i].set != 0 &&
		    session->internals.ext_data[i].type == type)
		{
			*data =
			    session->internals.ext_data[i].priv;
			return 0;
		}
	}
	return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
}

int
_gnutls_ext_get_resumed_session_data(gnutls_session_t session,
				     uint16_t type,
				     gnutls_ext_priv_data_t * data)
{
	int i;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.ext_data[i].resumed_set != 0
		    && session->internals.ext_data[i].type == type) {
			*data =
			    session->internals.ext_data[i].resumed_priv;
			return 0;
		}
	}
	return GNUTLS_E_INVALID_REQUEST;
}

/**
 * gnutls_ext_register:
 * @name: the name of the extension to register
 * @type: the numeric id of the extension
 * @parse_type: the parse type of the extension (see gnutls_ext_parse_type_t)
 * @recv_func: a function to receive the data
 * @send_func: a function to send the data
 * @deinit_func: a function deinitialize any private data
 * @pack_func: a function which serializes the extension's private data (used on session packing for resumption)
 * @unpack_func: a function which will deserialize the extension's private data
 *
 * This function will register a new extension type. The extension will remain
 * registered until gnutls_global_deinit() is called. If the extension type
 * is already registered then %GNUTLS_E_ALREADY_REGISTERED will be returned.
 *
 * Each registered extension can store temporary data into the gnutls_session_t
 * structure using gnutls_ext_set_data(), and they can be retrieved using
 * gnutls_ext_get_data().
 *
 * This function is not thread safe.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.4.0
 **/
int 
gnutls_ext_register(const char *name, int type, gnutls_ext_parse_type_t parse_type,
		    gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, 
		    gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func,
		    gnutls_ext_unpack_func unpack_func)
{
	extension_entry_st *tmp_mod;
	int ret;
	unsigned i;

	for (i = 0; extfunc[i] != NULL; i++) {
		if (extfunc[i]->type == type)
			return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
	}

	tmp_mod = gnutls_calloc(1, sizeof(*tmp_mod));
	if (tmp_mod == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	tmp_mod->name = gnutls_strdup(name);
	tmp_mod->free_struct = 1;
	tmp_mod->type = type;
	tmp_mod->parse_type = parse_type;
	tmp_mod->recv_func = recv_func;
	tmp_mod->send_func = send_func;
	tmp_mod->deinit_func = deinit_func;
	tmp_mod->pack_func = pack_func;
	tmp_mod->unpack_func = unpack_func;

	ret = ext_register(tmp_mod);
	if (ret < 0) {
		gnutls_free((void*)tmp_mod->name);
		gnutls_free(tmp_mod);
	}
	return ret;
}

/**
 * gnutls_session_ext_register:
 * @session: the session for which this extension will be set
 * @name: the name of the extension to register
 * @type: the numeric id of the extension
 * @parse_type: the parse type of the extension (see gnutls_ext_parse_type_t)
 * @recv_func: a function to receive the data
 * @send_func: a function to send the data
 * @deinit_func: a function deinitialize any private data
 * @pack_func: a function which serializes the extension's private data (used on session packing for resumption)
 * @unpack_func: a function which will deserialize the extension's private data
 * @flags: must be zero or flags from %gnutls_ext_flags_t
 *
 * This function will register a new extension type. The extension will be
 * only usable within the registered session. If the extension type
 * is already registered then %GNUTLS_E_ALREADY_REGISTERED will be returned,
 * unless the flag %GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL is specified. The latter
 * flag when specified can be used to override certain extensions introduced
 * after 3.6.0. It is expected to be used by applications which handle
 * custom extensions that are not currently supported in GnuTLS, but direct
 * support for them may be added in the future.
 *
 * Each registered extension can store temporary data into the gnutls_session_t
 * structure using gnutls_ext_set_data(), and they can be retrieved using
 * gnutls_ext_get_data().
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.5.5
 **/
int 
gnutls_session_ext_register(gnutls_session_t session,
			    const char *name, int type, gnutls_ext_parse_type_t parse_type,
			    gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, 
			    gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func,
			    gnutls_ext_unpack_func unpack_func, unsigned flags)
{
	extension_entry_st tmp_mod;
	extension_entry_st *exts;
	unsigned i;

	/* reject handling any extensions which modify the TLS handshake
	 * in any way, or are mapped to an exported API. */
	for (i = 0; extfunc[i] != NULL; i++) {
		if (extfunc[i]->type == type) {
			if (!(flags & GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL)) {
				return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
			} else if (extfunc[i]->cannot_be_overriden) {
				return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
			}
			break;
		}
	}

	memset(&tmp_mod, 0, sizeof(extension_entry_st));
	tmp_mod.free_struct = 1;
	tmp_mod.type = type;
	tmp_mod.parse_type = parse_type;
	tmp_mod.recv_func = recv_func;
	tmp_mod.send_func = send_func;
	tmp_mod.deinit_func = deinit_func;
	tmp_mod.pack_func = pack_func;
	tmp_mod.unpack_func = unpack_func;

	exts = gnutls_realloc(session->internals.rexts, (session->internals.rexts_size+1)*sizeof(*exts));
	if (exts == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	session->internals.rexts = exts;

	memcpy(&session->internals.rexts[session->internals.rexts_size], &tmp_mod, sizeof(extension_entry_st));
	session->internals.rexts_size++;

	return 0;
}

/**
 * gnutls_ext_set_data:
 * @session: a #gnutls_session_t opaque pointer
 * @type: the numeric id of the extension
 * @data: the private data to set
 *
 * This function allows an extension handler to store data in the current session
 * and retrieve them later on. The set data will be deallocated using
 * the gnutls_ext_deinit_data_func.
 *
 * Since: 3.4.0
 **/
void
gnutls_ext_set_data(gnutls_session_t session, unsigned type,
		    gnutls_ext_priv_data_t data)
{
	_gnutls_ext_set_session_data(session, type, data);
}

/**
 * gnutls_ext_get_data:
 * @session: a #gnutls_session_t opaque pointer
 * @type: the numeric id of the extension
 * @data: a pointer to the private data to retrieve
 *
 * This function retrieves any data previously stored with gnutls_ext_set_data().
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.4.0
 **/
int
gnutls_ext_get_data(gnutls_session_t session,
		    unsigned type, gnutls_ext_priv_data_t *data)
{
	return _gnutls_ext_get_session_data(session, type, data);
}
