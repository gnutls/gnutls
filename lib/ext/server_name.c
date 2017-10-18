/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
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

#include "gnutls_int.h"
#include "auth.h"
#include "errors.h"
#include "num.h"
#include "str.h"
#include <ext/server_name.h>

static int _gnutls_server_name_recv_params(gnutls_session_t session,
					   const uint8_t * data,
					   size_t data_size);
static int _gnutls_server_name_send_params(gnutls_session_t session,
					   gnutls_buffer_st * extdata);

static int _gnutls_server_name_unpack(gnutls_buffer_st * ps,
				      gnutls_ext_priv_data_t * _priv);
static int _gnutls_server_name_pack(gnutls_ext_priv_data_t _priv,
				    gnutls_buffer_st * ps);
static void _gnutls_server_name_deinit_data(gnutls_ext_priv_data_t priv);

int
_gnutls_server_name_set_raw(gnutls_session_t session,
		       gnutls_server_name_type_t type,
		       const void *name, size_t name_length);

const extension_entry_st ext_mod_server_name = {
	.name = "Server Name Indication",
	.type = GNUTLS_EXTENSION_SERVER_NAME,
	.parse_type = GNUTLS_EXT_MANDATORY,

	.recv_func = _gnutls_server_name_recv_params,
	.send_func = _gnutls_server_name_send_params,
	.pack_func = _gnutls_server_name_pack,
	.unpack_func = _gnutls_server_name_unpack,
	.deinit_func = _gnutls_server_name_deinit_data,
	.cannot_be_overriden = 1
};

/*
 * In case of a server: if a NAME_DNS extension type is received then
 * it stores into the session the value of NAME_DNS. The server may
 * use gnutls_ext_get_server_name(), in order to access it.
 *
 * In case of a client: If a proper NAME_DNS extension type is found
 * in the session then it sends the extension to the peer.
 *
 */
static int
_gnutls_server_name_recv_params(gnutls_session_t session,
				const uint8_t * data, size_t _data_size)
{
	const unsigned char *p;
	uint16_t len, type;
	ssize_t data_size = _data_size;
	server_name_ext_st *priv = NULL;
	gnutls_ext_priv_data_t epriv;

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		DECR_LENGTH_RET(data_size, 2, GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
		len = _gnutls_read_uint16(data);
		if (len == 0)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		if (len != data_size) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		p = data + 2;

		while (data_size > 0) {
			DECR_LEN(data_size, 1);
			type = *p;
			p++;

			DECR_LEN(data_size, 2);
			len = _gnutls_read_uint16(p);
			p += 2;

			if (len == 0) {
				_gnutls_handshake_log
				    ("HSK[%p]: Received server name size of zero\n",
				     session);
				return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
			}

			DECR_LEN(data_size, len);

			if (type == 0) { /* NAME_DNS */
				if (!_gnutls_dnsname_is_valid((char*)p, len))
					return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

				if (len < MAX_SERVER_NAME_SIZE) {
					priv = gnutls_calloc(1, sizeof(*priv));
					if (priv == NULL) {
						gnutls_assert();
						return GNUTLS_E_MEMORY_ERROR;
					}

					memcpy(priv->name, p, len);
					priv->name[len] = 0;

					priv->name_length = len;
					priv->type =
					    GNUTLS_NAME_DNS;

					epriv = priv;
					_gnutls_ext_set_session_data(session,
						     GNUTLS_EXTENSION_SERVER_NAME,
						     epriv);
					return 0;
				}
			}
			p += len;

		}


	}

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
_gnutls_server_name_send_params(gnutls_session_t session,
				gnutls_buffer_st * extdata)
{
	int total_size = 0, ret;
	server_name_ext_st *priv;
	gnutls_ext_priv_data_t epriv;

	ret =
	    _gnutls_ext_get_session_data(session,
					 GNUTLS_EXTENSION_SERVER_NAME,
					 &epriv);
	if (ret < 0)
		return 0;

	/* this function sends the client extension data (dnsname)
	 */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		priv = epriv;

		if (priv->name_length == 0 || priv->type != GNUTLS_NAME_DNS)
			return 0;

		/* uint8_t + uint16_t + size
		 */
		total_size = 2 + 1 + 2 + priv->name_length;

		/* UINT16: write total size of all names
		 */
		ret =
		    _gnutls_buffer_append_prefix(extdata, 16,
						 total_size - 2);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* UINT8: type of this extension
		 * UINT16: size of the first name
		 * LEN: the actual server name.
		 */
		ret =
		    _gnutls_buffer_append_prefix(extdata, 8, 0);
		if (ret < 0)
			return gnutls_assert_val(ret);

		_gnutls_debug_log("HSK[%p]: sent server name: '%s'\n", session, priv->name);

		ret =
		    _gnutls_buffer_append_data_prefix
			    (extdata, 16,
			     priv->name, priv->name_length);
		if (ret < 0)
			return gnutls_assert_val(ret);
	} else {
		return 0;
	}

	return total_size;
}

/**
 * gnutls_server_name_get:
 * @session: is a #gnutls_session_t type.
 * @data: will hold the data
 * @data_length: will hold the data length. Must hold the maximum size of data.
 * @type: will hold the server name indicator type
 * @indx: is the index of the server_name
 *
 * This function will allow you to get the name indication (if any), a
 * client has sent.  The name indication may be any of the enumeration
 * gnutls_server_name_type_t.
 *
 * If @type is GNUTLS_NAME_DNS, then this function is to be used by
 * servers that support virtual hosting, and the data will be a null
 * terminated IDNA ACE string (prior to GnuTLS 3.4.0 it was a UTF-8 string).
 *
 * If @data has not enough size to hold the server name
 * GNUTLS_E_SHORT_MEMORY_BUFFER is returned, and @data_length will
 * hold the required size.
 *
 * @indx is used to retrieve more than one server names (if sent by
 * the client).  The first server name has an index of 0, the second 1
 * and so on.  If no name with the given index exists
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, on UTF-8
 *  decoding error %GNUTLS_E_IDNA_ERROR is returned, otherwise a negative
 *  error code is returned.
 **/
int
gnutls_server_name_get(gnutls_session_t session, void *data,
		       size_t * data_length,
		       unsigned int *type, unsigned int indx)
{
	char *_data = data;
	server_name_ext_st *priv;
	int ret;
	gnutls_ext_priv_data_t epriv;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (indx != 0)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	ret =
	    _gnutls_ext_get_session_data(session,
					 GNUTLS_EXTENSION_SERVER_NAME,
					 &epriv);
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	priv = epriv;

	if (priv->name_length == 0) {
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	*type = priv->type;

	if (*data_length >	/* greater since we need one extra byte for the null */
	    priv->name_length) {
		*data_length = priv->name_length;
		memcpy(data, priv->name, *data_length);

		if (*type == GNUTLS_NAME_DNS)	/* null terminate */
			_data[(*data_length)] = 0;

	} else {
		*data_length = priv->name_length + 1;
		ret = GNUTLS_E_SHORT_MEMORY_BUFFER;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	return ret;
}

/* This does not do any conversion not perform any check */
int
_gnutls_server_name_set_raw(gnutls_session_t session,
		       gnutls_server_name_type_t type,
		       const void *name, size_t name_length)
{
	int ret;
	server_name_ext_st *priv;
	gnutls_ext_priv_data_t epriv;
	int set = 0;

	if (name_length >= MAX_SERVER_NAME_SIZE) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	ret =
	    _gnutls_ext_get_session_data(session,
					 GNUTLS_EXTENSION_SERVER_NAME,
					 &epriv);
	if (ret < 0) {
		set = 1;
	}

	if (set != 0) {
		priv = gnutls_calloc(1, sizeof(*priv));
		if (priv == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		epriv = priv;
	} else
		priv = epriv;

	priv->type = type;

	if (name_length > 0) {
		memcpy(priv->name, name, name_length);
		priv->name[name_length] = 0;
	}
	priv->name_length = name_length;

	if (set != 0)
		_gnutls_ext_set_session_data(session,
					     GNUTLS_EXTENSION_SERVER_NAME,
					     epriv);

	return 0;
}

/**
 * gnutls_server_name_set:
 * @session: is a #gnutls_session_t type.
 * @type: specifies the indicator type
 * @name: is a string that contains the server name.
 * @name_length: holds the length of name excluding the terminating null byte
 *
 * This function is to be used by clients that want to inform (via a
 * TLS extension mechanism) the server of the name they connected to.
 * This should be used by clients that connect to servers that do
 * virtual hosting.
 *
 * The value of @name depends on the @type type.  In case of
 * %GNUTLS_NAME_DNS, a UTF-8 null-terminated domain name string,
 * without the trailing dot, is expected.
 *
 * IPv4 or IPv6 addresses are not permitted to be set by this function.
 * If the function is called with a name of @name_length zero it will clear
 * all server names set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/
int
gnutls_server_name_set(gnutls_session_t session,
		       gnutls_server_name_type_t type,
		       const void *name, size_t name_length)
{
	int ret;
	gnutls_datum_t idn_name = {NULL,0};

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (name_length == 0) { /* unset extension */
		_gnutls_ext_unset_session_data(session, GNUTLS_EXTENSION_SERVER_NAME);
		return 0;
	}

	ret = gnutls_idna_map(name, name_length, &idn_name, 0);
	if (ret < 0) {
		 _gnutls_debug_log("unable to convert name %s to IDNA2008 format\n", (char*)name);
		 return ret;
	}

	name = idn_name.data;
	name_length = idn_name.size;

	ret = _gnutls_server_name_set_raw(session, type, name, name_length);
	gnutls_free(idn_name.data);

	return ret;
}

static void _gnutls_server_name_deinit_data(gnutls_ext_priv_data_t priv)
{
	gnutls_free(priv);
}

static int
_gnutls_server_name_pack(gnutls_ext_priv_data_t epriv,
			 gnutls_buffer_st * ps)
{
	server_name_ext_st *priv = epriv;
	int ret;

	BUFFER_APPEND_NUM(ps, priv->type);
	BUFFER_APPEND_PFX4(ps, priv->name,
			   priv->name_length);
	return 0;
}

static int
_gnutls_server_name_unpack(gnutls_buffer_st * ps,
			   gnutls_ext_priv_data_t * _priv)
{
	server_name_ext_st *priv;
	int ret;
	gnutls_ext_priv_data_t epriv;

	priv = gnutls_calloc(1, sizeof(*priv));
	if (priv == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	BUFFER_POP_NUM(ps, priv->type);
	BUFFER_POP_NUM(ps, priv->name_length);
	if (priv->name_length >=
	    sizeof(priv->name)) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	BUFFER_POP(ps, priv->name,
		   priv->name_length);
	priv->name[priv->name_length] = 0;

	epriv = priv;
	*_priv = epriv;

	return 0;

      error:
	gnutls_free(priv);
	return ret;
}

unsigned _gnutls_server_name_matches_resumed(gnutls_session_t session)
{
	server_name_ext_st *priv1, *priv2;
	int ret;
	gnutls_ext_priv_data_t epriv;

	ret =
	    _gnutls_ext_get_session_data(session,
					 GNUTLS_EXTENSION_SERVER_NAME,
					 &epriv);
	if (ret < 0) /* no server name in this session */
		priv1 = NULL;
	else
		priv1 = epriv;

	ret =
	    _gnutls_ext_get_resumed_session_data(session,
						 GNUTLS_EXTENSION_SERVER_NAME,
						 &epriv);
	if (ret < 0) /* no server name in extensions */
		priv2 = NULL;
	else
		priv2 = epriv;

	if (priv1 == NULL || priv2 == NULL) {
		if (priv1 == priv2)
			return 1;
		else
			return 0;
	}

	if (priv1->name_length != priv2->name_length)
		return 0;

	if (memcmp(priv1->name, priv2->name, priv1->name_length) != 0)
		return 0;

	return 1;
}
