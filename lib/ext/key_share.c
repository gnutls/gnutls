/*
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

/* This file contains the code the Key Share TLS 1.3 extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include <ext/ecc.h>
#include <state.h>
#include <num.h>
#include <algorithms.h>
#include "auth/psk.h"
#include "auth/cert.h"
#include "auth/anon.h"
#include "../ecc.h"
#include "../algorithms.h"
#include "pk.h"

static int key_share_recv_params(gnutls_session_t session,
					     const uint8_t * data,
					     size_t data_size);
static int key_share_send_params(gnutls_session_t session,
					     gnutls_buffer_st * extdata);

const extension_entry_st ext_mod_key_share = {
	.name = "Key Share",
	.id = GNUTLS_EXTENSION_KEY_SHARE,
	.parse_type = _GNUTLS_EXT_TLS_POST_CS,

	.recv_func = key_share_recv_params,
	.send_func = key_share_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL,
	.cannot_be_overriden = 1
};

/*
 * Generates key exchange parameters, and stores them in
 * session->key.kshare_*_params.
 *
 * struct {
 *     NamedGroup group;
 *     opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 *
 */
static int client_gen_key_share(gnutls_session_t session, const gnutls_group_entry_st *group, gnutls_buffer_st *extdata)
{
	gnutls_datum_t tmp = {NULL, 0};
	int ret;

	if (group->pk != GNUTLS_PK_EC && group->pk != GNUTLS_PK_ECDH_X25519 &&
	    group->pk != GNUTLS_PK_DH) {
		_gnutls_debug_log("Cannot send key share for group %s!\n", group->name);
		return GNUTLS_E_INT_RET_0;
	}

	_gnutls_handshake_log("EXT[%p]: sending key share for %s\n", session, group->name);

	ret =
	    _gnutls_buffer_append_prefix(extdata, 16, group->tls_id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (group->pk == GNUTLS_PK_EC) {
		gnutls_pk_params_release(&session->key.kshare_ecdh_params);
		gnutls_pk_params_init(&session->key.kshare_ecdh_params);

		ret = _gnutls_pk_generate_keys(group->pk, group->curve,
						&session->key.kshare_ecdh_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_ecc_ansi_x962_export(group->curve,
				session->key.kshare_ecdh_params.params[ECC_X],
				session->key.kshare_ecdh_params.params[ECC_Y],
				&tmp);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret =
		    _gnutls_buffer_append_data_prefix(extdata, 16, tmp.data, tmp.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		session->key.kshare_ecdh_params.algo = group->pk;
		session->key.kshare_ecdh_params.curve = group->curve;

		ret = 0;

	} else if (group->pk == GNUTLS_PK_ECDH_X25519) {
		gnutls_pk_params_release(&session->key.kshare_ecdhx_params);
		gnutls_pk_params_init(&session->key.kshare_ecdhx_params);

		ret = _gnutls_pk_generate_keys(group->pk, group->curve,
						&session->key.kshare_ecdhx_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret =
		    _gnutls_buffer_append_data_prefix(extdata, 16,
				session->key.kshare_ecdhx_params.raw_pub.data,
				session->key.kshare_ecdhx_params.raw_pub.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		session->key.kshare_ecdhx_params.algo = group->pk;
		session->key.kshare_ecdhx_params.curve = group->curve;

		ret = 0;

	} else if (group->pk == GNUTLS_PK_DH) {
		/* we need to initialize the group parameters first */
		gnutls_pk_params_release(&session->key.kshare_dh_params);
		gnutls_pk_params_init(&session->key.kshare_dh_params);

		ret = _gnutls_mpi_init_scan_nz(&session->key.kshare_dh_params.params[DH_G],
			group->generator->data, group->generator->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_mpi_init_scan_nz(&session->key.kshare_dh_params.params[DH_P],
			group->prime->data, group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		session->key.kshare_dh_params.algo = group->pk;
		session->key.kshare_dh_params.qbits = *group->q_bits;
		session->key.kshare_dh_params.params_nr = 3; /* empty q */

		ret = _gnutls_pk_generate_keys(group->pk, 0, &session->key.kshare_dh_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret =
		    _gnutls_buffer_append_prefix(extdata, 16, group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_fixed_mpi(extdata, session->key.kshare_dh_params.params[DH_Y],
				group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = 0;
	}

 cleanup:
	gnutls_free(tmp.data);
	return ret;
}

/*
 * Sends server key exchange parameters
 *
 */
static int server_gen_key_share(gnutls_session_t session, const gnutls_group_entry_st *group, gnutls_buffer_st *extdata)
{
	gnutls_datum_t tmp = {NULL, 0};
	int ret;

	if (group->pk != GNUTLS_PK_EC && group->pk != GNUTLS_PK_ECDH_X25519 &&
	    group->pk != GNUTLS_PK_DH) {
		_gnutls_debug_log("Cannot send key share for group %s!\n", group->name);
		return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
	}

	_gnutls_handshake_log("EXT[%p]: sending key share for %s\n", session, group->name);

	ret =
	    _gnutls_buffer_append_prefix(extdata, 16, group->tls_id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (group->pk == GNUTLS_PK_EC) {
		ret = _gnutls_ecc_ansi_x962_export(group->curve,
				session->key.kshare_ecdh_params.params[ECC_X],
				session->key.kshare_ecdh_params.params[ECC_Y],
				&tmp);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret =
		    _gnutls_buffer_append_data_prefix(extdata, 16, tmp.data, tmp.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;

	} else if (group->pk == GNUTLS_PK_ECDH_X25519) {
		ret =
		    _gnutls_buffer_append_data_prefix(extdata, 16,
				session->key.kshare_ecdhx_params.raw_pub.data,
				session->key.kshare_ecdhx_params.raw_pub.size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = 0;

	} else if (group->pk == GNUTLS_PK_DH) {
		ret =
		    _gnutls_buffer_append_prefix(extdata, 16, group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_fixed_mpi(extdata, session->key.kshare_dh_params.params[DH_Y],
				group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = 0;
	}

 cleanup:
	gnutls_free(tmp.data);
	return ret;
}

/* Generates shared key and stores it in session->key.key
 */
static int
server_use_key_share(gnutls_session_t session, const gnutls_group_entry_st *group,
		     const uint8_t * data, size_t data_size)
{
	const gnutls_ecc_curve_entry_st *curve;
	int ret;

	if (group->pk == GNUTLS_PK_EC) {
		gnutls_pk_params_st pub;

		gnutls_pk_params_release(&session->key.kshare_ecdh_params);
		gnutls_pk_params_init(&session->key.kshare_ecdh_params);

		curve = _gnutls_ecc_curve_get_params(group->curve);

		gnutls_pk_params_init(&pub);

		if (curve->size*2+1 != data_size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* generate our key */
		ret = _gnutls_pk_generate_keys(curve->pk, curve->id, &session->key.kshare_ecdh_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key */
		ret = _gnutls_ecc_ansi_x962_import(data, data_size,
						   &pub.params[ECC_X],
						   &pub.params[ECC_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;
		pub.curve = curve->id;
		pub.params_nr = 2;

		/* generate shared */
		ret = _gnutls_pk_derive_tls13(curve->pk, &session->key.key, &session->key.kshare_ecdh_params, &pub);
		gnutls_pk_params_release(&pub);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}

		ret = 0;

	} else if (group->pk == GNUTLS_PK_ECDH_X25519) {
		gnutls_pk_params_st pub;

		gnutls_pk_params_release(&session->key.kshare_ecdhx_params);
		gnutls_pk_params_init(&session->key.kshare_ecdhx_params);

		curve = _gnutls_ecc_curve_get_params(group->curve);

		if (curve->size != data_size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* generate our key */
		ret = _gnutls_pk_generate_keys(curve->pk, curve->id, &session->key.kshare_ecdhx_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		pub.algo = group->pk;
		pub.curve = curve->id;

		pub.raw_pub.data = (void*)data;
		pub.raw_pub.size = data_size;

		/* We don't mask the MSB in the final byte as required
		 * by RFC7748. This will be done internally by nettle 3.3 or later.
		 */
		ret = _gnutls_pk_derive_tls13(curve->pk, &session->key.key, &session->key.kshare_ecdhx_params, &pub);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}

		ret = 0;

	} else if (group->pk == GNUTLS_PK_DH) {
		gnutls_pk_params_st pub;

		/* we need to initialize the group parameters first */
		gnutls_pk_params_release(&session->key.kshare_dh_params);
		gnutls_pk_params_init(&session->key.kshare_dh_params);

		if (data_size != group->prime->size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* set group params */
		ret = _gnutls_mpi_init_scan_nz(&session->key.kshare_dh_params.params[DH_G],
			group->generator->data, group->generator->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_mpi_init_scan_nz(&session->key.kshare_dh_params.params[DH_P],
			group->prime->data, group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		session->key.kshare_dh_params.algo = GNUTLS_PK_DH;
		session->key.kshare_dh_params.qbits = *group->q_bits;
		session->key.kshare_dh_params.params_nr = 3; /* empty q */

		/* generate our keys */
		ret = _gnutls_pk_generate_keys(group->pk, 0, &session->key.kshare_dh_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		ret = _gnutls_mpi_init_scan_nz(&pub.params[DH_Y],
			data, data_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(GNUTLS_PK_DH, &session->key.key, &session->key.kshare_dh_params, &pub);
		_gnutls_mpi_release(pub.params[DH_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = 0;
	} else {
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}

	_gnutls_debug_log("EXT[%p]: server generated %s shared key\n", session, group->name);

	return ret;
}

/* Generates shared key and stores it in session->key.key
 */
static int
client_use_key_share(gnutls_session_t session, const gnutls_group_entry_st *group,
		     const uint8_t * data, size_t data_size)
{
	const gnutls_ecc_curve_entry_st *curve;
	int ret;

	if (group->pk == GNUTLS_PK_EC) {
		gnutls_pk_params_st pub;

		curve = _gnutls_ecc_curve_get_params(group->curve);

		gnutls_pk_params_init(&pub);

		if (curve->size*2+1 != data_size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* read the server's public key */
		ret = _gnutls_ecc_ansi_x962_import(data, data_size,
						   &pub.params[ECC_X],
						   &pub.params[ECC_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;
		pub.curve = curve->id;
		pub.params_nr = 2;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(curve->pk, &session->key.key, &session->key.kshare_ecdh_params, &pub);
		gnutls_pk_params_release(&pub);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}

		ret = 0;

	} else if (group->pk == GNUTLS_PK_ECDH_X25519) {
		gnutls_pk_params_st pub;

		curve = _gnutls_ecc_curve_get_params(group->curve);

		if (curve->size != data_size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		pub.algo = group->pk;
		pub.curve = curve->id;

		pub.raw_pub.data = (void*)data;
		pub.raw_pub.size = data_size;

		/* We don't mask the MSB in the final byte as required
		 * by RFC7748. This will be done internally by nettle 3.3 or later.
		 */
		ret = _gnutls_pk_derive_tls13(curve->pk, &session->key.key, &session->key.kshare_ecdhx_params, &pub);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}

		ret = 0;

	} else if (group->pk == GNUTLS_PK_DH) {
		gnutls_pk_params_st pub;

		if (data_size != group->prime->size)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		ret = _gnutls_mpi_init_scan_nz(&pub.params[DH_Y],
			data, data_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(GNUTLS_PK_DH, &session->key.key, &session->key.kshare_dh_params, &pub);
		_gnutls_mpi_release(pub.params[DH_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = 0;
	} else {
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}

	_gnutls_debug_log("EXT[%p]: client generated %s shared key\n", session, group->name);

	return ret;
}

static int
key_share_recv_params(gnutls_session_t session,
		      const uint8_t * data, size_t _data_size)
{
	int ret;
	ssize_t data_size = _data_size;
	ssize_t size;
	unsigned gid, used_share = 0;
	const version_entry_st *ver;
	const gnutls_group_entry_st *group, *sgroup = NULL;

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		ver = get_version(session);
		if (ver == NULL || ver->key_shares == 0)
			return gnutls_assert_val(0);

		DECR_LEN(data_size, 2);
		size = _gnutls_read_uint16(data);
		data += 2;

		if (data_size != size)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		while(data_size > 0) {
			DECR_LEN(data_size, 2);
			gid = _gnutls_read_uint16(data);
			data += 2;

			DECR_LEN(data_size, 2);
			size = _gnutls_read_uint16(data);
			data += 2;

			DECR_LEN(data_size, size);

			/* at this point we have already negotiated a group;
			 * find the group's share. */
			group = _gnutls_tls_id_to_group(gid);

			if (group != NULL)
				_gnutls_handshake_log("EXT[%p]: Received key share for %s\n", session, group->name);

			if (group != NULL) {
				if (group == session->internals.cand_ec_group)
					sgroup = group;
				else if (group == session->internals.cand_dh_group)
					sgroup = group;
			}

			if (sgroup == NULL) {
				data += size;
				continue;
			}

			_gnutls_session_group_set(session, sgroup);
			_gnutls_handshake_log("EXT[%p]: Selected group %s\n", session, sgroup->name);

			ret = server_use_key_share(session, sgroup, data, size);
			if (ret < 0) {
				return gnutls_assert_val(ret);
			}

			used_share = 1;
			break;
		}

		if (used_share == 0) {
			/* we signal for hello-retry-request */
			return gnutls_assert_val(GNUTLS_E_NO_COMMON_KEY_SHARE);
		}

	} else { /* Client */
		ver = get_version(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		DECR_LEN(data_size, 2);
		gid = _gnutls_read_uint16(data);
		data += 2;

		DECR_LEN(data_size, 2);
		size = _gnutls_read_uint16(data);
		data+=2;

		if (data_size != size)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		group = _gnutls_tls_id_to_group(gid);
		if (group == NULL)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* check if we support it */
		ret = _gnutls_session_supports_group(session, group->id);
		if (ret < 0) {
			_gnutls_handshake_log("EXT[%p]: received share for %s which is disabled\n", session, group->name);
			return gnutls_assert_val(ret);
		}

		_gnutls_session_group_set(session, group);

		ret = client_use_key_share(session, group, data, size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	return 0;
}

#define MAX_GROUPS 3
/* returns data_size or a negative number on failure
 */
static int
key_share_send_params(gnutls_session_t session,
		      gnutls_buffer_st * extdata)
{
	unsigned i;
	int ret;
	unsigned char *lengthp;
	unsigned int cur_length;
	gnutls_pk_algorithm_t selected_groups[MAX_GROUPS];
	unsigned int generated = 0;
	const gnutls_group_entry_st *group;
	const version_entry_st *ver;

	/* this extension is only being sent on client side */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		ver = _gnutls_version_max(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return gnutls_assert_val(0);

		/* write the total length later */
		lengthp = &extdata->data[extdata->length];

		ret =
		    _gnutls_buffer_append_prefix(extdata, 16, 0);
		if (ret < 0)
			return gnutls_assert_val(ret);

		cur_length = extdata->length;

		/* generate key shares for out top-3 groups
		 * if they are of different PK type. */
		for (i=0;i<session->internals.priorities->groups.size;i++) {
			group = session->internals.priorities->groups.entry[i];

			if (generated == 1 && group->pk == selected_groups[0])
				continue;
			else if (generated == 2 && (group->pk == selected_groups[1] || group->pk == selected_groups[0]))
				continue;

			selected_groups[generated] = group->pk;

			ret = client_gen_key_share(session, group, extdata);
			if (ret == GNUTLS_E_INT_RET_0)
				continue; /* no key share for this algorithm */
			if (ret < 0)
				return gnutls_assert_val(ret);

			generated++;

			if (generated >= MAX_GROUPS)
				break;
		}

		/* copy actual length */
		_gnutls_write_uint16(extdata->length - cur_length, lengthp);

	} else { /* server */
		ver = get_version(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return gnutls_assert_val(0);

		group = get_group(session);
		if (unlikely(group == NULL))
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		ret = server_gen_key_share(session, group, extdata);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	return 0;
}

