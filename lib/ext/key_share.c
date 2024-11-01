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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* This file contains the code the Key Share TLS 1.3 extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include "ext/supported_groups.h"
#include "state.h"
#include "num.h"
#include "algorithms.h"
#include "auth/psk.h"
#include "auth/cert.h"
#include "handshake.h"
#include "../ecc.h"
#include "../algorithms.h"
#include "pk.h"

#define KYBER768_PUBLIC_KEY_SIZE 1184
#define KYBER768_CIPHERTEXT_SIZE 1088

static int key_share_recv_params(gnutls_session_t session, const uint8_t *data,
				 size_t data_size);
static int key_share_send_params(gnutls_session_t session,
				 gnutls_buffer_st *extdata);

const hello_ext_entry_st ext_mod_key_share = {
	.name = "Key Share",
	.tls_id = 51,
	.gid = GNUTLS_EXTENSION_KEY_SHARE,
	.client_parse_point = _GNUTLS_EXT_TLS_POST_CS,
	.server_parse_point = _GNUTLS_EXT_TLS_POST_CS,
	.validity = GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO |
		    GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO | GNUTLS_EXT_FLAG_HRR,
	.recv_func = key_share_recv_params,
	.send_func = key_share_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL,
	.cannot_be_overriden = 1
};

static int client_gen_key_share_single(gnutls_session_t session,
				       const gnutls_group_entry_st *group,
				       gnutls_buffer_st *extdata)
{
	gnutls_datum_t tmp = { NULL, 0 };
	int ret;

	switch (group->pk) {
	case GNUTLS_PK_EC:
		gnutls_pk_params_release(&session->key.kshare.ecdh_params);
		gnutls_pk_params_init(&session->key.kshare.ecdh_params);

		ret = _gnutls_pk_generate_keys(group->pk, group->curve,
					       &session->key.kshare.ecdh_params,
					       1);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _gnutls_ecc_ansi_x962_export(
			group->curve,
			session->key.kshare.ecdh_params.params[ECC_X],
			session->key.kshare.ecdh_params.params[ECC_Y], &tmp);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = gnutls_buffer_append_data(extdata, tmp.data, tmp.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		session->key.kshare.ecdh_params.algo = group->pk;
		session->key.kshare.ecdh_params.curve = group->curve;

		ret = 0;
		break;

	case GNUTLS_PK_ECDH_X25519:
	case GNUTLS_PK_ECDH_X448:
		gnutls_pk_params_release(&session->key.kshare.ecdhx_params);
		gnutls_pk_params_init(&session->key.kshare.ecdhx_params);

		ret = _gnutls_pk_generate_keys(
			group->pk, group->curve,
			&session->key.kshare.ecdhx_params, 1);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = gnutls_buffer_append_data(
			extdata, session->key.kshare.ecdhx_params.raw_pub.data,
			session->key.kshare.ecdhx_params.raw_pub.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		session->key.kshare.ecdhx_params.algo = group->pk;
		session->key.kshare.ecdhx_params.curve = group->curve;

		ret = 0;
		break;

	case GNUTLS_PK_DH:
		/* we need to initialize the group parameters first */
		gnutls_pk_params_release(&session->key.kshare.dh_params);
		gnutls_pk_params_init(&session->key.kshare.dh_params);

		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_G],
			group->generator->data, group->generator->size);
		if (ret < 0) {
			ret = gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
			goto cleanup;
		}

		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_P],
			group->prime->data, group->prime->size);
		if (ret < 0) {
			ret = gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
			goto cleanup;
		}

		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_Q],
			group->q->data, group->q->size);
		if (ret < 0) {
			ret = gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
			goto cleanup;
		}

		session->key.kshare.dh_params.algo = group->pk;
		session->key.kshare.dh_params.dh_group =
			group->id; /* no curve in FFDH, we write the group */
		session->key.kshare.dh_params.qbits = *group->q_bits;
		session->key.kshare.dh_params.params_nr = 3;

		ret = _gnutls_pk_generate_keys(
			group->pk, 0, &session->key.kshare.dh_params, 1);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto cleanup;
		}

		ret = _gnutls_buffer_append_fixed_mpi(
			extdata, session->key.kshare.dh_params.params[DH_Y],
			group->prime->size);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto cleanup;
		}

		ret = 0;
		break;

	case GNUTLS_PK_MLKEM768:
	case GNUTLS_PK_EXP_KYBER768:
		gnutls_pk_params_release(&session->key.kshare.kem_params);
		gnutls_pk_params_init(&session->key.kshare.kem_params);

		ret = _gnutls_pk_generate_keys(
			group->pk, 0, &session->key.kshare.kem_params, 1);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = gnutls_buffer_append_data(
			extdata, session->key.kshare.kem_params.raw_pub.data,
			session->key.kshare.kem_params.raw_pub.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;
		break;

	default:
		_gnutls_debug_log("Cannot send key share for group %s!\n",
				  group->name);
		return GNUTLS_E_INT_RET_0;
	}

cleanup:
	gnutls_free(tmp.data);
	return ret;
}

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
static int client_gen_key_share(gnutls_session_t session,
				const gnutls_group_entry_st *group,
				gnutls_buffer_st *extdata)
{
	unsigned int length_pos;
	int ret;

	_gnutls_handshake_log("EXT[%p]: sending key share for %s\n", session,
			      group->name);

	ret = _gnutls_buffer_append_prefix(extdata, 16, group->tls_id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* save the position of length field */
	length_pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	for (const gnutls_group_entry_st *p = group; p != NULL; p = p->next) {
		ret = client_gen_key_share_single(session, p, extdata);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* copy actual length */
	_gnutls_write_uint16(extdata->length - length_pos - 2,
			     &extdata->data[length_pos]);

	return 0;
}

static int server_gen_key_share_single(gnutls_session_t session,
				       const gnutls_group_entry_st *group,
				       gnutls_buffer_st *extdata)
{
	gnutls_datum_t tmp = { NULL, 0 };
	int ret;

	switch (group->pk) {
	case GNUTLS_PK_EC:
		ret = _gnutls_ecc_ansi_x962_export(
			group->curve,
			session->key.kshare.ecdh_params.params[ECC_X],
			session->key.kshare.ecdh_params.params[ECC_Y], &tmp);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = gnutls_buffer_append_data(extdata, tmp.data, tmp.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;
		break;

	case GNUTLS_PK_ECDH_X25519:
	case GNUTLS_PK_ECDH_X448:
		ret = gnutls_buffer_append_data(
			extdata, session->key.kshare.ecdhx_params.raw_pub.data,
			session->key.kshare.ecdhx_params.raw_pub.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;
		break;

	case GNUTLS_PK_DH:
		ret = _gnutls_buffer_append_fixed_mpi(
			extdata, session->key.kshare.dh_params.params[DH_Y],
			group->prime->size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;
		break;

	case GNUTLS_PK_MLKEM768:
	case GNUTLS_PK_EXP_KYBER768:
		ret = gnutls_buffer_append_data(
			extdata, session->key.kshare.kem_params.raw_pub.data,
			session->key.kshare.kem_params.raw_pub.size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = 0;
		break;

	default:
		_gnutls_debug_log("Cannot send key share for group %s!\n",
				  group->name);
		return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
	}

cleanup:
	gnutls_free(tmp.data);
	return ret;
}

/*
 * Sends server key exchange parameters
 *
 */
static int server_gen_key_share(gnutls_session_t session,
				const gnutls_group_entry_st *group,
				gnutls_buffer_st *extdata)
{
	unsigned int length_pos;
	int ret;

	_gnutls_handshake_log("EXT[%p]: sending key share for %s\n", session,
			      group->name);

	ret = _gnutls_buffer_append_prefix(extdata, 16, group->tls_id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* save the position of length field */
	length_pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	for (const gnutls_group_entry_st *p = group; p != NULL; p = p->next) {
		ret = server_gen_key_share_single(session, p, extdata);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* copy actual length */
	_gnutls_write_uint16(extdata->length - length_pos - 2,
			     &extdata->data[length_pos]);

	return 0;
}

static int append_key_datum(gnutls_datum_t *dst, const gnutls_datum_t *src)
{
	dst->data = gnutls_realloc_fast(dst->data, dst->size + src->size);
	if (!dst->data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	memcpy(dst->data + dst->size, src->data, src->size);
	dst->size += src->size;
	return 0;
}

static int server_use_key_share_single(gnutls_session_t session,
				       const gnutls_group_entry_st *group,
				       gnutls_buffer_st *buffer)
{
	gnutls_datum_t key = { NULL, 0 };
	gnutls_datum_t data;
	gnutls_pk_params_st pub;
	const gnutls_ecc_curve_entry_st *curve;
	int ret;

	switch (group->pk) {
	case GNUTLS_PK_EC:
		gnutls_pk_params_release(&session->key.kshare.ecdh_params);
		gnutls_pk_params_init(&session->key.kshare.ecdh_params);

		curve = _gnutls_ecc_curve_get_params(group->curve);

		gnutls_pk_params_init(&pub);

		if (curve->size * 2 + 1 > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, curve->size * 2 + 1);

		/* generate our key */
		ret = _gnutls_pk_generate_keys(curve->pk, curve->id,
					       &session->key.kshare.ecdh_params,
					       1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key */
		ret = _gnutls_ecc_ansi_x962_import(data.data, data.size,
						   &pub.params[ECC_X],
						   &pub.params[ECC_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;
		pub.curve = curve->id;
		pub.params_nr = 2;

		/* generate shared */
		ret = _gnutls_pk_derive_tls13(curve->pk, &key,
					      &session->key.kshare.ecdh_params,
					      &pub);
		gnutls_pk_params_release(&pub);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_ECDH_X25519:
	case GNUTLS_PK_ECDH_X448:
		gnutls_pk_params_release(&session->key.kshare.ecdhx_params);
		gnutls_pk_params_init(&session->key.kshare.ecdhx_params);

		curve = _gnutls_ecc_curve_get_params(group->curve);

		if (curve->size > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, curve->size);

		/* generate our key */
		ret = _gnutls_pk_generate_keys(
			curve->pk, curve->id, &session->key.kshare.ecdhx_params,
			1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		pub.algo = group->pk;
		pub.curve = curve->id;

		pub.raw_pub.data = data.data;
		pub.raw_pub.size = data.size;

		/* We don't mask the MSB in the final byte as required
		 * by RFC7748. This will be done internally by nettle 3.3 or later.
		 */
		ret = _gnutls_pk_derive_tls13(curve->pk, &key,
					      &session->key.kshare.ecdhx_params,
					      &pub);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_DH:
		/* we need to initialize the group parameters first */
		gnutls_pk_params_release(&session->key.kshare.dh_params);
		gnutls_pk_params_init(&session->key.kshare.dh_params);

		if (group->prime->size > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, group->prime->size);

		/* set group params */
		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_G],
			group->generator->data, group->generator->size);
		if (ret < 0)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_P],
			group->prime->data, group->prime->size);
		if (ret < 0)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		ret = _gnutls_mpi_init_scan_nz(
			&session->key.kshare.dh_params.params[DH_Q],
			group->q->data, group->q->size);
		if (ret < 0)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		session->key.kshare.dh_params.algo = GNUTLS_PK_DH;
		session->key.kshare.dh_params.qbits = *group->q_bits;
		session->key.kshare.dh_params.params_nr = 3;

		/* generate our keys */
		ret = _gnutls_pk_generate_keys(
			group->pk, 0, &session->key.kshare.dh_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		ret = _gnutls_mpi_init_scan_nz(&pub.params[DH_Y], data.data,
					       data.size);
		if (ret < 0)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		pub.algo = group->pk;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(GNUTLS_PK_DH, &session->key.key,
					      &session->key.kshare.dh_params,
					      &pub);
		_gnutls_mpi_release(&pub.params[DH_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_MLKEM768:
	case GNUTLS_PK_EXP_KYBER768: {
		gnutls_pk_params_release(&session->key.kshare.kem_params);
		gnutls_pk_params_init(&session->key.kshare.kem_params);

		/* generate our key */
		ret = _gnutls_pk_generate_keys(
			group->pk, 0, &session->key.kshare.kem_params, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* server's public key is unused, but the raw_pub field
		 * is used to store ciphertext */
		gnutls_free(session->key.kshare.kem_params.raw_pub.data);

		if (KYBER768_PUBLIC_KEY_SIZE > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data,
					 KYBER768_PUBLIC_KEY_SIZE);

		ret = _gnutls_pk_encaps(group->pk,
					&session->key.kshare.kem_params.raw_pub,
					&key, &data);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;
	}
	default:
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}
}

/* Generates shared key and stores it in session->key.key
 */
static int server_use_key_share(gnutls_session_t session,
				const gnutls_group_entry_st *group,
				const uint8_t *data, size_t data_size)
{
	gnutls_buffer_st buffer;

	_gnutls_ro_buffer_init(&buffer, data, data_size);

	for (const gnutls_group_entry_st *p = group; p != NULL; p = p->next) {
		int ret;

		ret = server_use_key_share_single(session, p, &buffer);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	if (buffer.length > 0)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	_gnutls_debug_log("EXT[%p]: server generated %s shared key\n", session,
			  group->name);

	return 0;
}

static int client_use_key_share_single(gnutls_session_t session,
				       const gnutls_group_entry_st *group,
				       gnutls_buffer_st *buffer)
{
	gnutls_datum_t key = { NULL, 0 };
	gnutls_datum_t data;
	gnutls_pk_params_st pub;
	const gnutls_ecc_curve_entry_st *curve;
	int ret;

	switch (group->pk) {
	case GNUTLS_PK_EC:
		curve = _gnutls_ecc_curve_get_params(group->curve);

		gnutls_pk_params_init(&pub);

		if (session->key.kshare.ecdh_params.algo != group->pk ||
		    session->key.kshare.ecdh_params.curve != curve->id)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		if (curve->size * 2 + 1 > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, curve->size * 2 + 1);

		/* read the server's public key */
		ret = _gnutls_ecc_ansi_x962_import(data.data, data.size,
						   &pub.params[ECC_X],
						   &pub.params[ECC_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pub.algo = group->pk;
		pub.curve = curve->id;
		pub.params_nr = 2;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(curve->pk, &key,
					      &session->key.kshare.ecdh_params,
					      &pub);
		gnutls_pk_params_release(&pub);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_ECDH_X25519:
	case GNUTLS_PK_ECDH_X448:
		curve = _gnutls_ecc_curve_get_params(group->curve);

		if (session->key.kshare.ecdhx_params.algo != group->pk ||
		    session->key.kshare.ecdhx_params.curve != curve->id)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		if (curve->size > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, curve->size);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		pub.algo = group->pk;
		pub.curve = curve->id;

		pub.raw_pub.data = data.data;
		pub.raw_pub.size = data.size;

		/* We don't mask the MSB in the final byte as required
		 * by RFC7748. This will be done internally by nettle 3.3 or later.
		 */
		ret = _gnutls_pk_derive_tls13(curve->pk, &key,
					      &session->key.kshare.ecdhx_params,
					      &pub);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_DH:
		if (session->key.kshare.dh_params.algo != group->pk ||
		    session->key.kshare.dh_params.dh_group != group->id)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		if (group->prime->size > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data, group->prime->size);

		/* read the public key and generate shared */
		gnutls_pk_params_init(&pub);

		ret = _gnutls_mpi_init_scan_nz(&pub.params[DH_Y], data.data,
					       data.size);
		if (ret < 0)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		pub.algo = group->pk;

		/* generate shared key */
		ret = _gnutls_pk_derive_tls13(GNUTLS_PK_DH, &key,
					      &session->key.kshare.dh_params,
					      &pub);
		_gnutls_mpi_release(&pub.params[DH_Y]);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;

	case GNUTLS_PK_MLKEM768:
	case GNUTLS_PK_EXP_KYBER768: {
		if (KYBER768_CIPHERTEXT_SIZE > buffer->length)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		_gnutls_buffer_pop_datum(buffer, &data,
					 KYBER768_CIPHERTEXT_SIZE);

		ret = _gnutls_pk_decaps(
			group->pk, &key, &data,
			&session->key.kshare.kem_params.raw_priv);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);

		ret = append_key_datum(&session->key.key, &key);
		_gnutls_free_datum(&key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 0;
	}
	default:
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}
}

/* Generates shared key and stores it in session->key.key
 */
static int client_use_key_share(gnutls_session_t session,
				const gnutls_group_entry_st *group,
				const uint8_t *data, size_t data_size)
{
	gnutls_buffer_st buffer;

	_gnutls_ro_buffer_init(&buffer, data, data_size);

	for (const gnutls_group_entry_st *p = group; p != NULL; p = p->next) {
		int ret;

		ret = client_use_key_share_single(session, p, &buffer);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	if (buffer.length > 0)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	_gnutls_debug_log("EXT[%p]: client generated %s shared key\n", session,
			  group->name);

	return 0;
}

static int key_share_recv_params(gnutls_session_t session, const uint8_t *data,
				 size_t data_size)
{
	int ret;
	size_t size;
	unsigned gid;
	const version_entry_st *ver;
	const gnutls_group_entry_st *group;
	unsigned used_share = 0;

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		ver = get_version(session);
		if (ver == NULL || ver->key_shares == 0)
			return gnutls_assert_val(0);

		DECR_LEN(data_size, 2);
		size = _gnutls_read_uint16(data);
		data += 2;

		if (data_size != size)
			return gnutls_assert_val(
				GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		/* if we do PSK without DH ignore that share */
		if ((session->internals.hsk_flags & HSK_PSK_SELECTED) &&
		    (session->internals.hsk_flags & HSK_PSK_KE_MODE_PSK)) {
			reset_cand_groups(session);
			return 0;
		}

		while (data_size > 0) {
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
				_gnutls_handshake_log(
					"EXT[%p]: Received key share for %s\n",
					session, group->name);

			if (group != NULL &&
			    group == session->internals.cand_group) {
				_gnutls_session_group_set(session, group);

				ret = server_use_key_share(session, group, data,
							   size);
				if (ret < 0)
					return gnutls_assert_val(ret);

				used_share = 1;
				break;
			}

			data += size;
			continue;
		}

		/* we utilize GNUTLS_E_NO_COMMON_KEY_SHARE for:
		 * 1. signal for hello-retry-request in the handshake
		 *    layer during first client hello parsing (server side - here).
		 *    This does not result to error code being
		 *    propagated to app layer.
		 * 2. Propagate to application error code that no
		 *    common key share was found after an HRR was
		 *    received (client side)
		 * 3. Propagate to application error code that no
		 *    common key share was found after an HRR was
		 *    sent (server side).
		 * In cases (2,3) the error is translated to illegal
		 * parameter alert.
		 */
		if (used_share == 0) {
			return gnutls_assert_val(GNUTLS_E_NO_COMMON_KEY_SHARE);
		}

		session->internals.hsk_flags |= HSK_KEY_SHARE_RECEIVED;
	} else { /* Client */
		ver = get_version(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		if (_gnutls_ext_get_msg(session) == GNUTLS_EXT_FLAG_HRR) {
			if (unlikely(!(session->internals.hsk_flags &
				       HSK_HRR_RECEIVED)))
				return gnutls_assert_val(
					GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

			DECR_LEN(data_size, 2);
			gid = _gnutls_read_uint16(data);

			group = _gnutls_tls_id_to_group(gid);
			if (group == NULL)
				return gnutls_assert_val(
					GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

			_gnutls_handshake_log(
				"EXT[%p]: HRR key share with %s\n", session,
				group->name);

			/* check if we support it */
			if (!_gnutls_session_supports_group(session,
							    group->id)) {
				_gnutls_handshake_log(
					"EXT[%p]: received share for %s which is disabled\n",
					session, group->name);
				return gnutls_assert_val(
					GNUTLS_E_ECC_UNSUPPORTED_CURVE);
			}

			_gnutls_session_group_set(session, group);

			return 0;
		}
		/* else */

		DECR_LEN(data_size, 2);
		gid = _gnutls_read_uint16(data);
		data += 2;

		DECR_LEN(data_size, 2);
		size = _gnutls_read_uint16(data);
		data += 2;

		if (data_size != size)
			return gnutls_assert_val(
				GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		group = _gnutls_tls_id_to_group(gid);
		if (group == NULL)
			return gnutls_assert_val(
				GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		/* check if we support it */
		if (!_gnutls_session_supports_group(session, group->id)) {
			_gnutls_handshake_log(
				"EXT[%p]: received share for %s which is disabled\n",
				session, group->name);
			return gnutls_assert_val(
				GNUTLS_E_ECC_UNSUPPORTED_CURVE);
		}

		_gnutls_session_group_set(session, group);
		session->internals.hsk_flags |= HSK_KEY_SHARE_RECEIVED;

		ret = client_use_key_share(session, group, data, size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	return 0;
}

static inline bool pk_types_overlap(const gnutls_group_entry_st *a,
				    const gnutls_group_entry_st *b)
{
	const gnutls_group_entry_st *pa;

	for (pa = a; pa != NULL; pa = pa->next) {
		const gnutls_group_entry_st *pb;

		for (pb = b; pb != NULL; pb = pb->next) {
			if (pa->pk == pb->pk ||
			    (IS_ECDHX(pa->pk) && IS_ECDHX(pb->pk)) ||
			    (IS_KEM(pa->pk) && IS_KEM(pb->pk)))
				return true;
		}
	}

	return false;
}

/* returns data_size or a negative number on failure
 */
static int key_share_send_params(gnutls_session_t session,
				 gnutls_buffer_st *extdata)
{
	unsigned i;
	int ret;
	unsigned int generated = 0;
	const gnutls_group_entry_st *group;
	const version_entry_st *ver;

	/* this extension is only being sent on client side */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		unsigned int length_pos;

		ver = _gnutls_version_max(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return 0;

		if (!have_creds_for_tls13(session))
			return 0;

		length_pos = extdata->length;

		ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (session->internals.hsk_flags &
		    HSK_HRR_RECEIVED) { /* we know the group */
			group = get_group(session);
			if (unlikely(group == NULL))
				return gnutls_assert_val(
					GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

			ret = client_gen_key_share(session, group, extdata);
			if (ret == GNUTLS_E_INT_RET_0)
				return gnutls_assert_val(
					GNUTLS_E_NO_COMMON_KEY_SHARE);
			if (ret < 0)
				return gnutls_assert_val(ret);
		} else {
			const gnutls_group_entry_st *selected_groups[3] = {
				NULL,
			};
			unsigned max_groups = 2; /* GNUTLS_KEY_SHARE_TOP2 */

			if (session->internals.flags & GNUTLS_KEY_SHARE_TOP)
				max_groups = 1;
			else if (session->internals.flags &
				 GNUTLS_KEY_SHARE_TOP3)
				max_groups = 3;

			assert(max_groups <=
			       sizeof(selected_groups) /
				       sizeof(selected_groups[0]));

			/* generate key shares for out top-(max_groups) groups
			 * if they are of different PK type. */
			for (i = 0;
			     i < session->internals.priorities->groups.size;
			     i++) {
				unsigned int j;

				group = session->internals.priorities->groups
						.entry[i];

				for (j = 0; j < generated; j++) {
					if (pk_types_overlap(
						    group,
						    selected_groups[j])) {
						break;
					}
				}
				if (j < generated) {
					continue;
				}

				selected_groups[generated] = group;

				ret = client_gen_key_share(session, group,
							   extdata);
				if (ret == GNUTLS_E_INT_RET_0)
					continue; /* no key share for this algorithm */
				if (ret < 0)
					return gnutls_assert_val(ret);

				generated++;

				if (generated >= max_groups)
					break;
			}
		}

		/* copy actual length */
		_gnutls_write_uint16(extdata->length - length_pos - 2,
				     &extdata->data[length_pos]);

	} else { /* server */
		ver = get_version(session);
		if (unlikely(ver == NULL || ver->key_shares == 0))
			return gnutls_assert_val(0);

		if (_gnutls_ext_get_msg(session) == GNUTLS_EXT_FLAG_HRR) {
			group = session->internals.cand_group;

			if (group == NULL)
				return gnutls_assert_val(
					GNUTLS_E_NO_COMMON_KEY_SHARE);

			_gnutls_session_group_set(session, group);

			_gnutls_handshake_log(
				"EXT[%p]: requesting retry with group %s\n",
				session, group->name);
			ret = _gnutls_buffer_append_prefix(extdata, 16,
							   group->tls_id);
			if (ret < 0)
				return gnutls_assert_val(ret);
		} else {
			/* if we are negotiating PSK without DH, do not send a key share */
			if ((session->internals.hsk_flags & HSK_PSK_SELECTED) &&
			    (session->internals.hsk_flags &
			     HSK_PSK_KE_MODE_PSK))
				return gnutls_assert_val(0);

			group = get_group(session);
			if (unlikely(group == NULL))
				return gnutls_assert_val(
					GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

			ret = server_gen_key_share(session, group, extdata);
			if (ret < 0)
				return gnutls_assert_val(ret);
		}

		session->internals.hsk_flags |= HSK_KEY_SHARE_SENT;
	}

	return 0;
}
