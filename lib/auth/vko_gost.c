/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 * Copyright (C) 2016 Dmitry Eremin-Solenikov
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
#include "vko.h"
#include <state.h>
#include <datum.h>
#include <ext/ecc.h>
#include <auth/cert.h>
#include <pk.h>
#include <abstract_int.h>

#if defined(ENABLE_GOST)
static int gen_vko_gost_client_kx(gnutls_session_t, gnutls_buffer_st *);
static int proc_vko_gost_server_crt(gnutls_session_t session,
				    uint8_t * data, size_t _data_size);
static int proc_vko_gost_client_kx(gnutls_session_t session,
				   uint8_t * data, size_t _data_size);

const mod_auth_st vko_gost_auth_struct = {
	"VKO_GOST",
	_gnutls_gen_cert_server_crt,
	_gnutls_gen_cert_client_crt,
	NULL,
	gen_vko_gost_client_kx,
	_gnutls_gen_cert_client_crt_vrfy,
	_gnutls_gen_cert_server_cert_req,

	proc_vko_gost_server_crt,
	_gnutls_proc_crt,
	NULL,
	proc_vko_gost_client_kx,
	_gnutls_proc_cert_client_crt_vrfy,
	_gnutls_proc_cert_cert_req
};

static gnutls_digest_algorithm_t
get_vko_digest_algo(gnutls_session_t session)
{
	switch (gnutls_kx_get(session)) {
	case GNUTLS_KX_VKO_GOST_01:
		return GNUTLS_DIG_GOSTR_94;
	case GNUTLS_KX_VKO_GOST_12:
		return GNUTLS_DIG_STREEBOG_256;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
}

static int
calc_ukm(gnutls_session_t session, gnutls_datum_t *ukm)
{
	gnutls_digest_algorithm_t digalg = get_vko_digest_algo(session);
	gnutls_hash_hd_t dig;
	int ret;

	ret = gnutls_hash_init(&dig, digalg);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ukm->size = gnutls_hash_get_len(digalg);
	ukm->data = gnutls_malloc(ukm->size);
	if (ukm->data == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_INTERNAL_ERROR;
		goto cleanup;
	}

	gnutls_hash(dig, session->security_parameters.client_random,
		    sizeof(session->security_parameters.client_random));

	gnutls_hash(dig, session->security_parameters.server_random,
		    sizeof(session->security_parameters.server_random));

	gnutls_hash_deinit(dig, ukm->data);

	ukm->size = 8; /* VKO uses first 8 bytes */

	return 0;

cleanup:
	_gnutls_free_datum(ukm);

	return ret;
}

static int
proc_vko_gost_client_kx(gnutls_session_t session,
		     uint8_t * data, size_t _data_size)
{
	int ret, i = 0;
	ssize_t data_size = _data_size;
	const gnutls_group_entry_st *group = get_group(session);
	const gnutls_ecc_curve_entry_st *ecurve;
	gnutls_privkey_t privkey = session->internals.selected_key;
	cert_auth_info_t info = _gnutls_get_auth_info(session, GNUTLS_CRD_CERTIFICATE);
	gnutls_pcert_st peer_cert;
	int has_pcert = 0;
	gnutls_datum_t ukm;
	gnutls_datum_t cek;
	int len;

	if (group == NULL)
		return gnutls_assert_val(GNUTLS_E_ECC_NO_SUPPORTED_CURVES);

	ecurve = _gnutls_ecc_curve_get_params(group->curve);
	if (ecurve == NULL)
		return gnutls_assert_val(GNUTLS_E_ECC_NO_SUPPORTED_CURVES);

	/* FIXME: check ecurve */

	DECR_LEN(data_size, 1);
	if (data[0] != (ASN1_TAG_SEQUENCE | ASN1_CLASS_STRUCTURED))
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	i += 1;

	ret = asn1_get_length_der(&data[i], data_size, &len);
	if (ret < 0)
		return gnutls_assert_val(_gnutls_asn2err(ret));
	DECR_LEN(data_size, len);
	i += len;

	cek.data = &data[i];
	cek.size = ret;

	DECR_LEN(data_size, ret);

	if (data_size != 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	ret = calc_ukm(session, &ukm);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (!privkey || privkey->type != GNUTLS_PRIVKEY_X509) {
		gnutls_assert();
		_gnutls_free_datum(&ukm);
		goto cleanup;
	}

	if (info != NULL && info->ncerts != 0) {
		ret = _gnutls_get_auth_info_pcert(&peer_cert,
				session->security_parameters.
				cert_type, info);

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		has_pcert = 1;
	}

	ret = _gnutls_gost_keytrans_decrypt(has_pcert ? &peer_cert.pubkey->params : NULL,
					    &privkey->key.x509->params,
					    &cek, &ukm, &session->key.key);
	if (ret < 0) {
		gnutls_assert();
		_gnutls_free_datum(&ukm);
		goto cleanup;
	}

	if (ret == 0)
		session->internals.crt_requested = 0;

	ret = 0;

cleanup:
	if (has_pcert)
		gnutls_pcert_deinit(&peer_cert);

	gnutls_pk_params_clear(&session->key.ecdh_params);
	_gnutls_free_datum(&ukm);

	return ret;
}

/*
 * Returns < 0 in case of error, 0 if pubkey comes from certificate or 1 if it
 * should be generated
 */
static int
gen_gost_ecdh_params(gnutls_session_t session)
{
	int ret;
	gnutls_pcert_st *apr_cert_list;
	int apr_cert_list_length;
	gnutls_privkey_t apr_pkey;
	unsigned key_usage;

	/* find the appropriate certificate */
	if ((ret = _gnutls_get_selected_cert(session, &apr_cert_list,
					     &apr_cert_list_length,
					     &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (apr_cert_list_length == 0) {
		gnutls_assert();
		goto generate;
	}

	gnutls_pubkey_get_key_usage(apr_cert_list[0].pubkey, &key_usage);
	if (!(key_usage & GNUTLS_KEY_KEY_ENCIPHERMENT))
		return gnutls_assert_val(GNUTLS_E_KEY_USAGE_VIOLATION);

	if (apr_cert_list[0].pubkey->params.algo != session->key.ecdh_params.algo ||
	    apr_cert_list[0].pubkey->params.curve != session->key.ecdh_params.curve ||
	    apr_cert_list[0].pubkey->params.gost_params != session->key.ecdh_params.gost_params) {
		gnutls_assert();
		goto generate;
	}

	ret = _gnutls_privkey_get_mpis(apr_pkey, &session->key.ecdh_params);
	if (ret < 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	gnutls_assert();

	return 0;

generate:
	ret =  _gnutls_pk_generate_keys(session->key.ecdh_params.algo,
					session->key.ecdh_params.curve,
					&session->key.ecdh_params, 1);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 1;
}

static int
gen_vko_gost_client_kx(gnutls_session_t session,
			  gnutls_buffer_st * data)
{
	int ret;
	const gnutls_group_entry_st *group = get_group(session);
	const gnutls_ecc_curve_entry_st *ecurve;
	gnutls_datum_t out = {};
	gnutls_datum_t ukm = {};
	gnutls_pk_params_st pub;
	uint8_t tl[1 + ASN1_MAX_LENGTH_SIZE];
	int len;
	int is_ephem;

	if (group == NULL)
		return gnutls_assert_val(GNUTLS_E_ECC_NO_SUPPORTED_CURVES);

	ecurve = _gnutls_ecc_curve_get_params(group->curve);
	if (ecurve == NULL)
		return gnutls_assert_val(GNUTLS_E_ECC_NO_SUPPORTED_CURVES);

	/* FIXME: check ecurve */

	is_ephem = gen_gost_ecdh_params(session);
	if (is_ephem < 0)
		return gnutls_assert_val(is_ephem);
	else if (is_ephem == 0)
		session->internals.crt_requested = 0;

	session->key.key.size = 32; /* GOST key size */
	session->key.key.data = gnutls_malloc(session->key.key.size);
	if (session->key.key.data == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	/* Generate random */
	ret = gnutls_rnd(GNUTLS_RND_RANDOM, session->key.key.data,
			 session->key.key.size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = calc_ukm(session, &ukm);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	gnutls_pk_params_init(&pub);
	pub.params[GOST_X] = session->key.ecdh_x;
	pub.params[GOST_Y] = session->key.ecdh_y;
	pub.curve = session->key.ecdh_params.curve;
	pub.gost_params = session->key.ecdh_params.gost_params;
	pub.algo = session->key.ecdh_params.algo;

	ret = _gnutls_gost_keytrans_encrypt(&pub,
			&session->key.ecdh_params,
			is_ephem,
			&session->key.key,
			&ukm, &out);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	tl[0] = ASN1_TAG_SEQUENCE | ASN1_CLASS_STRUCTURED;
	asn1_length_der(out.size, tl + 1, &len);
	ret = gnutls_buffer_append_data(data, tl, len + 1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_buffer_append_data(data, out.data, out.size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = data->length;
 cleanup:
	/* no longer needed */
	_gnutls_mpi_release(&session->key.ecdh_x);
	_gnutls_mpi_release(&session->key.ecdh_y);
	gnutls_pk_params_clear(&session->key.ecdh_params);

	_gnutls_free_datum(&out);
	_gnutls_free_datum(&ukm);

	return ret;
}

static int
proc_vko_gost_server_crt(gnutls_session_t session,
		     uint8_t * data, size_t _data_size)
{
	int ret;
	gnutls_ecc_curve_t curve;
	const gnutls_group_entry_st *group;
	cert_auth_info_t info;
	gnutls_pcert_st peer_cert;

	ret = _gnutls_proc_crt(session, data, _data_size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	info = _gnutls_get_auth_info(session, GNUTLS_CRD_CERTIFICATE);

	if (info == NULL || info->ncerts == 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ret =
	    _gnutls_get_auth_info_pcert(&peer_cert,
					session->security_parameters.
					cert_type, info);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* just in case we are resuming a session */
	gnutls_pk_params_release(&session->key.ecdh_params);

	gnutls_pk_params_init(&session->key.ecdh_params);

	curve = peer_cert.pubkey->params.curve;
	group = _gnutls_id_to_group(curve);
	if (group == NULL || group->curve == 0) {
		_gnutls_debug_log("received unknown curve %d\n", curve);
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	} else {
		_gnutls_debug_log("received curve %s\n", group->name);
	}

	ret = _gnutls_session_supports_group(session, group->id);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	_gnutls_session_group_set(session, group);

	session->key.ecdh_params.algo = peer_cert.pubkey->params.algo;
	session->key.ecdh_params.curve = curve;
	session->key.ecdh_params.gost_params = peer_cert.pubkey->params.gost_params;

	session->key.ecdh_x = _gnutls_mpi_copy(peer_cert.pubkey->params.params[GOST_X]);
	if (session->key.ecdh_x == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	session->key.ecdh_y = _gnutls_mpi_copy(peer_cert.pubkey->params.params[GOST_Y]);
	if (session->key.ecdh_y == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&session->key.ecdh_y);
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	gnutls_pcert_deinit(&peer_cert);

	return 0;

cleanup:
	gnutls_pcert_deinit(&peer_cert);

	return ret;
}
#endif
