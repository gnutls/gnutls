/*
 * Copyright (C) 2000, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/* Contains functions that are supposed to pack and unpack session data,
 * before and after they are sent to the database backend.
 */

#include <gnutls_int.h>
#ifdef ENABLE_SRP
# include <auth_srp.h>
#endif
#include <auth_anon.h>
#include <auth_cert.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_session_pack.h>
#include <gnutls_datum.h>
#include <gnutls_num.h>

#define PACK_HEADER_SIZE 1
static int _gnutls_pack_certificate_auth_info(cert_auth_info_t info,
					      gnutls_datum_t *
					      packed_session);
static int _gnutls_unpack_certificate_auth_info(cert_auth_info_t info,
						const gnutls_datum_t *
						packed_session);
static int _gnutls_pack_certificate_auth_info_size(cert_auth_info_t info);


/* Since auth_info structures contain malloced data, this function
 * is required in order to pack these structures in a vector in
 * order to store them to the DB.
 */
int _gnutls_session_pack(gnutls_session_t session,
			 gnutls_datum_t * packed_session)
{
    uint32 pack_size;
    int ret;

    if (packed_session == NULL) {
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
    }


    switch (gnutls_auth_get_type(session)) {
#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:{
	    srp_server_auth_info_t info = _gnutls_get_auth_info(session);


	    if (info == NULL && session->key->auth_info_size != 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	    }

	    pack_size = session->key->auth_info_size;
	    packed_session->size =
		PACK_HEADER_SIZE + pack_size + sizeof(uint32);

	    packed_session->data[0] = GNUTLS_CRD_SRP;
	    _gnutls_write_uint32(pack_size,
				 &packed_session->data[PACK_HEADER_SIZE]);

	    if (session->key->auth_info_size > 0)
		memcpy(&packed_session->
		       data[PACK_HEADER_SIZE + sizeof(uint32)],
		       info, session->key->auth_info_size);

	}

	break;
#endif
    case GNUTLS_CRD_ANON:{
	    anon_auth_info_t info = _gnutls_get_auth_info(session);
	    if (info == NULL && session->key->auth_info_size != 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	    }

	    packed_session->size =
		PACK_HEADER_SIZE + session->key->auth_info_size +
		sizeof(uint32);

	    packed_session->data[0] = GNUTLS_CRD_ANON;
	    _gnutls_write_uint32(session->key->auth_info_size,
				 &packed_session->data[PACK_HEADER_SIZE]);

	    if (session->key->auth_info_size > 0)
		memcpy(&packed_session->
		       data[PACK_HEADER_SIZE + sizeof(uint32)],
		       info, session->key->auth_info_size);

	}
	break;
    case GNUTLS_CRD_CERTIFICATE:{
	    cert_auth_info_t info = _gnutls_get_auth_info(session);
	    if (info == NULL && session->key->auth_info_size != 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	    }

	    ret = _gnutls_pack_certificate_auth_info(info, packed_session);
	    if (ret < 0) {
		gnutls_assert();
		return ret;
	    }
	}
	break;
    default:
	return GNUTLS_E_INTERNAL_ERROR;

    }

    /* Auth_info structures copied. Now copy security_parameters_st. 
     */
    packed_session->size +=
	sizeof(security_parameters_st) + sizeof(uint32);

    _gnutls_write_uint32(sizeof(security_parameters_st),
			 &packed_session->data[packed_session->size -
					       sizeof
					       (security_parameters_st) -
					       sizeof(uint32)]);
    memcpy(&packed_session->
	   data[packed_session->size - sizeof(security_parameters_st)],
	   &session->security_parameters, sizeof(security_parameters_st));

    return 0;
}

/* Returns the size needed to hold the current session.
 */
uint _gnutls_session_size(gnutls_session_t session)
{
    uint32 pack_size;

    pack_size = PACK_HEADER_SIZE + sizeof(uint32);

    switch (gnutls_auth_get_type(session)) {
    case GNUTLS_CRD_SRP:
    case GNUTLS_CRD_ANON:
	pack_size += session->key->auth_info_size;
	break;
    case GNUTLS_CRD_CERTIFICATE:{
	    cert_auth_info_t info = _gnutls_get_auth_info(session);

	    pack_size += _gnutls_pack_certificate_auth_info_size(info);
	}
	break;
    }

    /* Auth_info structures copied. Now copy security_parameters_st. 
     */
    pack_size += sizeof(security_parameters_st) + sizeof(uint32);

    return pack_size;
}

int _gnutls_session_unpack(gnutls_session_t session,
			   const gnutls_datum_t * packed_session)
{
    uint32 pack_size;
    int ret;
    time_t timestamp = time(0);
    security_parameters_st sp;

    if (packed_session == NULL || packed_session->size == 0) {
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
    }

    if (session->key->auth_info != NULL) {
	_gnutls_free_auth_info(session);
    }

    switch (packed_session->data[0]) {
#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:{

	    pack_size =
		_gnutls_read_uint32(&packed_session->
				    data[PACK_HEADER_SIZE]);

	    if (pack_size == 0)
		break;
	    if (pack_size != sizeof(srp_server_auth_info_st)) {
		gnutls_assert();
		return GNUTLS_E_DB_ERROR;
	    }

	    session->key->auth_info = gnutls_malloc(pack_size);

	    if (session->key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	    }
	    session->key->auth_info_size = sizeof(srp_server_auth_info_st);


	    memcpy(session->key->auth_info,
		   &packed_session->data[PACK_HEADER_SIZE +
					 sizeof(uint32)], pack_size);
	}
	break;
#endif
    case GNUTLS_CRD_ANON:{
	    anon_auth_info_t info;

	    pack_size =
		_gnutls_read_uint32(&packed_session->
				    data[PACK_HEADER_SIZE]);

	    if (pack_size == 0)
		break;

	    if (pack_size != sizeof(anon_client_auth_info_st)) {
		gnutls_assert();
		return GNUTLS_E_DB_ERROR;
	    }

	    session->key->auth_info = gnutls_malloc(pack_size);

	    if (session->key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	    }
	    session->key->auth_info_size = pack_size;

	    memcpy(session->key->auth_info,
		   &packed_session->data[PACK_HEADER_SIZE +
					 sizeof(uint32)], pack_size);

	    /* Delete the DH parameters. (this might need to be moved to a function)
	     */
	    info = session->key->auth_info;
	    _gnutls_free_dh_info( &info->dh);
	    memset(&info->dh, 0, sizeof(dh_info_st));
	}
	break;
    case GNUTLS_CRD_CERTIFICATE:{
	    pack_size =
		_gnutls_read_uint32(&packed_session->
				    data[PACK_HEADER_SIZE]);

	    if (pack_size == 0) {
		session->key->auth_info = NULL;
		session->key->auth_info_size = 0;
		break;
	    }
	    if (pack_size < sizeof(cert_auth_info_st)) {
		gnutls_assert();
		return GNUTLS_E_DB_ERROR;
	    }

	    session->key->auth_info =
		gnutls_malloc(sizeof(cert_auth_info_st));

	    if (session->key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	    }
	    session->key->auth_info_size = sizeof(cert_auth_info_st);

	    ret =
		_gnutls_unpack_certificate_auth_info(session->
						     key->
						     auth_info,
						     packed_session);
	    if (ret < 0) {
		gnutls_assert();
		return ret;
	    }

	}
	break;
    default:
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;

    }

    session->key->auth_info_type = packed_session->data[0];

    /* Auth_info structures copied. Now copy security_parameters_st. 
     */
    ret =
	_gnutls_read_uint32(&packed_session->
			    data[PACK_HEADER_SIZE + sizeof(uint32) +
				 pack_size]);

    if (ret != sizeof(security_parameters_st)) {
	gnutls_assert();
	return GNUTLS_E_DB_ERROR;
    }
    memcpy(&sp, &packed_session->data[PACK_HEADER_SIZE +
				      2 * sizeof(uint32) + pack_size],
	   sizeof(security_parameters_st));

    if (timestamp - sp.timestamp <= session->internals.expire_time
	&& sp.timestamp <= timestamp) {

	memcpy(&session->internals.resumed_security_parameters, &sp,
	       sizeof(security_parameters_st));
    } else {
	_gnutls_free_auth_info(session);
	gnutls_assert();
	return GNUTLS_E_EXPIRED;
    }


    return 0;
}

int _gnutls_pack_certificate_auth_info(cert_auth_info_t info,
				       gnutls_datum_t * packed_session)
{
    unsigned int pos, i;
    int info_size;

    packed_session->size = _gnutls_pack_certificate_auth_info_size(info);

    if (info == NULL)
	info_size = 0;
    else
	info_size = sizeof(cert_auth_info_st);

    packed_session->data[0] = GNUTLS_CRD_CERTIFICATE;
    _gnutls_write_uint32(packed_session->size - PACK_HEADER_SIZE -
			 sizeof(uint32),
			 &packed_session->data[PACK_HEADER_SIZE]);

    if (info != NULL) {
	memcpy(&packed_session->data[PACK_HEADER_SIZE + sizeof(uint32)],
	       info, sizeof(cert_auth_info_st));
    }

    pos = PACK_HEADER_SIZE + sizeof(uint32) + info_size;

    if (info != NULL) {
	for (i = 0; i < info->ncerts; i++) {
	    _gnutls_write_uint32(info->raw_certificate_list[i].size,
				 &packed_session->data[pos]);
	    pos += sizeof(uint32);

	    memcpy(&packed_session->data[pos],
		   info->raw_certificate_list[i].data,
		   info->raw_certificate_list[i].size);
	    pos += info->raw_certificate_list[i].size;
	}
    }

    return 0;
}

static int _gnutls_pack_certificate_auth_info_size(cert_auth_info_t info)
{
    uint32 pack_size = sizeof(cert_auth_info_st);
    unsigned int i;

    if (info == NULL)
	return sizeof(uint32) + PACK_HEADER_SIZE;

    for (i = 0; i < info->ncerts; i++) {
	pack_size += sizeof(uint32) + info->raw_certificate_list[i].size;
    }

    return pack_size + PACK_HEADER_SIZE + sizeof(uint32);
}


int _gnutls_unpack_certificate_auth_info(cert_auth_info_t info,
					 const gnutls_datum_t *
					 packed_session)
{
    unsigned int i, j, pos;
    int ret;
    uint32 size;

    memcpy(info,
	   &packed_session->data[PACK_HEADER_SIZE + sizeof(uint32)],
	   sizeof(cert_auth_info_st));

    /* Delete the dh_info_st and rsa_info_st fields.
     */
    _gnutls_free_dh_info( &info->dh);
    _gnutls_free_rsa_info( &info->rsa_export);
    memset(&info->dh, 0, sizeof(dh_info_st));
    memset(&info->rsa_export, 0, sizeof(rsa_info_st));

    pos = PACK_HEADER_SIZE + sizeof(uint32) + sizeof(cert_auth_info_st);
    if (info->ncerts > 0) {
	info->raw_certificate_list =
	    gnutls_calloc(1, info->ncerts * sizeof(gnutls_datum_t));
	if (info->raw_certificate_list == NULL) {
	    gnutls_assert();
	    return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < info->ncerts; i++) {
	    size = _gnutls_read_uint32(&packed_session->data[pos]);
	    pos += sizeof(uint32);

	    ret =
		_gnutls_set_datum(&info->raw_certificate_list[i],
				  &packed_session->data[pos], size);
	    pos += size;

	    if (ret < 0) {
		gnutls_assert();
		goto clear;
	    }
	}
    }
    return 0;

  clear:
    for (j = 0; j < i; j++)
	_gnutls_free_datum(&info->raw_certificate_list[j]);

    gnutls_free(info->raw_certificate_list);
    return GNUTLS_E_MEMORY_ERROR;

}
