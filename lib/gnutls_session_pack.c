/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#include <gnutls_int.h>
#include <auth_srp.h>
#include <auth_anon.h>
#include <auth_x509.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_session_pack.h>
#include <gnutls_datum.h>
#include <gnutls_num.h>

#define PACK_HEADER_SIZE 1
int _gnutls_pack_x509pki_auth_info(X509PKI_AUTH_INFO info,
				   gnutls_datum * packed_session);
int _gnutls_unpack_x509pki_auth_info(X509PKI_AUTH_INFO info,
				     const gnutls_datum * packed_session);
static int _gnutls_pack_x509pki_auth_info_size();


/* Since auth_info structures contain malloced data, this function
 * is required in order to pack these structures in a vector in
 * order to store them to the DB.
 */
int _gnutls_session_pack(GNUTLS_STATE state, gnutls_datum * packed_session)
{
	uint32 pack_size;
	int ret;

	if (packed_session==NULL) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	switch (gnutls_get_auth_type(state)) {
	case GNUTLS_SRP:{
			SRP_SERVER_AUTH_INFO info =
			    _gnutls_get_auth_info(state);
			if (info == NULL || info->username[0] == 0)
				return GNUTLS_E_INVALID_PARAMETERS;

			pack_size = sizeof(SRP_SERVER_AUTH_INFO_INT);
			packed_session->size =
			    PACK_HEADER_SIZE + pack_size + sizeof(uint32);

			packed_session->data[0] = GNUTLS_SRP;
			WRITEuint32(pack_size,
				    &packed_session->
				    data[PACK_HEADER_SIZE]);
			memcpy(&packed_session->
			       data[PACK_HEADER_SIZE + sizeof(uint32)],
			       info, sizeof(SRP_SERVER_AUTH_INFO_INT));

		}
		break;
	case GNUTLS_ANON:{
			ANON_CLIENT_AUTH_INFO info =
			    _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_INVALID_PARAMETERS;

			pack_size = sizeof(ANON_CLIENT_AUTH_INFO_INT);
			packed_session->size =
			    PACK_HEADER_SIZE + pack_size + sizeof(uint32);

			packed_session->data[0] = GNUTLS_ANON;
			WRITEuint32(pack_size,
				    &packed_session->
				    data[PACK_HEADER_SIZE]);
			memcpy(&packed_session->
			       data[PACK_HEADER_SIZE + sizeof(uint32)],
			       info, sizeof(ANON_CLIENT_AUTH_INFO_INT));

		}
		break;
	case GNUTLS_X509PKI:{
			X509PKI_AUTH_INFO info =
			    _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_INVALID_PARAMETERS;

			ret =
			    _gnutls_pack_x509pki_auth_info(info,
							   packed_session);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}
		break;
	default:
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;

	}

	/* Auth_info structures copied. Now copy SecurityParameters. 
	 */
	packed_session->size += sizeof(SecurityParameters)+sizeof(uint32);

	WRITEuint32( sizeof(SecurityParameters), &packed_session->data[packed_session->size - sizeof(SecurityParameters) - sizeof(uint32)]);
	memcpy(&packed_session->
	       data[packed_session->size - sizeof(SecurityParameters)],
	       &state->security_parameters, sizeof(SecurityParameters));

	return 0;
}

/* Returns the size needed to hold the current session.
 */
int _gnutls_session_size( GNUTLS_STATE state)
{
	uint32 pack_size;

	pack_size = PACK_HEADER_SIZE + sizeof(uint32);

	switch ( gnutls_get_auth_type(state)) {
	case GNUTLS_SRP:
	case GNUTLS_ANON:
		pack_size += state->gnutls_key->auth_info_size;
	case GNUTLS_X509PKI:
		pack_size += _gnutls_pack_x509pki_auth_info_size( state);
	}

	/* Auth_info structures copied. Now copy SecurityParameters. 
	 */
	pack_size += sizeof(SecurityParameters) + sizeof(uint32);

	return pack_size;
}

int _gnutls_session_unpack(GNUTLS_STATE state,
			   const gnutls_datum * packed_session)
{
	uint32 pack_size;
	int ret;
	uint32 timestamp = time(0);
	SecurityParameters sp;

	if (packed_session==NULL || packed_session->size == 0) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	if (state->gnutls_key->auth_info != NULL) {
		_gnutls_free_auth_info( state);
	}
	
	switch (packed_session->data[0]) {
	case GNUTLS_SRP:{

			pack_size =
			    READuint32(&packed_session->
				       data[PACK_HEADER_SIZE]);
			

			if (pack_size == 0) break;
			if (pack_size != sizeof(SRP_SERVER_AUTH_INFO_INT)) {
				gnutls_assert();
				return GNUTLS_E_DB_ERROR;
			}
			
			state->gnutls_key->auth_info =
			    gnutls_calloc(1,
					  sizeof
					  (SRP_SERVER_AUTH_INFO_INT));
			if (state->gnutls_key->auth_info == NULL)
				return GNUTLS_E_MEMORY_ERROR;
			state->gnutls_key->auth_info_size =
			    sizeof(SRP_SERVER_AUTH_INFO_INT);


			memcpy(state->gnutls_key->auth_info,
			       &packed_session->data[PACK_HEADER_SIZE +
						     sizeof(uint32)],
			       sizeof(SRP_SERVER_AUTH_INFO_INT));
		}
		break;
	case GNUTLS_ANON:{
			pack_size =
			    READuint32(&packed_session->
				       data[PACK_HEADER_SIZE]);

			if (pack_size == 0) break;
			
			if (pack_size != sizeof(ANON_CLIENT_AUTH_INFO_INT)) {
				gnutls_assert();
				return GNUTLS_E_DB_ERROR;
			}

			state->gnutls_key->auth_info =
			    gnutls_calloc(1,
					  sizeof
					  (ANON_CLIENT_AUTH_INFO_INT));
			if (state->gnutls_key->auth_info == NULL)
				return GNUTLS_E_MEMORY_ERROR;
			state->gnutls_key->auth_info_size =
			    sizeof(ANON_CLIENT_AUTH_INFO_INT);

			memcpy(state->gnutls_key->auth_info,
			       &packed_session->data[PACK_HEADER_SIZE],
			       sizeof(ANON_CLIENT_AUTH_INFO_INT));
		}
		break;
	case GNUTLS_X509PKI:{
			pack_size =
			    READuint32(&packed_session->
				       data[PACK_HEADER_SIZE]);
			
			if (pack_size == 0) break;

			if (pack_size < sizeof(X509PKI_AUTH_INFO_INT)) {
				gnutls_assert();
				return GNUTLS_E_DB_ERROR;
			}

			state->gnutls_key->auth_info =
			    gnutls_calloc(1,
					  sizeof(X509PKI_AUTH_INFO_INT));
			if (state->gnutls_key->auth_info == NULL)
				return GNUTLS_E_MEMORY_ERROR;
			state->gnutls_key->auth_info_size =
			    sizeof(X509PKI_AUTH_INFO_INT);

			ret =
			    _gnutls_unpack_x509pki_auth_info(state->
							     gnutls_key->
							     auth_info,
							     packed_session);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}

			pack_size += ret;

		}
		break;
	default:
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;

	}

	state->gnutls_key->auth_info_type = packed_session->data[0];

	/* Auth_info structures copied. Now copy SecurityParameters. 
	 */
	ret =
	    READuint32(&packed_session->
		       data[PACK_HEADER_SIZE + sizeof(uint32) +
			    pack_size]);

	if (ret != sizeof(SecurityParameters)) {
		gnutls_assert();
		return GNUTLS_E_DB_ERROR;
	}
	memcpy(&sp, &packed_session->data[PACK_HEADER_SIZE +
				     2 * sizeof(uint32) + pack_size],
	       				sizeof(SecurityParameters));

	if ( timestamp - sp.timestamp <= state->gnutls_internals.expire_time 
		&& sp.timestamp <= timestamp) {

		memcpy( &state->gnutls_internals.resumed_security_parameters, &sp, sizeof(SecurityParameters));
	} else {
		_gnutls_free_auth_info( state);

		return GNUTLS_E_EXPIRED;
	}


	return 0;
}

int _gnutls_pack_x509pki_auth_info(X509PKI_AUTH_INFO info,
				   gnutls_datum * packed_session)
{
	uint32 pack_size = sizeof(X509PKI_AUTH_INFO_INT) + info->raw_certificate.size;
	packed_session->size =
	    pack_size + PACK_HEADER_SIZE + sizeof(uint32);

	packed_session->data[0] = GNUTLS_X509PKI;
	WRITEuint32(pack_size, &packed_session->data[PACK_HEADER_SIZE]);
	memcpy(&packed_session->data[PACK_HEADER_SIZE + sizeof(uint32)],
	       info, sizeof(X509PKI_AUTH_INFO_INT));
	
	if (info->raw_certificate.size > 0)
		memcpy(&packed_session->data[PACK_HEADER_SIZE + sizeof(uint32) +
			sizeof(X509PKI_AUTH_INFO_INT)], info->raw_certificate.data, 
			info->raw_certificate.size);

	return 0;
}

static int _gnutls_pack_x509pki_auth_info_size( GNUTLS_STATE state)
{
	X509PKI_AUTH_INFO info =
	    _gnutls_get_auth_info(state);
	uint32 pack_size = sizeof(X509PKI_AUTH_INFO_INT);

	if (info == NULL)
		return 0;
	    
	return pack_size + PACK_HEADER_SIZE + sizeof(uint32) + info->raw_certificate.size;
}


int _gnutls_unpack_x509pki_auth_info(X509PKI_AUTH_INFO info,
				     const gnutls_datum * packed_session)
{
int ret;

	memcpy(info,
	       &packed_session->data[PACK_HEADER_SIZE + sizeof(uint32)],
	       sizeof(X509PKI_AUTH_INFO_INT));

	if (info->raw_certificate.size > 0) {
		ret = gnutls_set_datum( &info->raw_certificate, 
		 &packed_session->data[PACK_HEADER_SIZE + sizeof(uint32) + sizeof(X509PKI_AUTH_INFO_INT)],
		 info->raw_certificate.size);

		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}
	return 0;
}
