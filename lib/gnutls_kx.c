/*
 * Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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

#include "gnutls_int.h"
#include "gnutls_handshake.h"
#include "gnutls_kx.h"
#include "gnutls_dh.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"
#include "debug.h"
#include "gnutls_gcry.h"
#include <gnutls_record.h>
#include <gnutls_datum.h>
#include <gnutls_alert.h>

/* This file contains important thing for the TLS handshake procedure.
 */

#define MASTER_SECRET "master secret"
static int generate_normal_master( GNUTLS_STATE state);

int _gnutls_generate_master( GNUTLS_STATE state) {
	if (state->gnutls_internals.resumed==RESUME_FALSE)
		return generate_normal_master(state);
	return 0;
}

#define PREMASTER state->gnutls_key->key
static int generate_normal_master( GNUTLS_STATE state) {
int ret = 0;
char random[2*TLS_RANDOM_SIZE];

	memcpy(random, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	memcpy(&random[TLS_RANDOM_SIZE], state->security_parameters.server_random, TLS_RANDOM_SIZE);

	_gnutls_hard_log( "INT: PREMASTER SECRET[%d]: %s\n", PREMASTER.size, _gnutls_bin2hex(PREMASTER.data, PREMASTER.size));
	_gnutls_hard_log( "INT: CLIENT RANDOM[%d]: %s\n", 32, _gnutls_bin2hex(state->security_parameters.client_random,32));
	_gnutls_hard_log( "INT: SERVER RANDOM[%d]: %s\n", 32, _gnutls_bin2hex(state->security_parameters.server_random,32));

	if ( state->security_parameters.version == GNUTLS_SSL3) {
		ret =
		    gnutls_ssl3_generate_random( PREMASTER.data, PREMASTER.size,
			       random, 2*TLS_RANDOM_SIZE, TLS_MASTER_SIZE,
			       state->security_parameters.master_secret);

	} else {
		ret =
		    gnutls_PRF( PREMASTER.data, PREMASTER.size,
			       MASTER_SECRET, strlen(MASTER_SECRET),
			       random, 2*TLS_RANDOM_SIZE, TLS_MASTER_SIZE, 
			       state->security_parameters.master_secret); 
	}
	gnutls_sfree_datum(&PREMASTER);
	
	if (ret<0) return ret;
	
	_gnutls_hard_log( "INT: MASTER SECRET: %s\n", _gnutls_bin2hex(state->security_parameters.master_secret, TLS_MASTER_SIZE));

	return ret;
}


/* This is called when we want to receive the key exchange message of the
 * server. It does nothing if this type of message is not required
 * by the selected ciphersuite. 
 */
int _gnutls_send_server_kx_message( GNUTLS_STATE state, int again)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_generate_server_kx==NULL) 
		return 0;

	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_server_kx( state, &data);

		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
	
	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_SERVER_KEY_EXCHANGE);
	gnutls_free(data);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return data_size;
}

/* This function sends a certificate request message to the
 * client.
 */
int _gnutls_send_server_certificate_request( GNUTLS_STATE state, int again)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_generate_server_certificate_request==NULL) 
		return 0;

	if (state->gnutls_internals.send_cert_req <= 0)
		return 0;
		
	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_server_certificate_request( state, &data);

		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_CERTIFICATE_REQUEST);
	gnutls_free(data);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return data_size;
}

/* Currently only used in SRP */
int _gnutls_send_server_kx_message2( GNUTLS_STATE state, int again)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_generate_server_kx2 == NULL)
		return 0;

	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_server_kx2( state, &data);

		if (data_size<0) {
			gnutls_assert();
			return data_size;
		}
	}

	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_SERVER_KEY_EXCHANGE);
		
	gnutls_free(data);
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	return data_size;
}

/* This is the function for the client to send the key
 * exchange message 
 */
int _gnutls_send_client_kx_message( GNUTLS_STATE state, int again)
{
	uint8 *data;
	int data_size;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_generate_client_kx==NULL) 
		return 0;


	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_kx( state, &data);
		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
    	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_CLIENT_KEY_EXCHANGE);
	gnutls_free(data);

	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/* Only used in SRP currently
 */
int _gnutls_send_client_kx_message0( GNUTLS_STATE state, int again)
{
	uint8 *data;
	int data_size;
	int ret = 0;

	if ( state->gnutls_internals.auth_struct->gnutls_generate_client_kx0 == NULL)
		return 0;


	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_kx0( state, &data);

		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_CLIENT_KEY_EXCHANGE);
	gnutls_free(data);

	return ret;
}


/* This is the function for the client to send the certificate
 * verify message
 */
int _gnutls_send_client_certificate_verify( GNUTLS_STATE state, int again)
{
	uint8 *data;
	int ret = 0;
	int data_size;

	/* This is a packet that is only sent by the client
	 */
	if (state->security_parameters.entity==GNUTLS_SERVER) return 0;
	
	/* if certificate verify is not needed just exit 
	 */
	if (state->gnutls_key->certificate_requested==0) {
		return 0;
	}

	if (state->gnutls_internals.auth_struct->gnutls_generate_client_cert_vrfy==NULL) {
		gnutls_assert();
		return 0; /* this algorithm does not support cli_cert_vrfy 
		           */
	}
	
	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_cert_vrfy( state, &data);
		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
		if (data_size == 0)
			return 0;

	}
	ret =
	    _gnutls_send_handshake( state, data,
				   data_size,
				   GNUTLS_CERTIFICATE_VERIFY);
	gnutls_free(data);

	return ret;
}


int _gnutls_recv_server_kx_message( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_process_server_kx!=NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
				   &datasize,
				   GNUTLS_SERVER_KEY_EXCHANGE, MANDATORY_PACKET);
		if (ret < 0)
			return ret;


		ret = state->gnutls_internals.auth_struct->gnutls_process_server_kx( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;
		
	}
	return ret;
}

int _gnutls_recv_server_certificate_request( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_process_server_certificate_request!=NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
				   &datasize,
				   GNUTLS_CERTIFICATE_REQUEST, OPTIONAL_PACKET);
		if (ret < 0)
			return ret;

		if (ret==0 && datasize == 0)
			return 0; /* ignored */
		
		ret = state->gnutls_internals.auth_struct->gnutls_process_server_certificate_request( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;
		
	}
	return ret;
}

int _gnutls_recv_server_kx_message2( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;


	if (state->gnutls_internals.auth_struct->gnutls_process_server_kx2 != NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
				   &datasize,
				   GNUTLS_SERVER_KEY_EXCHANGE, MANDATORY_PACKET);
		if (ret < 0)
			return ret;


		ret = state->gnutls_internals.auth_struct->gnutls_process_server_kx2( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;

	}
	return ret;
}

int _gnutls_recv_client_kx_message( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;


	/* Do key exchange only if the algorithm permits it */
	if (state->gnutls_internals.auth_struct->gnutls_process_client_kx != NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
					   &datasize,
					   GNUTLS_CLIENT_KEY_EXCHANGE, MANDATORY_PACKET);
		if (ret < 0)
			return ret;

		ret = state->gnutls_internals.auth_struct->gnutls_process_client_kx( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;

	}

	return ret;
}

/* only used in SRP */
int _gnutls_recv_client_kx_message0( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;

	/* Do key exchange only if the algorithm permits it */
	if (state->gnutls_internals.auth_struct->gnutls_process_client_kx0 != NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
					   &datasize,
					   GNUTLS_CLIENT_KEY_EXCHANGE, MANDATORY_PACKET);
		if (ret < 0)
			return ret;

		ret = state->gnutls_internals.auth_struct->gnutls_process_client_kx0( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;

	}
	return ret;
}

/* This is called when we want send our certificate
 */
int _gnutls_send_client_certificate( GNUTLS_STATE state, int again)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;


	if (state->gnutls_key->certificate_requested == 0)
		return 0;

	if (state->gnutls_internals.auth_struct->gnutls_generate_client_certificate==NULL) 
		return 0;

	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_certificate( state, &data);

		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_CERTIFICATE_PKT);
	gnutls_free(data);
	
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	return data_size;
}


/* This is called when we want send our certificate
 */
int _gnutls_send_server_certificate( GNUTLS_STATE state, int again)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;


	if (state->gnutls_internals.auth_struct->gnutls_generate_server_certificate==NULL) 
		return 0;

	data = NULL;
	data_size = 0;

	if (again == 0) {
		data_size = state->gnutls_internals.auth_struct->gnutls_generate_server_certificate( state, &data);

		if (data_size < 0) {
			gnutls_assert();
			return data_size;
		}
	}
	ret = _gnutls_send_handshake( state, data, data_size, GNUTLS_CERTIFICATE_PKT);
	gnutls_free(data);
	
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return data_size;
}


int _gnutls_recv_client_certificate( GNUTLS_STATE state)
{
	int datasize;
	opaque * data;
	int ret = 0;
	int optional;

	if (state->gnutls_internals.auth_struct->gnutls_process_client_certificate!=NULL) {

		/* if we have not requested a certificate then just return
		 */
		if ( state->gnutls_internals.send_cert_req == 0) {
			return 0;
		}

		if ( state->gnutls_internals.send_cert_req == GNUTLS_CERT_REQUIRE)
			optional = MANDATORY_PACKET;
		else 
			optional = OPTIONAL_PACKET;

		ret =
		    _gnutls_recv_handshake( state, &data,
					   &datasize,
					   GNUTLS_CERTIFICATE_PKT, optional);
		if (ret < 0) {
			if (optional == OPTIONAL_PACKET &&
			        ret==GNUTLS_E_WARNING_ALERT_RECEIVED && 
			        gnutls_protocol_get_version(state) == GNUTLS_SSL3 &&
				gnutls_alert_get_last(state)==GNUTLS_A_SSL3_NO_CERTIFICATE) {

				/* SSL3 does not send an empty certificate,
				 * but this alert. So we just ignore it.
				 */
				gnutls_assert();
				return 0;
			}
			/* certificate was required */
			if (optional==MANDATORY_PACKET) {
				gnutls_assert();
			}
			return ret;
		}

		if (ret == 0 && datasize == 0 && optional == OPTIONAL_PACKET) {
			/* well I'm not sure we should accept this
			 * behaviour.
			 */
			gnutls_assert();
			return 0;
		}


		ret = state->gnutls_internals.auth_struct->gnutls_process_client_certificate( state, data, datasize);
		gnutls_free(data);
		if (ret < 0 && ret != GNUTLS_E_NO_CERTIFICATE_FOUND) {
			gnutls_assert();
			return ret;
		}

		/* ok we should expect a certificate verify message now 
		 */
		if (ret==GNUTLS_E_NO_CERTIFICATE_FOUND && optional == OPTIONAL_PACKET)
			ret = 0;
		else
			state->gnutls_key->certificate_requested = 1;

	}

	return ret;
}

int _gnutls_recv_server_certificate( GNUTLS_STATE state)
{
	int datasize;
	opaque * data;
	int ret = 0;

	if (state->gnutls_internals.auth_struct->gnutls_process_server_certificate!=NULL) {

		ret =
		    _gnutls_recv_handshake( state, &data,
					   &datasize,
					   GNUTLS_CERTIFICATE_PKT, MANDATORY_PACKET);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		ret = state->gnutls_internals.auth_struct->gnutls_process_server_certificate( state, data, datasize);
		gnutls_free(data);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}

	return ret;
}


/* Recv the client certificate verify. This packet may not
 * arrive if the peer did not send us a certificate.
 */
int _gnutls_recv_client_certificate_verify_message( GNUTLS_STATE state)
{
	uint8 *data;
	int datasize;
	int ret = 0;


	if (state->gnutls_internals.auth_struct->gnutls_process_client_cert_vrfy != NULL) {

		if ( state->gnutls_internals.send_cert_req == 0 ||
			state->gnutls_key->certificate_requested == 0) {
			return 0;
		}

		ret =
		    _gnutls_recv_handshake( state, &data,
					   &datasize,
					   GNUTLS_CERTIFICATE_VERIFY, OPTIONAL_PACKET);
		if (ret < 0)
			return ret;

		if (ret==0 && datasize == 0 && state->gnutls_internals.send_cert_req == GNUTLS_CERT_REQUIRE) {
			/* certificate was required */
			gnutls_assert();
			return GNUTLS_E_NO_CERTIFICATE_FOUND;
		} 
		
		ret = state->gnutls_internals.auth_struct->gnutls_process_client_cert_vrfy( state, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;

	}

	return ret;
}
