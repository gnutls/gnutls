/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include "defines.h"
#include "gnutls_int.h"
#include "gnutls_handshake.h"
#include "gnutls_kx.h"
#include "gnutls_dh.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"
#include "debug.h"

#define MASTER_SECRET "master secret"

/* This is called when we want to receive the key exchange message of the
 * server. It does nothing if this type of message is not required
 * by the selected ciphersuite. 
 */
int _gnutls_send_server_kx_message(int cd, GNUTLS_STATE state)
{
	uint8 *data = NULL;
	int data_size = 0;
	int ret = 0;

#ifdef HARD_DEBUG
	fprintf(stderr, "Sending server KX message\n");
#endif
	data_size = state->gnutls_internals.auth_struct->gnutls_generate_server_kx( state->gnutls_key, &data);

	if (data_size<0) {
		gnutls_assert();
		return data_size;
	}

	ret = _gnutls_send_handshake(cd, state, data, data_size, GNUTLS_SERVER_KEY_EXCHANGE);
	gnutls_free(data);
	
	return data_size;
}

/* This is the function for the client to send the key
 * exchange message 
 */
int _gnutls_send_client_kx_message(int cd, GNUTLS_STATE state)
{
	uint8 *data;
	int data_size;
	int ret = 0;
	uint8 *premaster = NULL;
	int premaster_size = 0;
	svoid *master;
	char random[64];

#ifdef HARD_DEBUG
	int i;
	fprintf(stderr, "Sending client KX message\n");
#endif

	memmove(random, state->security_parameters.client_random, 32);
	memmove(&random[32], state->security_parameters.server_random, 32);

	data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_kx( state->gnutls_key, &data);
	if (data_size < 0) {
		gnutls_assert();
		return data_size;
	}

        ret = _gnutls_send_handshake(cd, state, data, data_size, GNUTLS_CLIENT_KEY_EXCHANGE);
	gnutls_free(data);
	
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &premaster_size, state->gnutls_key->KEY);
	premaster = secure_malloc(premaster_size);
	gcry_mpi_print(GCRYMPI_FMT_USG, premaster, &premaster_size, state->gnutls_key->KEY);

#ifdef HARD_DEBUG
	fprintf(stderr, "PREMASTER SECRET: ");
	for (i=0;i<premaster_size;i++) fprintf(stderr, "%x",premaster[i]);
	fprintf(stderr, "\n");
#endif

	/* THIS SHOULD BE DISCARDED */
	gnutls_mpi_release(state->gnutls_key->KEY);
	state->gnutls_key->KEY = NULL;


	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		master =
		    gnutls_ssl3_generate_random( premaster, premaster_size,
			       random, 64, 48);
	} else {
		master =
		    gnutls_PRF( premaster, premaster_size,
			       MASTER_SECRET, strlen(MASTER_SECRET), random, 64,
			       48);
	}
	secure_free(premaster);
#ifdef HARD_DEBUG
	fprintf(stderr, "MASTER SECRET: %s\n", _gnutls_bin2hex(master, 48));
#endif
	memmove(state->security_parameters.master_secret, master, 48);
	secure_free(master);
	return ret;
}

/* This is the function for the client to send the certificate
 * verify message
 * FIXME: this function does almost nothing except sending garbage to
 * peer.
 */
int _gnutls_send_client_certificate_verify(int cd, GNUTLS_STATE state)
{
	uint8 *data;
	int ret = 0;
	int data_size;

	/* if certificate verify is not needed just exit */
	if (state->gnutls_internals.certificate_verify_needed==0) return 0;

#ifdef HARD_DEBUG
	fprintf(stderr, "Sending client certificate verify message\n");
#endif
	data_size = state->gnutls_internals.auth_struct->gnutls_generate_client_cert_vrfy( state->gnutls_key, &data);
	if (data_size < 0) 
		return data_size;
	ret =
	    _gnutls_send_handshake(cd, state, data,
				   data_size,
				   GNUTLS_CERTIFICATE_VERIFY);
	gnutls_free(data);

	return ret;
}


int _gnutls_recv_server_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	uint8 *data;
	int datasize;
	int ret = 0;

#ifdef HARD_DEBUG
	fprintf(stderr, "Receiving Server KX message\n");
#endif
	algorithm =
	    _gnutls_cipher_suite_get_kx_algo
	    (state->gnutls_internals.current_cipher_suite);

	if (_gnutls_kx_server_key_exchange(algorithm) != 0) {
		ret =
		    _gnutls_recv_handshake(cd, state, &data,
				   &datasize,
				   GNUTLS_SERVER_KEY_EXCHANGE);
		if (ret < 0)
			return ret;


		ret = state->gnutls_internals.auth_struct->gnutls_process_server_kx( state->gnutls_key, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;
		
	}
	return ret;
}

int _gnutls_recv_client_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	uint8 *data;
#ifdef HARD_DEBUG
	int i;
#endif
	int datasize;
	int ret = 0;
	uint8 *premaster = NULL;
	int premaster_size = 0;
	svoid *master;
	uint8 random[64];

#ifdef HARD_DEBUG
	fprintf(stderr, "Receiving client KX message\n");
#endif
	memmove(random, state->security_parameters.client_random, 32);
	memmove(&random[32], state->security_parameters.server_random, 32);

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo
	    (state->gnutls_internals.current_cipher_suite);

	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_server_key_exchange(algorithm) != 0) {

		ret =
		    _gnutls_recv_handshake(cd, state, &data,
					   &datasize,
					   GNUTLS_CLIENT_KEY_EXCHANGE);
		if (ret < 0)
			return ret;

		ret = state->gnutls_internals.auth_struct->gnutls_process_client_kx( state->gnutls_key, data, datasize);
		gnutls_free(data);
		if (ret < 0)
			return ret;

           	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &premaster_size, state->gnutls_key->KEY);
		premaster = secure_malloc(premaster_size);
		gcry_mpi_print(GCRYMPI_FMT_USG, premaster, &premaster_size, state->gnutls_key->KEY);

		/* THIS SHOULD BE DISCARDED */
		gnutls_mpi_release(state->gnutls_key->KEY);
		state->gnutls_key->KEY = NULL;

	}

#ifdef HARD_DEBUG
		fprintf(stderr, "PREMASTER SECRET: ");
		for (i=0;i<premaster_size;i++) fprintf(stderr, "%x",premaster[i]);
		fprintf(stderr, "\n");
#endif

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		master =
		    gnutls_ssl3_generate_random( premaster, premaster_size,
			       random, 64, 48);

	} else {
		master =
		    gnutls_PRF( premaster, premaster_size,
			       MASTER_SECRET, strlen(MASTER_SECRET),
			       random, 64, 48); 
	}
	secure_free(premaster);
#ifdef HARD_DEBUG
	fprintf(stderr, "master secret: %s\n", _gnutls_bin2hex(master, 48));
#endif
	memmove(state->security_parameters.master_secret, master, 48);
	secure_free(master);
	return ret;
}
