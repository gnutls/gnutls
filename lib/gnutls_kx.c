#include "defines.h"
#include "gnutls_int.h"
#include "gnutls_kx.h"
#include "gnutls_dh.h"
#include "gnutls_errors.h"

#define MASTER_SECRET "master secret"

int _gnutls_send_server_kx_message(int cd, GNUTLS_STATE state)
{
	KX_Algorithm algorithm;
	MPI x, X, g, p;
	int n_X, n_g, n_p;
	uint16 _n_X, _n_g, _n_p;
	uint8 data[1536];	/* 3*512 */
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	int ret=0;


	n_X = n_g = n_p = 512 - 2;

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo(state->
					     gnutls_internals.current_cipher_suite);

	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_algo_server_key_exchange(algorithm) != 0) {

		if ( _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite) == KX_ANON_DH) {
			X = _gnutls_calc_dh_secret(&x);

			state->gnutls_internals.dh_secret = x;

			g = _gnutls_get_dh_params(&p);


			data_p = &data[0];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_p[2],
				       &n_p, p);
			mpi_release(p);

			_n_p = n_p;
#ifndef WORDS_BIGENDIAN
			_n_p = byteswap16(_n_p);
			memmove(data_p, &_n_p, 2);
#else
			memmove(data_p, &_n_p, 2);
#endif


			data_g = &data_p[2+n_p];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_g[2],
				       &n_g, g);
			mpi_release(g);
			_n_g = n_g;
#ifndef WORDS_BIGENDIAN

			_n_g = byteswap16(_n_g);
			memmove(data_g, &_n_g, 2);
#else
			memmove(data_g, &_n_g, 2);
#endif

			data_X = &data_g[2+n_g];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_X[2],
				       &n_X, X);
			mpi_release(X);
			
			_n_X = n_X;
#ifndef WORDS_BIGENDIAN
			_n_X = byteswap16(_n_X);
			memmove(data_X, &_n_X, 2);
#else
			memmove(data_X, &_n_X, 2);
#endif

			ret =
			    _gnutls_send_handshake(cd, state, data,
						   n_p + n_g + n_X + 6,
						   GNUTLS_SERVER_KEY_EXCHANGE);
		} else {
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	return ret;

}

int _gnutls_send_client_kx_message(int cd, GNUTLS_STATE state)
{
	KX_Algorithm algorithm;
	MPI x, X;
	int n_X;
	uint16 _n_X;
	uint8 data[1536];	/* 3*512 */
	int ret=0;
	uint8 premaster[1500];
	int premaster_size = sizeof(premaster);
	svoid* master;
	char* random = gnutls_malloc(64);
	
	memmove( random, state->security_parameters.client_random, 32);
	memmove( &random[32], state->security_parameters.server_random, 32);

	n_X = 1530;

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo(state->
					     gnutls_internals.current_cipher_suite);

	if ( _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite) == KX_ANON_DH) {

			data[0] = 1; /* extern */
			
			X = __gnutls_calc_dh_secret(&x, state->gnutls_internals.client_g, state->gnutls_internals.client_p);
			gcry_mpi_print(GCRYMPI_FMT_STD, &data[3],
				       &n_X, X);

			mpi_release(X);
			
			_n_X = n_X;
#ifndef WORDS_BIGENDIAN
			_n_X = byteswap16(_n_X);
			memmove(&data[1], &_n_X, 2);
#else
			memmove(&data[1], &_n_X, 2);
#endif

			ret =
			    _gnutls_send_handshake(cd, state, data,
						   n_X + 3,
						   GNUTLS_CLIENT_KEY_EXCHANGE);

			/* calculate the key after sending the message */
			state->gnutls_internals.KEY = __gnutls_calc_dh_key( state->gnutls_internals.client_Y, x, state->gnutls_internals.client_p);
			gcry_mpi_print(GCRYMPI_FMT_STD, premaster,
				       &premaster_size, state->gnutls_internals.KEY);

			/* THIS SHOULD BE DISCARDED */
			mpi_release(state->gnutls_internals.KEY);
			mpi_release(state->gnutls_internals.client_Y);
			mpi_release(state->gnutls_internals.client_p);
			mpi_release(state->gnutls_internals.client_g);
			state->gnutls_internals.KEY=NULL;
			state->gnutls_internals.client_Y=NULL;
			state->gnutls_internals.client_p=NULL;
			state->gnutls_internals.client_g=NULL;
		} else {
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	master = gnutls_PRF( premaster, premaster_size, MASTER_SECRET, strlen(MASTER_SECRET),
						random, 64 ,48);

#ifdef HARD_DEBUG
	fprintf(stderr, "master secret: %s\n", bin2hex(master, 48));
#endif
	memmove( state->security_parameters.master_secret, master, 48);

	secure_free(master);
	gnutls_free(random);
	
	return ret;

}

int _gnutls_recv_server_kx_message(int cd, GNUTLS_STATE state)
{
	KX_Algorithm algorithm;
	uint16 n_Y, n_g, n_p;
	int _n_Y, _n_g, _n_p;
	uint8 data[15000];
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int ret=0, i=0;

	n_Y = n_g = n_p = 512 - 2;

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo(state->
					     gnutls_internals.current_cipher_suite);

	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_algo_server_key_exchange(algorithm) != 0) {

		if ( _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite) == KX_ANON_DH) {

			state->gnutls_internals.next_handshake_type = GNUTLS_SERVER_KEY_EXCHANGE;
			ret = gnutls_recv_int(cd, state, GNUTLS_HANDSHAKE, data, 15000);
			state->gnutls_internals.next_handshake_type = GNUTLS_NONE;


			memmove( &n_p, &data[i], 2);
			i+=2;
#ifndef WORDS_BIGENDIAN
			n_p = byteswap16(n_p);
#endif
			data_p = &data[i];
			i+=n_p;	
			
			memmove( &n_g, &data[i], 2);
#ifndef WORDS_BIGENDIAN
			n_g = byteswap16(n_g);
#endif
			i+=2;
			data_g = &data[i];
			i+=n_g;
			
			memmove( &n_Y, &data[i], 2);
			i+=2;
#ifndef WORDS_BIGENDIAN
			n_Y = byteswap16(n_Y);
#endif
			data_Y = &data[i];
			i+=n_Y;
			
			_n_Y = n_Y;
			_n_g = n_g;
			_n_p = n_p;
			
			gcry_mpi_scan( &state->gnutls_internals.client_Y, GCRYMPI_FMT_STD, data_Y, &_n_Y);
			gcry_mpi_scan( &state->gnutls_internals.client_g, GCRYMPI_FMT_STD, data_g, &_n_g);
			gcry_mpi_scan( &state->gnutls_internals.client_p, GCRYMPI_FMT_STD, data_p, &_n_p);
		} else {
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	return ret;

}

int _gnutls_recv_client_kx_message(int cd, GNUTLS_STATE state)
{
	KX_Algorithm algorithm;
	uint16 n_Y;
	int _n_Y;
	uint8 data[1000];
	int ret=0;
	uint8 premaster[1500];
	int premaster_size = sizeof(premaster);
	svoid* master;
	char* random = gnutls_malloc(64);
	
	memmove( random, state->security_parameters.client_random, 32);
	memmove( &random[32], state->security_parameters.server_random, 32);

	n_Y = 1000 - 3;

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo(state->
					     gnutls_internals.current_cipher_suite);

	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_algo_server_key_exchange(algorithm) != 0) {

		if ( _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite) == KX_ANON_DH) {

			state->gnutls_internals.next_handshake_type = GNUTLS_CLIENT_KEY_EXCHANGE;
			ret = gnutls_recv_int(cd, state, GNUTLS_HANDSHAKE, data, 15000);
			state->gnutls_internals.next_handshake_type = GNUTLS_NONE;
			
			if ( data[0] != 1) return GNUTLS_E_UNIMPLEMENTED_FEATURE;

			memmove( &n_Y, &data[1], 2);
#ifndef WORDS_BIGENDIAN
			n_Y = byteswap16(n_Y);
#endif

			_n_Y = n_Y;
			
			gcry_mpi_scan( &state->gnutls_internals.client_Y, GCRYMPI_FMT_STD, &data[3], &_n_Y);
			state->gnutls_internals.KEY = _gnutls_calc_dh_key( state->gnutls_internals.client_Y, state->gnutls_internals.dh_secret);

			gcry_mpi_print(GCRYMPI_FMT_STD, premaster,
				       &premaster_size, state->gnutls_internals.KEY);
			/* THIS SHOULD BE DISCARDED */
			mpi_release(state->gnutls_internals.KEY);
			mpi_release(state->gnutls_internals.client_Y);
			mpi_release(state->gnutls_internals.dh_secret);
			state->gnutls_internals.KEY=NULL;
			state->gnutls_internals.client_Y=NULL;
			state->gnutls_internals.dh_secret=NULL;
		} else {
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	master = gnutls_PRF( premaster, premaster_size, MASTER_SECRET, strlen(MASTER_SECRET),
						random, 64 ,48);


#ifdef HARD_DEBUG
	fprintf(stderr, "master secret: %s\n", bin2hex(master, 48));
#endif
	memmove( state->security_parameters.master_secret, master, 48);

	secure_free(master);
	gnutls_free(random);

	return ret;

}


