/*
 * Copyright (C) 2000,2001,2003 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <x509_b64.h> /* for PKCS3 PEM decoding */
#include <gnutls_global.h>
#include <gnutls_dh.h>
#include "debug.h"

/* Replaces the prime in the static DH parameters, with a randomly
 * generated one.
 */
/*-
  * gnutls_dh_params_set - This function will replace the old DH parameters
  * @dh_params: Is a structure will hold the prime numbers
  * @prime: holds the new prime
  * @generator: holds the new generator
  * @bits: is the prime's number of bits. This value is ignored.
  *
  * This function will replace the pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters should be stored in the
  * appropriate gnutls_datum. 
  * 
  -*/
int gnutls_dh_params_set(gnutls_dh_params dh_params, gnutls_datum prime,
			 gnutls_datum generator, int bits)
{
	GNUTLS_MPI tmp_prime, tmp_g;
	size_t siz = 0;

	/* sprime is not null, because of the check_bits()
	 * above.
	 */

	siz = prime.size;
	if (_gnutls_mpi_scan(&tmp_prime, prime.data, &siz)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = generator.size;
	if (_gnutls_mpi_scan(&tmp_g, generator.data, &siz)) {
		_gnutls_mpi_release(&tmp_prime);
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* copy the generated values to the structure
	 */
	dh_params->_prime = tmp_prime;
	dh_params->_generator = tmp_g;

	return 0;

}

/*-
  * gnutls_dh_params_generate - This function will generate new DH parameters
  * @prime: will hold the new prime
  * @generator: will hold the new generator
  * @bits: is the prime's number of bits
  *
  * This function will generate a new pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * This function is normally very slow. An other function
  * (gnutls_dh_params_set()) should be called in order to replace the 
  * included DH primes in the gnutls library.
  * 
  * Note that the bits value should be one of 768, 1024, 2048, 3072 or 4096.
  * Also note that the generation of new DH parameters is only usefull
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  -*/
int gnutls_dh_params_generate(gnutls_datum * prime,
			      gnutls_datum * generator, int bits)
{

	GNUTLS_MPI tmp_prime, tmp_g;
	size_t siz;

	if (_gnutls_dh_generate_prime(&tmp_g, &tmp_prime, bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	siz = 0;
	_gnutls_mpi_print(NULL, &siz, tmp_g);

	generator->data = gnutls_malloc(siz);
	if (generator->data == NULL) {
		_gnutls_mpi_release(&tmp_g);
		_gnutls_mpi_release(&tmp_prime);
		return GNUTLS_E_MEMORY_ERROR;
	}

	generator->size = siz;
	_gnutls_mpi_print(generator->data, &siz, tmp_g);


	siz = 0;
	_gnutls_mpi_print(NULL, &siz, tmp_prime);

	prime->data = gnutls_malloc(siz);
	if (prime->data == NULL) {
		gnutls_free(generator->data);
		generator->data = NULL; generator->size = 0;
		_gnutls_mpi_release(&tmp_g);
		_gnutls_mpi_release(&tmp_prime);
		return GNUTLS_E_MEMORY_ERROR;
	}
	prime->size = siz;
	_gnutls_mpi_print(prime->data, &siz, tmp_prime);

#ifdef DEBUG
	{
		opaque buffer[512];

		_gnutls_debug_log
		    ("dh_params_generate: Generated %d bits prime %s, generator %s.\n",
	     	bits, _gnutls_bin2hex(prime->data, prime->size, buffer, sizeof(buffer)),
	     	_gnutls_bin2hex(generator->data, generator->size, buffer, sizeof(buffer)));
	}
#endif

	return 0;

}
