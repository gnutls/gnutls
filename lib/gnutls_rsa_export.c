/*
 * Copyright (C) 2002,2003 Nikos Mavroyanopoulos
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

/* This file contains code for RSA temporary keys. These keys are
 * only used in export cipher suites.
 */
 
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include "debug.h"

/* This function takes a number of bits and returns a supported
 * number of bits. Ie a number of bits that we have a prime in the
 * dh_primes structure.
 */
static int supported_bits[] = { 512, 0 };
static int normalize_bits(int bits)
{
	if (bits >= 512)
		bits = 512;

	return bits;
}


/* returns e and m, depends on the requested bits.
 * We only support limited key sizes.
 */
const GNUTLS_MPI* _gnutls_get_rsa_params(gnutls_rsa_params rsa_params, int bits)
{
	if (rsa_params == NULL) {
		gnutls_assert();
		return NULL;
	}

	bits = normalize_bits(bits);

	return rsa_params->params;

}

/* resarr will contain: modulus(0), public exponent(1), private exponent(2),
 * prime1 - p (3), prime2 - q(4), u (5).
 */
int _gnutls_rsa_generate_params(GNUTLS_MPI* resarr, int bits)
{

	int ret;
	GCRY_SEXP parms, key, list;

	ret = gcry_sexp_build( &parms, NULL, "(genkey(rsa(nbits %d)))", bits);
	if (ret != 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* generate the RSA key */
	ret = gcry_pk_genkey( &key, parms);
	gcry_sexp_release( parms);

	if (ret != 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

       	list = gcry_sexp_find_token( key, "n", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[0] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);

       	list = gcry_sexp_find_token( key, "e", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[1] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);

       	list = gcry_sexp_find_token( key, "d", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[2] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);

       	list = gcry_sexp_find_token( key, "p", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[3] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);


       	list = gcry_sexp_find_token( key, "q", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[4] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);


       	list = gcry_sexp_find_token( key, "u", 0);
	if (list == NULL) {
        	gnutls_assert();
        	gcry_sexp_release( key);
                return GNUTLS_E_INTERNAL_ERROR;
	}

	resarr[5] = gcry_sexp_nth_mpi(list, 1, 0);
	gcry_sexp_release(list);

	gcry_sexp_release(key);

	return 0;

}

/* returns a negative value if the bits size is not supported 
 */
static int check_bits(int bits)
{
	int i = 0;
	do {
		if (supported_bits[i] == bits)
			return 0;
		i++;
	} while (supported_bits[i] != 0);

	gnutls_assert();
	return GNUTLS_E_INVALID_REQUEST;
}

#define FREE_PRIVATE_PARAMS for (i=0;i<RSA_PRIVATE_PARAMS;i++) \
		_gnutls_mpi_release(&rsa_params->params[i])


/**
  * gnutls_rsa_params_set - This function will replace the old RSA parameters
  * @rsa_params: Is a structure will hold the parameters
  * @m: holds the modulus
  * @e: holds the public exponent
  * @d: holds the private exponent
  * @p: holds the first prime (p)
  * @q: holds the second prime (q)
  * @u: holds the coefficient
  * @bits: is the modulus's number of bits
  *
  * This function will replace the parameters used in the RSA-EXPORT key
  * exchange. The new parameters should be stored in the
  * appropriate gnutls_datum. 
  * 
  * Note that the bits value should only be 512. That is because the
  * RSA-EXPORT ciphersuites are only allowed to sign a modulus of 512 bits.
  *
  **/
int gnutls_rsa_params_set(gnutls_rsa_params rsa_params, 
	gnutls_datum m, gnutls_datum e,
	gnutls_datum d, gnutls_datum p, gnutls_datum q, gnutls_datum u,
	int bits) 
{
	int i = 0;
	size_t siz = 0;

	if (check_bits(bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	for (i=0;i<RSA_PRIVATE_PARAMS;i++) {
		_gnutls_mpi_release(&rsa_params->params[i]);
	}

	siz = m.size;
	if (_gnutls_mpi_scan(&rsa_params->params[0], m.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = e.size;
	if (_gnutls_mpi_scan(&rsa_params->params[1], e.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = d.size;
	if (_gnutls_mpi_scan(&rsa_params->params[2], d.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = p.size;
	if (_gnutls_mpi_scan(&rsa_params->params[3], p.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = q.size;
	if (_gnutls_mpi_scan(&rsa_params->params[4], q.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = u.size;
	if (_gnutls_mpi_scan(&rsa_params->params[5], u.data, &siz)) {
		gnutls_assert();
		FREE_PRIVATE_PARAMS;
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;

}

/**
  * gnutls_rsa_params_init - This function will initialize the temporary RSA parameters
  * @rsa_params: Is a structure that will hold the parameters
  *
  * This function will initialize the temporary RSA parameters structure.
  *
  **/
int gnutls_rsa_params_init(gnutls_rsa_params * rsa_params)
{

	*rsa_params = gnutls_calloc( 1, sizeof(_gnutls_rsa_params));
	if (*rsa_params==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;

}

/**
  * gnutls_rsa_params_deinit - This function will deinitialize the RSA parameters
  * @rsa_params: Is a structure that holds the parameters
  *
  * This function will deinitialize the RSA parameters structure.
  *
  **/
void gnutls_rsa_params_deinit(gnutls_rsa_params rsa_params)
{
int i;

	if (rsa_params == NULL)
		return;

	for (i=0; i< RSA_PRIVATE_PARAMS;i++)
		_gnutls_mpi_release( &rsa_params->params[i]);

	gnutls_free(rsa_params);

}

#define FREE_ALL_MPIS for (i=0;i<sizeof(rsa_params)/sizeof(GNUTLS_MPI);i++) \
	_gnutls_mpi_release( &rsa_params[i]) \

/**
  * gnutls_rsa_params_generate - This function will generate temporary RSA parameters
  * @m: will hold the modulus
  * @e: will hold the public exponent
  * @d: will hold the private exponent
  * @p: will hold the first prime (p)
  * @q: will hold the second prime (q)
  * @u: will hold the coefficient
  * @bits: is the prime's number of bits
  *
  * This function will generate new temporary RSA parameters for use in 
  * RSA-EXPORT ciphersuites. The new parameters will be allocated using
  * malloc and will be stored in the appropriate datum.
  * This function is normally slow. An other function
  * (gnutls_rsa_params_set()) should be called in order to use the 
  * generated RSA parameters.
  * 
  * Note that the bits value should be 512.
  * Also note that the generation of new RSA parameters is only usefull
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  **/
int gnutls_rsa_params_generate(gnutls_datum * m, gnutls_datum *e,
	gnutls_datum *d, gnutls_datum *p, gnutls_datum* q, 
	gnutls_datum* u, int bits)
{

	GNUTLS_MPI rsa_params[RSA_PRIVATE_PARAMS];
	size_t siz;
	uint i;
	int ret;

	if (check_bits(bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	ret = _gnutls_rsa_generate_params( rsa_params, bits);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[0]);

	m->data = malloc(siz);
	if (m->data == NULL) {
		FREE_ALL_MPIS;
		return GNUTLS_E_MEMORY_ERROR;
	}

	m->size = siz;
	_gnutls_mpi_print( m->data, &siz, rsa_params[0]);

	/* E */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[1]);

	e->data = malloc(siz);
	if (e->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		return GNUTLS_E_MEMORY_ERROR;
	}

	e->size = siz;
	_gnutls_mpi_print( e->data, &siz, rsa_params[1]);

	/* D */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[2]);

	d->data = malloc(siz);
	if (d->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		return GNUTLS_E_MEMORY_ERROR;
	}

	d->size = siz;
	_gnutls_mpi_print( d->data, &siz, rsa_params[2]);

	/* P */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[3]);

	p->data = malloc(siz);
	if (p->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		return GNUTLS_E_MEMORY_ERROR;
	}

	p->size = siz;
	_gnutls_mpi_print(p->data, &siz, rsa_params[3]);

	/* Q */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[4]);

	q->data = malloc(siz);
	if (q->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		return GNUTLS_E_MEMORY_ERROR;
	}

	q->size = siz;
	_gnutls_mpi_print(q->data, &siz, rsa_params[4]);

	/* U */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[5]);

	u->data = malloc(siz);
	if (u->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		_gnutls_free_datum( q);
		return GNUTLS_E_MEMORY_ERROR;
	}

	u->size = siz;
	_gnutls_mpi_print(u->data, &siz, rsa_params[5]);

	FREE_ALL_MPIS;

	_gnutls_log("Generated %d bits modulus %s, exponent %s.\n",
		    bits, _gnutls_bin2hex(m->data, m->size),
		    _gnutls_bin2hex( e->data, e->size));

	return 0;

}
