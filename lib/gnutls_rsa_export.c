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
#include <gnutls_rsa_export.h>
#include "debug.h"

/* This function takes a number of bits and returns a supported
 * number of bits. Ie a number of bits that we have a prime in the
 * dh_primes structure.
 */

#define MAX_SUPPORTED_BITS 512

static int normalize_bits(int bits)
{
	if (bits >= MAX_SUPPORTED_BITS)
		bits = MAX_SUPPORTED_BITS;

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

#define FREE_PRIVATE_PARAMS for (i=0;i<RSA_PRIVATE_PARAMS;i++) \
		_gnutls_mpi_release(&rsa_params->params[i])


/**
  * gnutls_rsa_params_import_raw - This function will replace the old RSA parameters
  * @rsa_params: Is a structure will hold the parameters
  * @m: holds the modulus
  * @e: holds the public exponent
  * @d: holds the private exponent
  * @p: holds the first prime (p)
  * @q: holds the second prime (q)
  * @u: holds the coefficient
  *
  * This function will replace the parameters in the given structure.
  * The new parameters should be stored in the appropriate gnutls_datum. 
  * 
  **/
int gnutls_rsa_params_import_raw(gnutls_rsa_params rsa_params, 
	gnutls_datum m, gnutls_datum e,
	gnutls_datum d, gnutls_datum p, gnutls_datum q, gnutls_datum u)
{
	int i = 0;
	size_t siz = 0;

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

/**
  * gnutls_rsa_params_generate2 - This function will generate temporary RSA parameters
  * @params: The structure where the parameters will be stored
  * @bits: is the prime's number of bits
  *
  * This function will generate new temporary RSA parameters for use in 
  * RSA-EXPORT ciphersuites.  This function is normally slow. 
  * 
  * Note that if the parameters are to be used in export cipher suites the 
  * bits value should be 512 or less.
  * Also note that the generation of new RSA parameters is only usefull
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  **/
int gnutls_rsa_params_generate2(gnutls_rsa_params params, int bits)
{

	int ret;

	ret = _gnutls_rsa_generate_params( params->params, bits);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;

}

/**
  * gnutls_rsa_params_export_raw - This function will export the RSA parameters
  * @params: a structure that holds the rsa parameters
  * @m: will hold the modulus
  * @e: will hold the public exponent
  * @d: will hold the private exponent
  * @p: will hold the first prime (p)
  * @q: will hold the second prime (q)
  * @u: will hold the coefficient
  * @bits: if non null will hold the prime's number of bits
  *
  * This function will export the RSA parameters found in the given
  * structure. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * 
  **/
int gnutls_rsa_params_export_raw(gnutls_rsa_params params,
	gnutls_datum * m, gnutls_datum *e,
	gnutls_datum *d, gnutls_datum *p, gnutls_datum* q, 
	gnutls_datum* u, int *bits)
{
	size_t siz;

	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[0]);

	m->data = gnutls_malloc(siz);
	if (m->data == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	m->size = siz;
	_gnutls_mpi_print( m->data, &siz, params->params[0]);

	/* E */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[1]);

	e->data = gnutls_malloc(siz);
	if (e->data == NULL) {
		_gnutls_free_datum( m);
		return GNUTLS_E_MEMORY_ERROR;
	}

	e->size = siz;
	_gnutls_mpi_print( e->data, &siz, params->params[1]);

	/* D */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[2]);

	d->data = gnutls_malloc(siz);
	if (d->data == NULL) {
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		return GNUTLS_E_MEMORY_ERROR;
	}

	d->size = siz;
	_gnutls_mpi_print( d->data, &siz, params->params[2]);

	/* P */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[3]);

	p->data = gnutls_malloc(siz);
	if (p->data == NULL) {
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		return GNUTLS_E_MEMORY_ERROR;
	}

	p->size = siz;
	_gnutls_mpi_print(p->data, &siz, params->params[3]);

	/* Q */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[4]);

	q->data = gnutls_malloc(siz);
	if (q->data == NULL) {
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		return GNUTLS_E_MEMORY_ERROR;
	}

	q->size = siz;
	_gnutls_mpi_print(q->data, &siz, params->params[4]);

	/* U */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, params->params[5]);

	u->data = gnutls_malloc(siz);
	if (u->data == NULL) {
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		_gnutls_free_datum( q);
		return GNUTLS_E_MEMORY_ERROR;
	}

	u->size = siz;
	_gnutls_mpi_print(u->data, &siz, params->params[5]);
	
	if (bits)
		*bits = _gnutls_mpi_get_nbits(params->params[3]);

	return 0;

}
