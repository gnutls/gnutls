/*
 *  Copyright (C) 2000,2001,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
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
#include <x509/mpi.h>
#include "debug.h"


/* returns the prime and the generator of DH params.
 */
int _gnutls_get_dh_params(gnutls_dh_params dh_primes,
				GNUTLS_MPI * ret_p, GNUTLS_MPI * ret_g)
{
	GNUTLS_MPI g = NULL, prime = NULL;

	if (dh_primes == NULL || dh_primes->_prime == NULL ||
		dh_primes->_generator == NULL) 
	{
		gnutls_assert();
		return GNUTLS_E_NO_TEMPORARY_DH_PARAMS;
	}

	prime = _gnutls_mpi_copy(dh_primes->_prime);
	g = _gnutls_mpi_copy(dh_primes->_generator);

	if (prime == NULL || g == NULL) {	/* if not prime was found */
		gnutls_assert();
		_gnutls_mpi_release(&g);
		_gnutls_mpi_release(&prime);
		*ret_p = NULL;
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (ret_p)
		*ret_p = prime;
	if (ret_g)
		*ret_g = g;
	return 0;
}

/* These should be added in gcrypt.h */
GNUTLS_MPI _gcry_generate_elg_prime(int mode, unsigned pbits,
				    unsigned qbits, GNUTLS_MPI g,
				    GNUTLS_MPI ** ret_factors);

int _gnutls_dh_generate_prime(GNUTLS_MPI * ret_g, GNUTLS_MPI * ret_n,
			      int bits)
{

	GNUTLS_MPI g, prime;
	int qbits;

	g = mpi_new(16);	/* this should be ok */
	if (g == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* generate a random prime */
	/* this is an emulation of Michael Wiener's table
	 * bad emulation.
	 */
	qbits = 120 + (((bits / 256) - 1) * 20);
	if (qbits & 1)		/* better have a even one */
		qbits++;

	prime = _gcry_generate_elg_prime(0, bits, qbits, g, NULL);
	if (prime == NULL || g == NULL) {
		_gnutls_mpi_release(&g);
		_gnutls_mpi_release(&prime);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (ret_g)
		*ret_g = g;
	if (ret_n)
		*ret_n = prime;

	return 0;

}

/* Replaces the prime in the static DH parameters, with a randomly
 * generated one.
 */
/**
  * gnutls_dh_import_raw - This function will import DH parameters
  * @dh_params: Is a structure that will hold the prime numbers
  * @prime: holds the new prime
  * @generator: holds the new generator
  *
  * This function will replace the pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters should be stored in the
  * appropriate gnutls_datum. 
  * 
  **/
int gnutls_dh_params_import_raw(gnutls_dh_params dh_params, const gnutls_datum *prime,
			const gnutls_datum* generator)
{
	GNUTLS_MPI tmp_prime, tmp_g;
	size_t siz = 0;

	siz = prime->size;
	if (_gnutls_mpi_scan(&tmp_prime, prime->data, &siz)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = generator->size;
	if (_gnutls_mpi_scan(&tmp_g, generator->data, &siz)) {
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

/**
  * gnutls_dh_params_init - This function will initialize the DH parameters
  * @dh_params: Is a structure that will hold the prime numbers
  *
  * This function will initialize the DH parameters structure.
  *
  **/
int gnutls_dh_params_init(gnutls_dh_params * dh_params)
{

	(*dh_params) = gnutls_calloc(1, sizeof(_gnutls_dh_params));
	if (*dh_params == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;

}

/**
  * gnutls_dh_params_deinit - This function will deinitialize the DH parameters
  * @dh_params: Is a structure that holds the prime numbers
  *
  * This function will deinitialize the DH parameters structure.
  *
  **/
void gnutls_dh_params_deinit(gnutls_dh_params dh_params)
{
	if (dh_params == NULL)
		return;

	_gnutls_mpi_release(&dh_params->_prime);
	_gnutls_mpi_release(&dh_params->_generator);

	gnutls_free(dh_params);

}

/**
  * gnutls_dh_params_generate2 - This function will generate new DH parameters
  * @params: Is the structure that the DH parameters will be stored
  * @bits: is the prime's number of bits
  *
  * This function will generate a new pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * This function is normally slow. 
  * 
  * Note that the bits value should be one of 768, 1024, 2048, 3072 or 4096.
  * Also note that the DH parameters are only usefull to servers. 
  * Since clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  **/
int gnutls_dh_params_generate2(gnutls_dh_params params, int bits)
{

	if (_gnutls_dh_generate_prime(&params->_generator, 
		&params->_prime, bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;
}

/**
  * gnutls_dh_params_import_pkcs3 - This function will import DH params from a pkcs3 structure
  * @params: A structure were the parameters will be copied to
  * @pkcs3_params: should contain a PKCS3 DHParams structure PEM or DER encoded
  * @format: the format of params. PEM or DER.
  *
  * This function will extract the DHParams found in a PKCS3 formatted
  * structure. This is the format generated by "openssl dhparam" tool.
  * The output will be allocated using gnutls_malloc() and will be put
  * in prime and generator structures.
  *
  * If the structure is PEM encoded, it should have a header
  * of "BEGIN DH PARAMETERS".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_dh_params_import_pkcs3(gnutls_dh_params params, 
	const gnutls_datum * pkcs3_params, gnutls_x509_crt_fmt format)
{
	ASN1_TYPE c2;
	int result, need_free = 0;
	gnutls_datum _params;

	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;

		result = _gnutls_fbase64_decode("DH PARAMETERS",
						pkcs3_params->data, pkcs3_params->size,
						&out);

		if (result <= 0) {
			if (result==0) result = GNUTLS_E_INTERNAL_ERROR;
			gnutls_assert();
			return result;
		}

		_params.data = out;
		_params.size = result;
		
		need_free = 1;

	} else {
		_params.data = pkcs3_params->data;
		_params.size = pkcs3_params->size;
	}

	if ((result = asn1_create_element
	     (_gnutls_get_gnutls_asn(), "GNUTLS.DHParameter", &c2))
	    != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding(&c2, _params.data, _params.size, NULL);
	    
	if (need_free != 0) gnutls_free( _params.data);

	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */

		_gnutls_x509_log("DHParams: Decoding error %d\n", result);
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	/* Read PRIME 
	 */
	result = _gnutls_x509_read_int( c2, "prime", &params->_prime);
	if ( result < 0) {
		asn1_delete_structure(&c2);
		gnutls_assert();
		return result;
	}

	/* read the generator
	 */
	result = _gnutls_x509_read_int( c2, "base", &params->_generator);
	if ( result < 0) {
		asn1_delete_structure(&c2);
		_gnutls_mpi_release( &params->_prime);
		gnutls_assert();
		return result;
	}

	asn1_delete_structure(&c2);

	return 0;
}

/**
  * gnutls_dh_params_export_pkcs3 - This function will export DH params to a pkcs3 structure
  * @params: Holds the DH parameters
  * @format: the format of output params. One of PEM or DER.
  * @params_data: will contain a PKCS3 DHParams structure PEM or DER encoded
  * @params_data_size: holds the size of params_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the given dh parameters to a PKCS3
  * DHParams structure. This is the format generated by "openssl dhparam" tool.
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN DH PARAMETERS".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_dh_params_export_pkcs3( gnutls_dh_params params,
	   gnutls_x509_crt_fmt format, unsigned char* params_data, int* params_data_size)
{
	ASN1_TYPE c2;
	int result;
	size_t g_size, p_size;
	opaque * p_data, *g_data;
	opaque * all_data;
	
	_gnutls_mpi_print( NULL, &g_size, params->_generator);
	_gnutls_mpi_print( NULL, &p_size, params->_prime);

	all_data = gnutls_alloca( g_size + p_size);
	if (all_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	p_data = &all_data[0];
	g_data = &all_data[p_size];
	
	_gnutls_mpi_print( p_data, &p_size, params->_prime);
	_gnutls_mpi_print( g_data, &g_size, params->_generator);

	/* Ok. Now we have the data. Create the asn1 structures
	 */	

	if ((result = asn1_create_element
	     (_gnutls_get_gnutls_asn(), "GNUTLS.DHParameter", &c2))
	    != ASN1_SUCCESS) {
		gnutls_assert();
		gnutls_afree(all_data);
		return _gnutls_asn2err(result);
	}

	/* Write PRIME 
	 */
	if ((result = asn1_write_value(c2, "prime",
					    p_data, p_size)) != ASN1_SUCCESS) 
	{
		gnutls_assert();
		gnutls_afree(all_data);
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	/* Write the GENERATOR
	 */
	if ((result = asn1_write_value(c2, "base",
					    g_data, g_size)) != ASN1_SUCCESS) {
		gnutls_assert();
		gnutls_afree(all_data);
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	gnutls_afree(all_data);

	if ((result = asn1_write_value(c2, "privateValueLength",
					    NULL, 0)) != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	if (format == GNUTLS_X509_FMT_DER) {
		if (params_data == NULL) *params_data_size = 0;

		if ((result=asn1_der_coding( c2, "", params_data, params_data_size, NULL)) != ASN1_SUCCESS) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			
			if (result == ASN1_MEM_ERROR)
				return GNUTLS_E_SHORT_MEMORY_BUFFER;

			return _gnutls_asn2err(result);
		}

		asn1_delete_structure(&c2);

	} else { /* PEM */
		opaque *tmp;
		opaque *out;
		int len;

		len = 0;
		asn1_der_coding( c2, "", NULL, &len, NULL);

		tmp = gnutls_alloca( len);
		if (tmp == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		if ((result=asn1_der_coding( c2, "", tmp, &len, NULL)) != ASN1_SUCCESS) {
			gnutls_assert();
			gnutls_afree( tmp);
			asn1_delete_structure(&c2);
			return _gnutls_asn2err(result);
		}

		asn1_delete_structure(&c2);
		
		result = _gnutls_fbase64_encode("DH PARAMETERS",
						tmp, len, &out);

		gnutls_afree( tmp);

		if (result < 0) {
			gnutls_assert();
			return result;
		}

		if (result == 0) {	/* oooops */
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if (result + 1 > *params_data_size) {
			gnutls_assert();
			gnutls_free(out);
			*params_data_size = result;
			return GNUTLS_E_SHORT_MEMORY_BUFFER;
		}

		*params_data_size = result;
		
		if (params_data) {
			memcpy( params_data, out, result);
			params_data[result] = 0;
		}
		gnutls_free( out);
		
	}

	return 0;
}

/**
  * gnutls_dh_params_export_raw - This function will export the raw DH parameters
  * @params: Holds the DH parameters
  * @prime: will hold the new prime
  * @generator: will hold the new generator
  * @bits: if non null will hold is the prime's number of bits
  *
  * This function will export the pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * 
  **/
int gnutls_dh_params_export_raw(gnutls_dh_params params,
	gnutls_datum * prime, gnutls_datum * generator, int *bits)
{

	size_t size;

	size = 0;
	_gnutls_mpi_print(NULL, &size, params->_generator);

	generator->data = gnutls_malloc(size);
	if (generator->data == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	generator->size = size;
	_gnutls_mpi_print(generator->data, &size, params->_generator);


	size = 0;
	_gnutls_mpi_print(NULL, &size, params->_prime);

	prime->data = gnutls_malloc(size);
	if (prime->data == NULL) {
		gnutls_free(generator->data);
		return GNUTLS_E_MEMORY_ERROR;
	}
	prime->size = size;
	_gnutls_mpi_print(prime->data, &size, params->_prime);
	
	if (bits)
		*bits = _gnutls_mpi_get_nbits( params->_prime);

	return 0;

}
