/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_cert.h>
#include <gnutls_cert.h>
#include <x509_asn1.h>
#include <x509_der.h>
#include <gnutls_datum.h>
#include <gnutls_mpi.h>
#include <gnutls_global.h>

void _gcry_mpi_invm( MPI x, MPI a, MPI n );

/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
int _gnutls_PKCS1key2gnutlsKey(gnutls_private_key * pkey,
			       gnutls_datum raw_key)
{
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	node_asn *pkey_asn;

	pkey->pk_algorithm = GNUTLS_PK_RSA;

	if ((result =
	     asn1_create_structure(_gnutls_get_gnutls_asn(),
				   "GNUTLS.RSAPrivateKey", &pkey_asn,
				   "rsakey")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ((sizeof(pkey->params) / sizeof(GNUTLS_MPI)) < RSA_PRIVATE_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the GNUTLS_MPIs in params */
		return GNUTLS_E_INTERNAL_ERROR;
	}

	result = asn1_get_der(pkey_asn, raw_key.data, raw_key.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "rsakey.modulus",
					    str, sizeof(str) - 1,
					    &pkey->params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(pkey_asn);
		return result;
	}

	if ((result =
	     _gnutls_x509_read_int(pkey_asn, "rsakey.publicExponent", str,
				   sizeof(str) - 1,
				   &pkey->params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(pkey_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		return result;
	}

	if ((result =
	     _gnutls_x509_read_int(pkey_asn, "rsakey.privateExponent", str,
				   sizeof(str) - 1,
				   &pkey->params[2])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		asn1_delete_structure(pkey_asn);
		return result;
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "rsakey.prime1",
					    str, sizeof(str) - 1,
					    &pkey->params[3])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		asn1_delete_structure(pkey_asn);
		return result;
	}

	if ((result = _gnutls_x509_read_int(pkey_asn, "rsakey.prime2",
					    str, sizeof(str) - 1,
					    &pkey->params[4])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		asn1_delete_structure(pkey_asn);
		return result;
	}

#if 1
	/* Calculate the coefficient. This is because the gcrypt
	 * library is uses the p,q in the reverse order.
	 */
	pkey->params[5] =
	    _gnutls_mpi_snew(_gnutls_mpi_get_nbits(pkey->params[0]));

	if (pkey->params[5] == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_invm(pkey->params[5], pkey->params[3], pkey->params[4]);
	/*				p, q */
#else
	if ( (result=_gnutls_x509_read_int( pkey_asn, "rsakey.coefficient",
		str, sizeof(str)-1, &pkey->params[5])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release( &pkey->params[0]);
		_gnutls_mpi_release( &pkey->params[1]);
		_gnutls_mpi_release( &pkey->params[2]);
		_gnutls_mpi_release( &pkey->params[3]);
		_gnutls_mpi_release( &pkey->params[4]);
		asn1_delete_structure(pkey_asn);
		return result;
	}
#endif

	pkey->params_size = RSA_PRIVATE_PARAMS;

	asn1_delete_structure(pkey_asn);

	if (gnutls_set_datum(&pkey->raw, raw_key.data, raw_key.size) < 0) {
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		_gnutls_mpi_release(&pkey->params[4]);
		_gnutls_mpi_release(&pkey->params[5]);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;


}

int _gnutls_DSAkey2gnutlsKey(gnutls_private_key * pkey,
			     gnutls_datum raw_key)
{
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	node_asn *dsa_asn;

	pkey->pk_algorithm = GNUTLS_PK_DSA;

	if ((result =
	     asn1_create_structure(_gnutls_get_gnutls_asn(),
				   "GNUTLS.DSAPrivateKey", &dsa_asn,
				   "dsakey")) != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ((sizeof(pkey->params) / sizeof(GNUTLS_MPI)) < DSA_PRIVATE_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the GNUTLS_MPIs in params */
		return GNUTLS_E_INTERNAL_ERROR;
	}

	result = asn1_get_der(dsa_asn, raw_key.data, raw_key.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "dsakey.p",
					    str, sizeof(str) - 1,
					    &pkey->params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(dsa_asn);
		return result;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "dsakey.q",
					    str, sizeof(str) - 1,
					    &pkey->params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(dsa_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		return result;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "dsakey.g",
					    str, sizeof(str) - 1,
					    &pkey->params[2])) < 0) {
		gnutls_assert();
		asn1_delete_structure(dsa_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		return result;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "dsakey.Y",
					    str, sizeof(str) - 1,
					    &pkey->params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(dsa_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		return result;
	}

	if ((result = _gnutls_x509_read_int(dsa_asn, "dsakey.priv",
					    str, sizeof(str) - 1,
					    &pkey->params[4])) < 0) {
		gnutls_assert();
		asn1_delete_structure(dsa_asn);
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		return result;
	}
	pkey->params_size = DSA_PRIVATE_PARAMS;

	asn1_delete_structure(dsa_asn);

	if (gnutls_set_datum(&pkey->raw, raw_key.data, raw_key.size) < 0) {
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		_gnutls_mpi_release(&pkey->params[4]);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;


}

void _gnutls_free_private_key(gnutls_private_key pkey)
{
	int i;

	for (i = 0; i < pkey.params_size; i++) {
		_gnutls_mpi_release(&pkey.params[i]);
	}

	gnutls_free_datum(&pkey.raw);

	return;
}
