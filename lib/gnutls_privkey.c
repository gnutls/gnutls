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
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <x509_asn1.h>
#include <x509_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_global.h>


/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
int _gnutls_PKCS1key2gnutlsKey(gnutls_private_key * pkey, gnutls_datum raw_key) {
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	int len = sizeof(str);
	node_asn *pkcs_asn;
	
	pkey->pk_algorithm = GNUTLS_PK_RSA;
	
	if (asn1_create_structure( _gnutls_get_gnutls_asn(), "GNUTLS.RSAPrivateKey", &pkcs_asn, "rsakey")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	if ((sizeof( pkey->params)/sizeof(MPI)) < RSA_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the MPIs in params */
		return GNUTLS_E_INTERNAL;
	}

	result = asn1_get_der( pkcs_asn, raw_key.data, raw_key.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkcs_asn, "rsakey.privateExponent", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(pkcs_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	if (_gnutls_mpi_scan( &pkey->params[0], /* u */
		  str, &len) != 0 || pkey->params[0]==NULL) {
		gnutls_assert();
		asn1_delete_structure(pkcs_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}


	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkcs_asn, "rsakey.modulus", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(pkcs_asn);
		_gnutls_mpi_release( &pkey->params[0]);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[1], /* A */
		  str, &len) != 0 || pkey->params[1] == NULL) {
		gnutls_assert();
		asn1_delete_structure(pkcs_asn);
		_gnutls_mpi_release( &pkey->params[0]);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	asn1_delete_structure(pkcs_asn);

	if (gnutls_set_datum( &pkey->raw, raw_key.data, raw_key.size) < 0) {
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;


}

int _gnutls_DSAkey2gnutlsKey(gnutls_private_key * pkey, gnutls_datum raw_key) {
	int result;
	opaque str[MAX_PARAMETER_SIZE];
	int len = sizeof(str);
	node_asn *pkix_asn;
	
	pkey->pk_algorithm = GNUTLS_PK_DSA;
	
	if (asn1_create_structure( _gnutls_get_gnutls_asn(), "GNUTLS.DSAPrivateKey", &pkix_asn, "dsakey")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	if ((sizeof( pkey->params)/sizeof(MPI)) < DSA_PARAMS) {
		gnutls_assert();
		/* internal error. Increase the MPIs in params */
		return GNUTLS_E_INTERNAL;
	}

	result = asn1_get_der( pkix_asn, raw_key.data, raw_key.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkix_asn, "dsakey.p", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[0], /* p */
		  str, &len) != 0) {
		gnutls_assert();
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkix_asn, "dsakey.q", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[1], /* q */ str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkix_asn, "dsakey.g", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[2], /* g */ str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkix_asn, "dsakey.Y", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[3], /* priv key */
		  str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	
	len = sizeof(str) - 1;
	result =
	    asn1_read_value( pkix_asn, "dsakey.priv", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( &pkey->params[4], /* priv key */
		  str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
		_gnutls_mpi_release(&pkey->params[2]);
		_gnutls_mpi_release(&pkey->params[3]);
		asn1_delete_structure(pkix_asn);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	asn1_delete_structure(pkix_asn);

	if (gnutls_set_datum( &pkey->raw, raw_key.data, raw_key.size) < 0) {
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

void _gnutls_free_private_key( gnutls_private_key pkey) {
int n, i;

	switch( pkey.pk_algorithm) {
	case GNUTLS_PK_RSA:
		n = 2;/* the number of parameters in MPI* */
		break;
	default:
		n=0;
	}
	for (i=0;i<n;i++) {
		_gnutls_mpi_release( &pkey.params[i]);
	}

	gnutls_free_datum( &pkey.raw);

	return;
}

