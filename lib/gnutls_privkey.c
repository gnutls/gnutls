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
#include <cert_b64.h>
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <cert_asn1.h>
#include <cert_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_global.h>

/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
int _gnutls_pkcs1key2gnutlsKey(gnutls_private_key * pkey, gnutls_datum cert) {
	int result;
	opaque str[MAX_X509_CERT_SIZE];
	int len = sizeof(str);
	node_asn *pkcs_asn;
	
	pkey->pk_algorithm = GNUTLS_PK_RSA;
	
	/* we do return 2 MPIs 
	 */
	pkey->params = gnutls_malloc(2*sizeof(MPI));
	
	if (asn1_create_structure( _gnutls_get_pkcs(), "PKCS-1.RSAPrivateKey", &pkcs_asn, "rsakey")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( pkcs_asn, cert.data, cert.size);
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
	if (gcry_mpi_scan( &pkey->params[0], /* u */
		  GCRYMPI_FMT_USG, str, &len) != 0) {
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

	if (gcry_mpi_scan( &pkey->params[1], /* A */
		  GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		asn1_delete_structure(pkcs_asn);
		_gnutls_mpi_release( &pkey->params[0]);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	asn1_delete_structure(pkcs_asn);

	if (gnutls_set_datum( &pkey->raw, cert.data, cert.size) < 0) {
		_gnutls_mpi_release(&pkey->params[0]);
		_gnutls_mpi_release(&pkey->params[1]);
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

}

