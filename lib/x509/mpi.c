/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
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
#include <gnutls_global.h>
#include <libtasn1.h>
#include "common.h"
#include "x509.h"
#include "mpi.h"

/*
 * some x509 certificate parsing functions that relate to MPI parameter
 * extraction. Returns 2 parameters (m,e).
 */

int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ((result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk,
	     "rsa_public_key")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}


	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.modulus", 
		str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.publicExponent", 
		str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&params[0]);
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}


/* reads p,q and g 
 * from the certificate 
 * params[0-2]
 */
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.Dss-Parms", &spk,
	     "dsa_parms")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}

	/* FIXME: If the parameters are not included in the certificate
	 * then the issuer's parameters should be used.
	 */

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.p", str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read q */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.q", str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		_gnutls_mpi_release(&params[0]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read g */
	
	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.g", str, sizeof(str)-1, &params[2])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		_gnutls_mpi_release(&params[0]);
		_gnutls_mpi_release(&params[1]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}

/* reads DSA's Y
 * from the certificate 
 * params[3]
 */
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ( (result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey", &spk,
	     "dsa_public_key")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_public_key", str, sizeof(str)-1, &params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	asn1_delete_structure(&spk);

	return 0;

}


/* Extracts DSA and RSA parameters from a certificate.
 */
int _gnutls_x509_crt_get_mpis( gnutls_x509_crt cert,
	GNUTLS_MPI* params, int *params_size) 
{
int len, result;
opaque str[5*1024];
int pk_algorithm;

	/* Read the algorithm's OID
	 */
	pk_algorithm = gnutls_x509_crt_get_pk_algorithm(cert, NULL);

	/* Read the algorithm's parameters
	 */
	len = sizeof(str);
	result = asn1_read_value(cert->cert, 
		"cert2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", str, &len);
	len /= 8;

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	switch( pk_algorithm) {
	case GNUTLS_PK_RSA:
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		if ( *params_size < RSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the GNUTLS_MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _gnutls_x509_read_rsa_params( str, len, params)) < 0) {
			gnutls_assert();
			return result;
		}
		*params_size = RSA_PUBLIC_PARAMS;
		
		return 0;
		break;
	case GNUTLS_PK_DSA:
		/* params[0] is p,
		 * params[1] is q,
		 * params[2] is q,
		 * params[3] is pub.
		 */

		if ( *params_size < DSA_PUBLIC_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the GNUTLS_MPIs in params */
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if ((result =
		     _gnutls_x509_read_dsa_pubkey( str, len, params)) < 0) {
			gnutls_assert();
			return result;
		}

		/* Now read the parameters
		 */

		len = sizeof(str);
		result = asn1_read_value(cert->cert, 
			"cert2.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", str, &len);

		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		if ((result =
		     _gnutls_x509_read_dsa_params(str, len, params)) < 0) {
			gnutls_assert();
			return result;
		}
		*params_size = DSA_PUBLIC_PARAMS;
		
		return 0;
		break;

	default:
		/* other types like DH
		 * currently not supported
		 */
		gnutls_assert();

		return GNUTLS_E_X509_CERTIFICATE_ERROR;
	}
}
