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
#include <gnutls_num.h>
#include "mpi.h"

/*
 * some x509 certificate parsing functions that relate to MPI parameter
 * extraction. This reads the BIT STRING subjectPublicKey.
 * Returns 2 parameters (m,e).
 */
int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ((result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk))
	     != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&spk, der, dersize, NULL);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
	}


	if ( (result=_gnutls_x509_read_int( spk, "modulus", 
		str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	if ( (result=_gnutls_x509_read_int( spk, "publicExponent", 
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
 * from the certificate (subjectPublicKey BIT STRING).
 * params[0-2]
 */
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.Dss-Parms", &spk
	     )) != ASN1_SUCCESS) {
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
	 * then the issuer's parameters should be used. This is not
	 * done yet.
	 */

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "p", str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read q */

	if ( (result=_gnutls_x509_read_int( spk, "q", str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		_gnutls_mpi_release(&params[0]);
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	/* Read g */
	
	if ( (result=_gnutls_x509_read_int( spk, "g", str, sizeof(str)-1, &params[2])) < 0) {
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
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey", &spk
	     )) != ASN1_SUCCESS) {
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

	if ( (result=_gnutls_x509_read_int( spk, "", str, sizeof(str)-1, &params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(&spk);
		return _gnutls_asn2err(result);
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
		"tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", str, &len);
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
			"tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", str, &len);

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

/*
 * some x509 certificate functions that relate to MPI parameter
 * setting. This writes the BIT STRING subjectPublicKey.
 * Needs 2 parameters (m,e).
 */
int _gnutls_x509_write_rsa_params( GNUTLS_MPI * params, int params_size,
	opaque * der, int* dersize)
{
	int result;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	if ((result=asn1_create_element
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk))
	     != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (params_size < 2) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	result = _gnutls_x509_write_int( spk, "modulus", params[0]);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = _gnutls_x509_write_int( spk, "publicExponent", params[1]);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	if (der == NULL) *dersize = 0;
	result = asn1_der_coding( spk, "", der, dersize, NULL);

	asn1_delete_structure(&spk);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;

}

/* this function reads a (small) unsigned integer
 * from asn1 structs. Combines the read and the convertion
 * steps.
 */
int _gnutls_x509_read_ui( ASN1_TYPE node, const char* value, 
	opaque* tmpstr, int tmpstr_size, unsigned int* ret)
{
int len, result;

	len = tmpstr_size;
	result = asn1_read_value( node, value, tmpstr, &len);
	if (result != ASN1_SUCCESS) {
		return _gnutls_asn2err(result);
	}

	if (len == 1)
		*ret = tmpstr[0];
	else if (len == 2)
		*ret = _gnutls_read_uint16(tmpstr);
	else if (len == 3)
		*ret = _gnutls_read_uint24(tmpstr);
	else if (len == 4)
		*ret = _gnutls_read_uint32(tmpstr);
	else {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	return 0;
}
