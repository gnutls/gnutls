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

#include <libtasn1.h>
#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <crl.h>
#include <dn.h>

/**
  * gnutls_x509_crl_init - This function initializes a gnutls_crl structure
  * @crl: The structure to be initialized
  *
  * This function will initialize a CRL structure. CRL stands for
  * Certificate Revocation List.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crl_init(gnutls_crl * crl)
{
	*crl = gnutls_calloc( 1, sizeof(gnutls_crl_int));

	if (*crl) return 0;		/* success */
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_crl_deinit - This function deinitializes memory used by a gnutls_crl structure
  * @crl: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_x509_crl_deinit(gnutls_crl crl)
{
	asn1_delete_structure(&crl->crl);
	_gnutls_free_datum(&crl->signed_data);

	gnutls_free(crl);
}

/**
  * gnutls_x509_crl_import_der - This function will import a DER encoded CRL
  * @crl: The structure to store the parsed CRL.
  * @der: The DER encoded CRL.
  *
  * This function will convert the given DER encoded CRL
  * to the native gnutls_crl format. The output will be stored in 'crl'.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crl_import_der(const gnutls_datum * der, gnutls_crl crl)
{
	int result = 0;
	int start, end;

	crl->crl = ASN1_TYPE_EMPTY;

	result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.CertificateList",
				     &crl->crl, "crl2");
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&crl->crl, der->data, der->size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	/* Get the signed data
	 */
	result = asn1_der_decoding_startEnd(crl->crl, der->data, der->size,
					    "crl2.tbsCertList", &start,
					    &end);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}


	result =
	    _gnutls_set_datum(&crl->signed_data, &der->data[start],
			      end - start + 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	return 0;

      cleanup:
	asn1_delete_structure(&crl->crl);
	_gnutls_free_datum(&crl->signed_data);
	return result;
}


/**
  * gnutls_x509_crl_get_issuer_dn_string - This function returns the CRL's issuer distinguished name
  * @crl: should contain a gnutls_crl structure
  * @buf: a pointer to a structure to hold the peer's name
  * @sizeof_buf: holds the size of 'buf'
  *
  * This function will copy the name of the CRL issuer in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough,
  * and 0 on success.
  *
  **/
int gnutls_x509_crl_get_issuer_dn_string(const gnutls_crl crl, char *buf,
					 unsigned int sizeof_buf)
{
	if (buf == NULL || sizeof_buf == 0 || crl == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_parse_dn( crl->crl, "crl2.tbsCertList.issuer.rdnSequence",
		buf, sizeof_buf);

		
}
