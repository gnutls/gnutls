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
#include <common.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>

/**
  * gnutls_x509_crl_init - This function initializes a gnutls_x509_crl structure
  * @crl: The structure to be initialized
  *
  * This function will initialize a CRL structure. CRL stands for
  * Certificate Revocation List. A revocation list usually contains
  * lists of certificate serial numbers that have been revoked
  * by an Authority. The revocation lists are always signed with
  * the authority's private key.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crl_init(gnutls_x509_crl * crl)
{
	*crl = gnutls_calloc(1, sizeof(gnutls_x509_crl_int));

	if (*crl) {
		int result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.CertificateList",
				     &(*crl)->crl);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
		return 0;	/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_crl_deinit - This function deinitializes memory used by a gnutls_x509_crl structure
  * @crl: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_x509_crl_deinit(gnutls_x509_crl crl)
{
	if (crl->crl)
		asn1_delete_structure(&crl->crl);
	_gnutls_free_datum(&crl->signed_data);
	_gnutls_free_datum(&crl->signature);

	gnutls_free(crl);
}

/**
  * gnutls_x509_crl_import - This function will import a DER or PEM encoded CRL
  * @crl: The structure to store the parsed CRL.
  * @data: The DER or PEM encoded CRL.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded CRL
  * to the native gnutls_x509_crl format. The output will be stored in 'crl'.
  *
  * If the CRL is PEM encoded it should have a header of "X509 CRL".
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crl_import(gnutls_x509_crl crl, const gnutls_datum * data,
			   gnutls_x509_crt_fmt format)
{
	int result = 0, need_free = 0;
	int start, end;
	gnutls_datum _data = { data->data, data->size };
	opaque *signature = NULL;

	/* If the CRL is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;

		result =
		    _gnutls_fbase64_decode(PEM_CRL, data->data, data->size,
					   &out);

		if (result <= 0) {
			if (result == 0)
				result = GNUTLS_E_INTERNAL_ERROR;
			gnutls_assert();
			return result;
		}

		_data.data = out;
		_data.size = result;

		need_free = 1;
	}


	result =
	    asn1_der_decoding(&crl->crl, _data.data, _data.size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	/* Get the signed data
	 */
	result =
	    asn1_der_decoding_startEnd(crl->crl, _data.data, _data.size,
				       "tbsCertList", &start, &end);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}


	result =
	    _gnutls_set_datum(&crl->signed_data, &_data.data[start],
			      end - start + 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Read the signature */
	{
		int len;

		len = 0;
		result = asn1_read_value( crl->crl, "signature", NULL, &len);
		
		if (result != ASN1_MEM_ERROR) {
			result = _gnutls_asn2err(result);
			gnutls_assert();
			goto cleanup;
		}
		
		signature = gnutls_malloc( len);
		if (signature == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		/* read the bit string of the signature
		 */
		result =
		    asn1_read_value(crl->crl, "signature", signature,
				    &len);

		if (result != ASN1_SUCCESS) {
			result = _gnutls_asn2err(result);
			gnutls_assert();
			goto cleanup;
		}

		if (len % 8 != 0) {
			gnutls_assert();
			result = GNUTLS_E_CERTIFICATE_ERROR;
			goto cleanup;
		}

		if ((result =
		     _gnutls_set_datum(&crl->signature, signature,
				       len / 8)) < 0) {
			gnutls_assert();
			goto cleanup;
		}

		/* Read the signature algorithm. Note that parameters are not
		 * read. They will be read from the issuer's certificate if needed.
		 */

		result =
		    asn1_read_value(crl->crl,
				    "signatureAlgorithm.algorithm",
				    signature, &len);

		if (result != ASN1_SUCCESS) {
			result = _gnutls_asn2err(result);
			gnutls_assert();
			goto cleanup;
		}
		
		crl->signature_algorithm =
		    _gnutls_x509_oid2pk_algorithm(signature);

		gnutls_free( signature);
		signature = NULL;

	}

	if (need_free)
		_gnutls_free_datum(&_data);

	return 0;

      cleanup:
      	gnutls_free( signature);
	_gnutls_free_datum(&crl->signed_data);
	_gnutls_free_datum(&crl->signature);
	if (need_free)
		_gnutls_free_datum(&_data);
	return result;
}


/**
  * gnutls_x509_crl_get_issuer_dn - This function returns the CRL's issuer distinguished name
  * @crl: should contain a gnutls_x509_crl structure
  * @buf: a pointer to a structure to hold the peer's name (may be null)
  * @sizeof_buf: initialy holds the size of 'buf'
  *
  * This function will copy the name of the CRL issuer in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253.
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size.
  * On success zero is returned.
  *
  **/
int gnutls_x509_crl_get_issuer_dn(gnutls_x509_crl crl, char *buf,
				  int *sizeof_buf)
{
	if (sizeof_buf == 0 || crl == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	return _gnutls_x509_parse_dn(crl->crl,
				     "tbsCertList.issuer.rdnSequence",
				     buf, sizeof_buf);


}

/**
  * gnutls_x509_crl_get_issuer_dn_by_oid - This function returns the CRL's issuer distinguished name
  * @crl: should contain a gnutls_x509_crl structure
  * @oid: holds an Object Identified in null terminated string
  * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use zero to get the first one.
  * @buf: a pointer to a structure to hold the peer's name (may be null)
  * @sizeof_buf: initialy holds the size of 'buf'
  *
  * This function will extract the part of the name of the CRL issuer specified
  * by the given OID. The output will be encoded as described in RFC2253.
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size.
  * On success zero is returned.
  *
  **/
int gnutls_x509_crl_get_issuer_dn_by_oid(gnutls_x509_crl crl,
					 const char *oid, int indx,
					 char *buf, int *sizeof_buf)
{
	if (sizeof_buf == 0 || crl == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	return _gnutls_x509_parse_dn_oid(crl->crl,
					 "tbsCertList.issuer.rdnSequence",
					 oid, indx, buf, sizeof_buf);


}

/**
  * gnutls_x509_crl_get_signature_algorithm - This function returns the CRL's signature algorithm
  * @crl: should contain a gnutls_x509_crl structure
  *
  * This function will return a value of the gnutls_pk_algorithm enumeration that 
  * is the signature algorithm. 
  *
  * Returns a negative value on error.
  *
  **/
int gnutls_x509_crl_get_signature_algorithm(gnutls_x509_crl crl)
{
	return crl->signature_algorithm;

	return 0;
}

/**
  * gnutls_x509_crl_get_version - This function returns the CRL's version number
  * @crl: should contain a gnutls_x509_crl structure
  *
  * This function will return the version of the specified CRL.
  *
  * Returns a negative value on error.
  *
  **/
int gnutls_x509_crl_get_version(gnutls_x509_crl crl)
{
	opaque version[5];
	int len, result;

	len = sizeof(version);
	if ((result =
	     asn1_read_value(crl->crl, "tbsCertList.version", version,
			     &len)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return (int) version[0] + 1;
}

/**
  * gnutls_x509_crl_get_this_update - This function returns the CRL's thisUpdate time
  * @crl: should contain a gnutls_x509_crl structure
  *
  * This function will return the time this CRL was issued.
  *
  * Returns (time_t)-1 on error.
  *
  **/
time_t gnutls_x509_crl_get_this_update(gnutls_x509_crl crl)
{
	return _gnutls_x509_get_time(crl->crl,
				     "tbsCertList.thisUpdate");
}

/**
  * gnutls_x509_crl_get_next_update - This function returns the CRL's nextUpdate time
  * @crl: should contain a gnutls_x509_crl structure
  *
  * This function will return the time the next CRL will be issued.
  * This field is optional in a CRL so it might be normal to get
  * an error instead.
  *
  * Returns (time_t)-1 on error.
  *
  **/
time_t gnutls_x509_crl_get_next_update(gnutls_x509_crl crl)
{
	return _gnutls_x509_get_time(crl->crl,
				     "tbsCertList.nextUpdate");
}

/**
  * gnutls_x509_crl_get_certificate_count - This function returns the number of revoked certificates in a CRL
  * @crl: should contain a gnutls_x509_crl structure
  *
  * This function will return the number of revoked certificates in the
  * given CRL.
  *
  * Returns a negative value on failure.
  *
  **/
int gnutls_x509_crl_get_certificate_count(gnutls_x509_crl crl)
{

	int count, result;

	result =
	    asn1_number_of_elements(crl->crl,
				    "tbsCertList.revokedCertificates",
				    &count);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return 0;	/* no certificates */
	}

	return count;
}

/**
  * gnutls_x509_crl_get_certificate - This function returns the serial number of a revoked certificate
  * @crl: should contain a gnutls_x509_crl structure
  * @index: the index of the certificate to extract (starting from 0)
  * @serial: where the serial number will be copied
  * @serial_size: initialy holds the size of serial
  * @time: if non null, will hold the time this certificate was revoked
  *
  * This function will return the serial number of the specified, by the index, 
  * revoked certificate.
  *
  * Returns a negative value on failure.
  *
  **/
int gnutls_x509_crl_get_certificate(gnutls_x509_crl crl, int index,
				    unsigned char *serial,
				    int *serial_size, time_t * time)
{

	int result;
	char str_index[MAX_INT_DIGITS];
	char serial_name[64];
	char date_name[64];

	_gnutls_int2str(index + 1, str_index);
	_gnutls_str_cpy(serial_name, sizeof(serial_name),
			"tbsCertList.revokedCertificates.?");
	_gnutls_str_cat(serial_name, sizeof(serial_name), str_index);
	_gnutls_str_cat(serial_name, sizeof(serial_name),
			".userCertificate");

	_gnutls_str_cpy(date_name, sizeof(date_name),
			"tbsCertList.revokedCertificates.?");
	_gnutls_str_cat(date_name, sizeof(date_name), str_index);
	_gnutls_str_cat(date_name, sizeof(date_name), ".revocationDate");


	if ((result =
	     asn1_read_value(crl->crl, serial_name, serial,
			     serial_size)) != ASN1_SUCCESS) {
		gnutls_assert();
		if (result == ASN1_ELEMENT_NOT_FOUND)
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		return _gnutls_asn2err(result);
	}

	if (time) {
		*time = _gnutls_x509_get_time(crl->crl, date_name);
	}

	return 0;
}

/*-
  * _gnutls_x509_crl_get_raw_issuer_dn - This function returns the issuer's DN DER encoded
  * @crl: should contain a gnutls_x509_crl structure
  * @dn: will hold the starting point of the DN
  *
  * This function will return a pointer to the DER encoded DN structure and
  * the length.
  *
  * Returns a negative value on error, and zero on success.
  *
  -*/
int _gnutls_x509_crl_get_raw_issuer_dn(gnutls_x509_crl crl,
				       gnutls_const_datum * dn)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result, len1;
	int start1, end1;

	/* get the issuer of 'crl'
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(), "PKIX1.TBSCertList",
				 &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding(&c2, crl->signed_data.data,
			      crl->signed_data.size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding_startEnd(c2, crl->signed_data.data,
				       crl->signed_data.size, "issuer",
				       &start1, &end1);
	asn1_delete_structure(&c2);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	len1 = end1 - start1 + 1;

	dn->data = &crl->signed_data.data[start1];
	dn->size = len1;

	return 0;

}

/**
  * gnutls_x509_crl_export - This function will export the CRL
  * @crl: Holds the revocation list
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a private key PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the revocation list to DER or PEM format.
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN X509 CRL".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_x509_crl_export( gnutls_x509_crl crl,
	gnutls_x509_crt_fmt format, unsigned char* output_data, int* output_data_size)
{
	return _gnutls_x509_export_int( crl->crl, format, PEM_CRL, *output_data_size,
		output_data, output_data_size);
}

/*-
  * _gnutls_x509_crl_cpy - This function copies a gnutls_x509_crl structure
  * @dest: The structure where to copy
  * @src: The structure to be copied
  *
  * This function will copy an X.509 certificate structure. 
  *
  * Returns 0 on success.
  *
  -*/
int _gnutls_x509_crl_cpy(gnutls_x509_crl dest, gnutls_x509_crl src)
{
int ret;
int der_size;
opaque * der;
gnutls_datum tmp;

	ret = gnutls_x509_crl_export( src, GNUTLS_X509_FMT_DER, NULL, &der_size);
	if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		gnutls_assert();
		return ret;
	}

	der = gnutls_alloca( der_size);
	if (der == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = gnutls_x509_crl_export( src, GNUTLS_X509_FMT_DER, der, &der_size);
	if (ret < 0) {
		gnutls_assert();
		gnutls_afree( der);
		return ret;
	}

	tmp.data = der;
	tmp.size = der_size;
	ret = gnutls_x509_crl_import( dest, &tmp, GNUTLS_X509_FMT_DER);

	gnutls_afree( der);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;

}
