/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Free
 * Software Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson, Howard Chu
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Functions on X.509 Certificate parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509_int.h>
#include <libtasn1.h>
#include <gnutls_pk.h>

/**
 * gnutls_x509_crt_init:
 * @cert: The structure to be initialized
 *
 * This function will initialize an X.509 certificate structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_init (gnutls_x509_crt_t * cert)
{
  gnutls_x509_crt_t tmp = gnutls_calloc (1, sizeof (gnutls_x509_crt_int));
  int result;

  if (!tmp)
    return GNUTLS_E_MEMORY_ERROR;

  result = asn1_create_element (_gnutls_get_pkix (),
                                "PKIX1.Certificate", &tmp->cert);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (tmp);
      return _gnutls_asn2err (result);
    }

  /* If you add anything here, be sure to check if it has to be added
     to gnutls_x509_crt_import as well. */

  *cert = tmp;

  return 0;                     /* success */
}

/*-
 * _gnutls_x509_crt_cpy - This function copies a gnutls_x509_crt_t structure
 * @dest: The structure where to copy
 * @src: The structure to be copied
 *
 * This function will copy an X.509 certificate structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 -*/
int
_gnutls_x509_crt_cpy (gnutls_x509_crt_t dest, gnutls_x509_crt_t src)
{
  int ret;
  size_t der_size=0;
  opaque *der;
  gnutls_datum_t tmp;

  ret = gnutls_x509_crt_export (src, GNUTLS_X509_FMT_DER, NULL, &der_size);
  if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert ();
      return ret;
    }

  der = gnutls_malloc (der_size);
  if (der == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = gnutls_x509_crt_export (src, GNUTLS_X509_FMT_DER, der, &der_size);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (der);
      return ret;
    }

  tmp.data = der;
  tmp.size = der_size;
  ret = gnutls_x509_crt_import (dest, &tmp, GNUTLS_X509_FMT_DER);

  gnutls_free (der);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
 * gnutls_x509_crt_deinit:
 * @cert: The structure to be deinitialized
 *
 * This function will deinitialize a certificate structure.
 **/
void
gnutls_x509_crt_deinit (gnutls_x509_crt_t cert)
{
  if (!cert)
    return;

  if (cert->cert)
    asn1_delete_structure (&cert->cert);

  gnutls_free (cert);
}

/**
 * gnutls_x509_crt_import:
 * @cert: The structure to store the parsed certificate.
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded Certificate
 * to the native gnutls_x509_crt_t format. The output will be stored
 * in @cert.
 *
 * If the Certificate is PEM encoded it should have a header of "X509
 * CERTIFICATE", or "CERTIFICATE".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_import (gnutls_x509_crt_t cert,
                        const gnutls_datum_t * data,
                        gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result =
        _gnutls_fbase64_decode (PEM_X509_CERT2, data->data, data->size, &out);

      if (result <= 0)
        {
          /* try for the second header */
          result =
            _gnutls_fbase64_decode (PEM_X509_CERT, data->data,
                                    data->size, &out);

          if (result <= 0)
            {
              if (result == 0)
                result = GNUTLS_E_INTERNAL_ERROR;
              gnutls_assert ();
              return result;
            }
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if (cert->cert)
    {
      /* Any earlier asn1_der_decoding will modify the ASN.1
         structure, so we need to replace it with a fresh
         structure. */
      asn1_delete_structure (&cert->cert);

      result = asn1_create_element (_gnutls_get_pkix (),
                                    "PKIX1.Certificate", &cert->cert);
      if (result != ASN1_SUCCESS)
        {
          result = _gnutls_asn2err (result);
          gnutls_assert ();
          goto cleanup;
        }
    }

  result = asn1_der_decoding (&cert->cert, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = _gnutls_asn2err (result);
      gnutls_assert ();
      goto cleanup;
    }

  /* Since we do not want to disable any extension
   */
  cert->use_extensions = 1;
  if (need_free)
    _gnutls_free_datum (&_data);

  return 0;

cleanup:
  if (need_free)
    _gnutls_free_datum (&_data);
  return result;
}


/**
 * gnutls_x509_crt_get_issuer_dn:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @buf: a pointer to a structure to hold the name (may be null)
 * @buf_size: initially holds the size of @buf
 *
 * This function will copy the name of the Certificate issuer in the
 * provided buffer. The name will be in the form
 * "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253. The output string
 * will be ASCII or UTF-8 encoded, depending on the certificate data.
 *
 * If @buf is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @buf_size will not include the null character.
 *
 * Returns: GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 * long enough, and in that case the @buf_size will be updated with
 * the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_issuer_dn (gnutls_x509_crt_t cert, char *buf,
                               size_t * buf_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn (cert->cert,
                                "tbsCertificate.issuer.rdnSequence", buf,
                                buf_size);
}

/**
 * gnutls_x509_crt_get_issuer_dn_by_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use (0) to get the first one.
 * @raw_flag: If non (0) returns the raw DER data of the DN part.
 * @buf: a pointer to a structure to hold the name (may be null)
 * @buf_size: initially holds the size of @buf
 *
 * This function will extract the part of the name of the Certificate
 * issuer specified by the given OID. The output, if the raw flag is not
 * used, will be encoded as described in RFC2253. Thus a string that is
 * ASCII or UTF-8 encoded, depending on the certificate data.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * If raw flag is (0), this function will only return known OIDs as
 * text. Other OIDs will be DER encoded, as described in RFC2253 --
 * in hex format with a '\#' prefix.  You can check about known OIDs
 * using gnutls_x509_dn_oid_known().
 *
 * If @buf is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @buf_size will not include the null character.
 *
 * Returns: GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 *   long enough, and in that case the @buf_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_issuer_dn_by_oid (gnutls_x509_crt_t cert,
                                      const char *oid, int indx,
                                      unsigned int raw_flag, void *buf,
                                      size_t * buf_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn_oid (cert->cert,
                                    "tbsCertificate.issuer.rdnSequence",
                                    oid, indx, raw_flag, buf, buf_size);
}

/**
 * gnutls_x509_crt_get_issuer_dn_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use (0) to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @oid_size: initially holds the size of @oid
 *
 * This function will extract the OIDs of the name of the Certificate
 * issuer specified by the given index.
 *
 * If @oid is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @oid_size will not include the null character.
 *
 * Returns: GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 *   long enough, and in that case the @oid_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_issuer_dn_oid (gnutls_x509_crt_t cert,
                                   int indx, void *oid, size_t * oid_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_get_dn_oid (cert->cert,
                                  "tbsCertificate.issuer.rdnSequence",
                                  indx, oid, oid_size);
}

/**
 * gnutls_x509_crt_get_dn:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @buf: a pointer to a structure to hold the name (may be null)
 * @buf_size: initially holds the size of @buf
 *
 * This function will copy the name of the Certificate in the provided
 * buffer. The name will be in the form "C=xxxx,O=yyyy,CN=zzzz" as
 * described in RFC2253. The output string will be ASCII or UTF-8
 * encoded, depending on the certificate data.
 *
 * If @buf is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @buf_size will not include the null character.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 *   long enough, and in that case the @buf_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_dn (gnutls_x509_crt_t cert, char *buf,
                        size_t * buf_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn (cert->cert,
                                "tbsCertificate.subject.rdnSequence", buf,
                                buf_size);
}

/**
 * gnutls_x509_crt_get_dn_by_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use (0) to get the first one.
 * @raw_flag: If non (0) returns the raw DER data of the DN part.
 * @buf: a pointer where the DN part will be copied (may be null).
 * @buf_size: initially holds the size of @buf
 *
 * This function will extract the part of the name of the Certificate
 * subject specified by the given OID. The output, if the raw flag is
 * not used, will be encoded as described in RFC2253. Thus a string
 * that is ASCII or UTF-8 encoded, depending on the certificate data.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * If raw flag is (0), this function will only return known OIDs as
 * text. Other OIDs will be DER encoded, as described in RFC2253 --
 * in hex format with a '\#' prefix.  You can check about known OIDs
 * using gnutls_x509_dn_oid_known().
 *
 * If @buf is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @buf_size will not include the null character.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *buf_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_dn_by_oid (gnutls_x509_crt_t cert, const char *oid,
                               int indx, unsigned int raw_flag,
                               void *buf, size_t * buf_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn_oid (cert->cert,
                                    "tbsCertificate.subject.rdnSequence",
                                    oid, indx, raw_flag, buf, buf_size);
}

/**
 * gnutls_x509_crt_get_dn_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use (0) to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @oid_size: initially holds the size of @oid
 *
 * This function will extract the OIDs of the name of the Certificate
 * subject specified by the given index.
 *
 * If @oid is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @oid_size will not include the null character.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the @oid_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_dn_oid (gnutls_x509_crt_t cert,
                            int indx, void *oid, size_t * oid_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_get_dn_oid (cert->cert,
                                  "tbsCertificate.subject.rdnSequence",
                                  indx, oid, oid_size);
}

/**
 * gnutls_x509_crt_get_signature_algorithm:
 * @cert: should contain a #gnutls_x509_crt_t structure
 *
 * This function will return a value of the #gnutls_sign_algorithm_t
 * enumeration that is the signature algorithm that has been used to
 * sign this certificate.
 *
 * Returns: a #gnutls_sign_algorithm_t value, or a negative error code on
 *   error.
 **/
int
gnutls_x509_crt_get_signature_algorithm (gnutls_x509_crt_t cert)
{
  return _gnutls_x509_get_signature_algorithm(cert->cert, "signatureAlgorithm.algorithm");
}

/**
 * gnutls_x509_crt_get_signature:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @sig: a pointer where the signature part will be copied (may be null).
 * @sizeof_sig: initially holds the size of @sig
 *
 * This function will extract the signature field of a certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. and a negative error code on error.
 **/
int
gnutls_x509_crt_get_signature (gnutls_x509_crt_t cert,
                               char *sig, size_t * sizeof_sig)
{
  int result;
  int bits, len;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bits = 0;
  result = asn1_read_value (cert->cert, "signature", NULL, &bits);
  if (result != ASN1_MEM_ERROR)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  if (bits % 8 != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  len = bits / 8;

  if (*sizeof_sig < (unsigned int) len)
    {
      *sizeof_sig = bits / 8;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  result = asn1_read_value (cert->cert, "signature", sig, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_version:
 * @cert: should contain a #gnutls_x509_crt_t structure
 *
 * This function will return the version of the specified Certificate.
 *
 * Returns: version of certificate, or a negative error code on error.
 **/
int
gnutls_x509_crt_get_version (gnutls_x509_crt_t cert)
{
  opaque version[8];
  int len, result;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = sizeof (version);
  if ((result =
       asn1_read_value (cert->cert, "tbsCertificate.version", version,
                        &len)) != ASN1_SUCCESS)
    {

      if (result == ASN1_ELEMENT_NOT_FOUND)
        return 1;               /* the DEFAULT version */
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return (int) version[0] + 1;
}

/**
 * gnutls_x509_crt_get_activation_time:
 * @cert: should contain a #gnutls_x509_crt_t structure
 *
 * This function will return the time this Certificate was or will be
 * activated.
 *
 * Returns: activation time, or (time_t)-1 on error.
 **/
time_t
gnutls_x509_crt_get_activation_time (gnutls_x509_crt_t cert)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return (time_t) - 1;
    }

  return _gnutls_x509_get_time (cert->cert,
                                "tbsCertificate.validity.notBefore");
}

/**
 * gnutls_x509_crt_get_expiration_time:
 * @cert: should contain a #gnutls_x509_crt_t structure
 *
 * This function will return the time this Certificate was or will be
 * expired.
 *
 * Returns: expiration time, or (time_t)-1 on error.
 **/
time_t
gnutls_x509_crt_get_expiration_time (gnutls_x509_crt_t cert)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return (time_t) - 1;
    }

  return _gnutls_x509_get_time (cert->cert,
                                "tbsCertificate.validity.notAfter");
}

/**
 * gnutls_x509_crt_get_serial:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @result: The place where the serial number will be copied
 * @result_size: Holds the size of the result field.
 *
 * This function will return the X.509 certificate's serial number.
 * This is obtained by the X509 Certificate serialNumber field. Serial
 * is not always a 32 or 64bit number. Some CAs use large serial
 * numbers, thus it may be wise to handle it as something opaque.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_get_serial (gnutls_x509_crt_t cert, void *result,
                            size_t * result_size)
{
  int ret, len;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = *result_size;
  ret =
    asn1_read_value (cert->cert, "tbsCertificate.serialNumber", result, &len);
  *result_size = len;

  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_subject_key_id:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @ret: The place where the identifier will be copied
 * @ret_size: Holds the size of the result field.
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function will return the X.509v3 certificate's subject key
 * identifier.  This is obtained by the X.509 Subject Key identifier
 * extension field (2.5.29.14).
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_get_subject_key_id (gnutls_x509_crt_t cert, void *ret,
                                    size_t * ret_size, unsigned int *critical)
{
  int result, len;
  gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }


  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "2.5.29.14", 0, &id,
                                       critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.SubjectKeyIdentifier", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&id);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, id.data, id.size, NULL);
  _gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  len = *ret_size;
  result = asn1_read_value (c2, "", ret, &len);

  *ret_size = len;
  asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      if (result != ASN1_MEM_ERROR)
        gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_authority_key_id:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @ret: The place where the identifier will be copied
 * @ret_size: Holds the size of the result field.
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function will return the X.509v3 certificate authority's key
 * identifier.  This is obtained by the X.509 Authority Key
 * identifier extension field (2.5.29.35). Note that this function
 * only returns the keyIdentifier field of the extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_get_authority_key_id (gnutls_x509_crt_t cert, void *ret,
                                      size_t * ret_size,
                                      unsigned int *critical)
{
  int result, len;
  gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }


  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "2.5.29.35", 0, &id,
                                       critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.AuthorityKeyIdentifier", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&id);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, id.data, id.size, NULL);
  _gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  len = *ret_size;
  result = asn1_read_value (c2, "keyIdentifier", ret, &len);

  *ret_size = len;
  asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      if (result != ASN1_MEM_ERROR)
        gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_pk_algorithm:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @bits: if bits is non null it will hold the size of the parameters' in bits
 *
 * This function will return the public key algorithm of an X.509
 * certificate.
 *
 * If bits is non null, it should have enough size to hold the parameters
 * size in bits. For RSA the bits returned is the modulus.
 * For DSA the bits returned are of the public
 * exponent.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 * success, or a negative error code on error.
 **/
int
gnutls_x509_crt_get_pk_algorithm (gnutls_x509_crt_t cert, unsigned int *bits)
{
  int result;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
  
  if (bits)
    *bits = 0;

  result =
    _gnutls_x509_get_pk_algorithm (cert->cert,
                                   "tbsCertificate.subjectPublicKeyInfo",
                                   bits);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return result;

}

inline static int
is_type_printable (int type)
{
  if (type == GNUTLS_SAN_DNSNAME || type == GNUTLS_SAN_RFC822NAME ||
      type == GNUTLS_SAN_URI)
    return 1;
  else
    return 0;
}

#define XMPP_OID "1.3.6.1.5.5.7.8.5"

/* returns the type and the name on success.
 * Type is also returned as a parameter in case of an error.
 */
int
_gnutls_parse_general_name (ASN1_TYPE src, const char *src_name,
                            int seq, void *name, size_t * name_size,
                            unsigned int *ret_type, int othername_oid)
{
  int len;
  char nptr[ASN1_MAX_NAME_SIZE];
  int result;
  opaque choice_type[128];
  gnutls_x509_subject_alt_name_t type;

  seq++;                        /* 0->1, 1->2 etc */

  if (src_name[0] != 0)
    snprintf (nptr, sizeof (nptr), "%s.?%u", src_name, seq);
  else
    snprintf (nptr, sizeof (nptr), "?%u", seq);

  len = sizeof (choice_type);
  result = asn1_read_value (src, nptr, choice_type, &len);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }


  type = _gnutls_x509_san_find_type (choice_type);
  if (type == (gnutls_x509_subject_alt_name_t) - 1)
    {
      gnutls_assert ();
      return GNUTLS_E_X509_UNKNOWN_SAN;
    }

  if (ret_type)
    *ret_type = type;

  if (type == GNUTLS_SAN_OTHERNAME)
    {
      if (othername_oid)
        _gnutls_str_cat (nptr, sizeof (nptr), ".otherName.type-id");
      else
        _gnutls_str_cat (nptr, sizeof (nptr), ".otherName.value");

      len = *name_size;
      result = asn1_read_value (src, nptr, name, &len);
      *name_size = len;

      if (result == ASN1_MEM_ERROR)
        return GNUTLS_E_SHORT_MEMORY_BUFFER;

      if (result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          return _gnutls_asn2err (result);
        }

      if (othername_oid)
        {
          if (len > strlen (XMPP_OID) && strcmp (name, XMPP_OID) == 0)
            type = GNUTLS_SAN_OTHERNAME_XMPP;
        }
      else
        {
          char oid[42];

          if (src_name[0] != 0)
            snprintf (nptr, sizeof (nptr), "%s.?%u.otherName.type-id",
                      src_name, seq);
          else
            snprintf (nptr, sizeof (nptr), "?%u.otherName.type-id", seq);

          len = sizeof (oid);
          result = asn1_read_value (src, nptr, oid, &len);
          if (result != ASN1_SUCCESS)
            {
              gnutls_assert ();
              return _gnutls_asn2err (result);
            }

          if (len > strlen (XMPP_OID) && strcmp (oid, XMPP_OID) == 0)
            {
              ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
              size_t orig_name_size = *name_size;

              result = asn1_create_element
                (_gnutls_get_pkix (), "PKIX1.UTF8String", &c2);
              if (result != ASN1_SUCCESS)
                {
                  gnutls_assert ();
                  return _gnutls_asn2err (result);
                }

              result = asn1_der_decoding (&c2, name, *name_size, NULL);
              if (result != ASN1_SUCCESS)
                {
                  gnutls_assert ();
                  asn1_delete_structure (&c2);
                  return _gnutls_asn2err (result);
                }

              len = *name_size;
              result = asn1_read_value (c2, "", name, &len);
              if (result != ASN1_SUCCESS)
                {
                  gnutls_assert ();
                  asn1_delete_structure (&c2);
                  *name_size = len + 1;
                  return _gnutls_asn2err (result);
                }
              asn1_delete_structure (&c2);

              if (len + 1 > orig_name_size)
                {
                  gnutls_assert ();
                  *name_size = len + 1;
                  return GNUTLS_E_SHORT_MEMORY_BUFFER;
                }

              *name_size = len;
              /* null terminate it */
              ((char *) name)[*name_size] = 0;
            }
        }
    }
  else if (type == GNUTLS_SAN_DN)
    {
      _gnutls_str_cat (nptr, sizeof (nptr), ".directoryName");
      result = _gnutls_x509_parse_dn (src, nptr, name, name_size);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }
    }
  else if (othername_oid)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else
    {
      size_t orig_name_size = *name_size;

      _gnutls_str_cat (nptr, sizeof (nptr), ".");
      _gnutls_str_cat (nptr, sizeof (nptr), choice_type);

      len = *name_size;
      result = asn1_read_value (src, nptr, name, &len);
      *name_size = len;

      if (result == ASN1_MEM_ERROR)
        {
          if (is_type_printable (type))
            (*name_size)++;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }

      if (result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          return _gnutls_asn2err (result);
        }

      if (is_type_printable (type))
        {

          if (len + 1 > orig_name_size)
            {
              gnutls_assert ();
              (*name_size)++;
              return GNUTLS_E_SHORT_MEMORY_BUFFER;
            }

          /* null terminate it */
          ((char *) name)[*name_size] = 0;
        }

    }

  return type;
}

static int
get_alt_name (gnutls_x509_crt_t cert, const char *extension_id,
              unsigned int seq, void *ret,
              size_t * ret_size, unsigned int *ret_type,
              unsigned int *critical, int othername_oid)
{
  int result;
  gnutls_datum_t dnsname;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  gnutls_x509_subject_alt_name_t type;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result =
       _gnutls_x509_crt_get_extension (cert, extension_id, 0, &dnsname,
                                       critical)) < 0)
    {
      return result;
    }

  if (dnsname.size == 0 || dnsname.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (strcmp ("2.5.29.17", extension_id) == 0)
    result = asn1_create_element (_gnutls_get_pkix (),
                                  "PKIX1.SubjectAltName", &c2);
  else if (strcmp ("2.5.29.18", extension_id) == 0)
    result = asn1_create_element (_gnutls_get_pkix (),
                                  "PKIX1.IssuerAltName", &c2);
  else
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&dnsname);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, dnsname.data, dnsname.size, NULL);
  _gnutls_free_datum (&dnsname);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  result =
    _gnutls_parse_general_name (c2, "", seq, ret, ret_size, ret_type,
                                othername_oid);

  asn1_delete_structure (&c2);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  type = result;

  return type;
}

/**
 * gnutls_x509_crt_get_subject_alt_name:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function retrieves the Alternative Name (2.5.29.17), contained
 * in the given certificate in the X509v3 Certificate Extensions.
 *
 * When the SAN type is otherName, it will extract the data in the
 * otherName's value field, and %GNUTLS_SAN_OTHERNAME is returned.
 * You may use gnutls_x509_crt_get_subject_alt_othername_oid() to get
 * the corresponding OID and the "virtual" SAN types (e.g.,
 * %GNUTLS_SAN_OTHERNAME_XMPP).
 *
 * If an otherName OID is known, the data will be decoded.  Otherwise
 * the returned data will be DER encoded, and you will have to decode
 * it yourself.  Currently, only the RFC 3920 id-on-xmppAddr SAN is
 * recognized.
 *
 * Returns: the alternative subject name type on success, one of the
 *   enumerated #gnutls_x509_subject_alt_name_t.  It will return
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough to
 *   hold the value.  In that case @ret_size will be updated with the
 *   required size.  If the certificate does not have an Alternative
 *   name with the specified sequence number then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 **/
int
gnutls_x509_crt_get_subject_alt_name (gnutls_x509_crt_t cert,
                                      unsigned int seq, void *ret,
                                      size_t * ret_size,
                                      unsigned int *critical)
{
  return get_alt_name (cert, "2.5.29.17", seq, ret, ret_size, NULL, critical,
                       0);
}

/**
 * gnutls_x509_crt_get_issuer_alt_name:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function retrieves the Issuer Alternative Name (2.5.29.18),
 * contained in the given certificate in the X509v3 Certificate
 * Extensions.
 *
 * When the SAN type is otherName, it will extract the data in the
 * otherName's value field, and %GNUTLS_SAN_OTHERNAME is returned.
 * You may use gnutls_x509_crt_get_subject_alt_othername_oid() to get
 * the corresponding OID and the "virtual" SAN types (e.g.,
 * %GNUTLS_SAN_OTHERNAME_XMPP).
 *
 * If an otherName OID is known, the data will be decoded.  Otherwise
 * the returned data will be DER encoded, and you will have to decode
 * it yourself.  Currently, only the RFC 3920 id-on-xmppAddr Issuer
 * AltName is recognized.
 *
 * Returns: the alternative issuer name type on success, one of the
 *   enumerated #gnutls_x509_subject_alt_name_t.  It will return
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough
 *   to hold the value.  In that case @ret_size will be updated with
 *   the required size.  If the certificate does not have an
 *   Alternative name with the specified sequence number then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Since: 2.10.0
 **/
int
gnutls_x509_crt_get_issuer_alt_name (gnutls_x509_crt_t cert,
                                     unsigned int seq, void *ret,
                                     size_t * ret_size,
                                     unsigned int *critical)
{
  return get_alt_name (cert, "2.5.29.18", seq, ret, ret_size, NULL, critical,
                       0);
}

/**
 * gnutls_x509_crt_get_subject_alt_name2:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @ret_type: holds the type of the alternative name (one of gnutls_x509_subject_alt_name_t).
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function will return the alternative names, contained in the
 * given certificate. It is the same as
 * gnutls_x509_crt_get_subject_alt_name() except for the fact that it
 * will return the type of the alternative name in @ret_type even if
 * the function fails for some reason (i.e.  the buffer provided is
 * not enough).
 *
 * Returns: the alternative subject name type on success, one of the
 *   enumerated #gnutls_x509_subject_alt_name_t.  It will return
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough
 *   to hold the value.  In that case @ret_size will be updated with
 *   the required size.  If the certificate does not have an
 *   Alternative name with the specified sequence number then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 **/
int
gnutls_x509_crt_get_subject_alt_name2 (gnutls_x509_crt_t cert,
                                       unsigned int seq, void *ret,
                                       size_t * ret_size,
                                       unsigned int *ret_type,
                                       unsigned int *critical)
{
  return get_alt_name (cert, "2.5.29.17", seq, ret, ret_size, ret_type,
                       critical, 0);
}

/**
 * gnutls_x509_crt_get_issuer_alt_name2:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @ret_type: holds the type of the alternative name (one of gnutls_x509_subject_alt_name_t).
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function will return the alternative names, contained in the
 * given certificate. It is the same as
 * gnutls_x509_crt_get_issuer_alt_name() except for the fact that it
 * will return the type of the alternative name in @ret_type even if
 * the function fails for some reason (i.e.  the buffer provided is
 * not enough).
 *
 * Returns: the alternative issuer name type on success, one of the
 *   enumerated #gnutls_x509_subject_alt_name_t.  It will return
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough
 *   to hold the value.  In that case @ret_size will be updated with
 *   the required size.  If the certificate does not have an
 *   Alternative name with the specified sequence number then
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Since: 2.10.0
 *
 **/
int
gnutls_x509_crt_get_issuer_alt_name2 (gnutls_x509_crt_t cert,
                                      unsigned int seq, void *ret,
                                      size_t * ret_size,
                                      unsigned int *ret_type,
                                      unsigned int *critical)
{
  return get_alt_name (cert, "2.5.29.18", seq, ret, ret_size, ret_type,
                       critical, 0);
}

/**
 * gnutls_x509_crt_get_subject_alt_othername_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @oid: is the place where the otherName OID will be copied to
 * @oid_size: holds the size of ret.
 *
 * This function will extract the type OID of an otherName Subject
 * Alternative Name, contained in the given certificate, and return
 * the type as an enumerated element.
 *
 * This function is only useful if
 * gnutls_x509_crt_get_subject_alt_name() returned
 * %GNUTLS_SAN_OTHERNAME.
 *
 * If @oid is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @oid_size will not include the null character.
 *
 * Returns: the alternative subject name type on success, one of the
 * enumerated gnutls_x509_subject_alt_name_t.  For supported OIDs, it
 * will return one of the virtual (GNUTLS_SAN_OTHERNAME_*) types,
 * e.g. %GNUTLS_SAN_OTHERNAME_XMPP, and %GNUTLS_SAN_OTHERNAME for
 * unknown OIDs.  It will return %GNUTLS_E_SHORT_MEMORY_BUFFER if
 * @ret_size is not large enough to hold the value.  In that case
 * @ret_size will be updated with the required size.  If the
 * certificate does not have an Alternative name with the specified
 * sequence number and with the otherName type then
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 **/
int
gnutls_x509_crt_get_subject_alt_othername_oid (gnutls_x509_crt_t cert,
                                               unsigned int seq,
                                               void *oid, size_t * oid_size)
{
  return get_alt_name (cert, "2.5.29.17", seq, oid, oid_size, NULL, NULL, 1);
}

/**
 * gnutls_x509_crt_get_issuer_alt_othername_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the otherName OID will be copied to
 * @ret_size: holds the size of ret.
 *
 * This function will extract the type OID of an otherName Subject
 * Alternative Name, contained in the given certificate, and return
 * the type as an enumerated element.
 *
 * If @oid is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @oid_size will not include the null character.
 *
 * This function is only useful if
 * gnutls_x509_crt_get_issuer_alt_name() returned
 * %GNUTLS_SAN_OTHERNAME.
 *
 * Returns: the alternative issuer name type on success, one of the
 * enumerated gnutls_x509_subject_alt_name_t.  For supported OIDs, it
 * will return one of the virtual (GNUTLS_SAN_OTHERNAME_*) types,
 * e.g. %GNUTLS_SAN_OTHERNAME_XMPP, and %GNUTLS_SAN_OTHERNAME for
 * unknown OIDs.  It will return %GNUTLS_E_SHORT_MEMORY_BUFFER if
 * @ret_size is not large enough to hold the value.  In that case
 * @ret_size will be updated with the required size.  If the
 * certificate does not have an Alternative name with the specified
 * sequence number and with the otherName type then
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Since: 2.10.0
 **/
int
gnutls_x509_crt_get_issuer_alt_othername_oid (gnutls_x509_crt_t cert,
                                              unsigned int seq,
                                              void *ret, size_t * ret_size)
{
  return get_alt_name (cert, "2.5.29.18", seq, ret, ret_size, NULL, NULL, 1);
}

/**
 * gnutls_x509_crt_get_basic_constraints:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @critical: will be non (0) if the extension is marked as critical
 * @ca: pointer to output integer indicating CA status, may be NULL,
 *   value is 1 if the certificate CA flag is set, 0 otherwise.
 * @pathlen: pointer to output integer indicating path length (may be
 *   NULL), non-negative error codes indicate a present pathLenConstraint
 *   field and the actual value, -1 indicate that the field is absent.
 *
 * This function will read the certificate's basic constraints, and
 * return the certificates CA status.  It reads the basicConstraints
 * X.509 extension (2.5.29.19).
 *
 * Returns: If the certificate is a CA a positive value will be
 * returned, or (0) if the certificate does not have CA flag set.  A
 * negative error code may be returned in case of errors.  If the
 * certificate does not contain the basicConstraints extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
gnutls_x509_crt_get_basic_constraints (gnutls_x509_crt_t cert,
                                       unsigned int *critical,
                                       unsigned int *ca, int *pathlen)
{
  int result;
  gnutls_datum_t basicConstraints;
  unsigned int tmp_ca;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "2.5.29.19", 0,
                                       &basicConstraints, critical)) < 0)
    {
      return result;
    }

  if (basicConstraints.size == 0 || basicConstraints.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    _gnutls_x509_ext_extract_basicConstraints (&tmp_ca,
                                               pathlen,
                                               basicConstraints.data,
                                               basicConstraints.size);
  if (ca)
    *ca = tmp_ca;
  _gnutls_free_datum (&basicConstraints);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return tmp_ca;
}

/**
 * gnutls_x509_crt_get_ca_status:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @critical: will be non (0) if the extension is marked as critical
 *
 * This function will return certificates CA status, by reading the
 * basicConstraints X.509 extension (2.5.29.19). If the certificate is
 * a CA a positive value will be returned, or (0) if the certificate
 * does not have CA flag set.
 *
 * Use gnutls_x509_crt_get_basic_constraints() if you want to read the
 * pathLenConstraint field too.
 *
 * Returns: A negative error code may be returned in case of parsing error.
 * If the certificate does not contain the basicConstraints extension
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
gnutls_x509_crt_get_ca_status (gnutls_x509_crt_t cert, unsigned int *critical)
{
  int pathlen;
  unsigned int ca;
  return gnutls_x509_crt_get_basic_constraints (cert, critical, &ca,
                                                &pathlen);
}

/**
 * gnutls_x509_crt_get_key_usage:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @key_usage: where the key usage bits will be stored
 * @critical: will be non (0) if the extension is marked as critical
 *
 * This function will return certificate's key usage, by reading the
 * keyUsage X.509 extension (2.5.29.15). The key usage value will ORed
 * values of the: %GNUTLS_KEY_DIGITAL_SIGNATURE,
 * %GNUTLS_KEY_NON_REPUDIATION, %GNUTLS_KEY_KEY_ENCIPHERMENT,
 * %GNUTLS_KEY_DATA_ENCIPHERMENT, %GNUTLS_KEY_KEY_AGREEMENT,
 * %GNUTLS_KEY_KEY_CERT_SIGN, %GNUTLS_KEY_CRL_SIGN,
 * %GNUTLS_KEY_ENCIPHER_ONLY, %GNUTLS_KEY_DECIPHER_ONLY.
 *
 * Returns: the certificate key usage, or a negative error code in case of
 *   parsing error.  If the certificate does not contain the keyUsage
 *   extension %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be
 *   returned.
 **/
int
gnutls_x509_crt_get_key_usage (gnutls_x509_crt_t cert,
                               unsigned int *key_usage,
                               unsigned int *critical)
{
  int result;
  gnutls_datum_t keyUsage;
  uint16_t _usage;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "2.5.29.15", 0, &keyUsage,
                                       critical)) < 0)
    {
      return result;
    }

  if (keyUsage.size == 0 || keyUsage.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = _gnutls_x509_ext_extract_keyUsage (&_usage, keyUsage.data,
                                              keyUsage.size);
  _gnutls_free_datum (&keyUsage);

  *key_usage = _usage;

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_proxy:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @critical: will be non (0) if the extension is marked as critical
 * @pathlen: pointer to output integer indicating path length (may be
 *   NULL), non-negative error codes indicate a present pCPathLenConstraint
 *   field and the actual value, -1 indicate that the field is absent.
 * @policyLanguage: output variable with OID of policy language
 * @policy: output variable with policy data
 * @sizeof_policy: output variable size of policy data
 *
 * This function will get information from a proxy certificate.  It
 * reads the ProxyCertInfo X.509 extension (1.3.6.1.5.5.7.1.14).
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/
int
gnutls_x509_crt_get_proxy (gnutls_x509_crt_t cert,
                           unsigned int *critical,
                           int *pathlen,
                           char **policyLanguage,
                           char **policy, size_t * sizeof_policy)
{
  int result;
  gnutls_datum_t proxyCertInfo;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "1.3.6.1.5.5.7.1.14", 0,
                                       &proxyCertInfo, critical)) < 0)
    {
      return result;
    }

  if (proxyCertInfo.size == 0 || proxyCertInfo.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = _gnutls_x509_ext_extract_proxyCertInfo (pathlen,
                                                   policyLanguage,
                                                   policy,
                                                   sizeof_policy,
                                                   proxyCertInfo.data,
                                                   proxyCertInfo.size);
  _gnutls_free_datum (&proxyCertInfo);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_crt_get_extension_by_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the extensions, this specifies which to send. Use (0) to get the first one.
 * @buf: a pointer to a structure to hold the name (may be null)
 * @buf_size: initially holds the size of @buf
 * @critical: will be non (0) if the extension is marked as critical
 *
 * This function will return the extension specified by the OID in the
 * certificate.  The extensions will be returned as binary data DER
 * encoded, in the provided buffer.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned. If the certificate does not
 *   contain the specified extension
 *   GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
gnutls_x509_crt_get_extension_by_oid (gnutls_x509_crt_t cert,
                                      const char *oid, int indx,
                                      void *buf, size_t * buf_size,
                                      unsigned int *critical)
{
  int result;
  gnutls_datum_t output;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result =
       _gnutls_x509_crt_get_extension (cert, oid, indx, &output,
                                       critical)) < 0)
    {
      gnutls_assert ();
      return result;
    }

  if (output.size == 0 || output.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (output.size > (unsigned int) *buf_size)
    {
      *buf_size = output.size;
      _gnutls_free_datum (&output);
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  *buf_size = output.size;

  if (buf)
    memcpy (buf, output.data, output.size);

  _gnutls_free_datum (&output);

  return 0;

}

/**
 * gnutls_x509_crt_get_extension_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use (0) to get the first one.
 * @oid: a pointer to a structure to hold the OID (may be null)
 * @oid_size: initially holds the size of @oid
 *
 * This function will return the requested extension OID in the certificate.
 * The extension OID will be stored as a string in the provided buffer.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.  If you have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 **/
int
gnutls_x509_crt_get_extension_oid (gnutls_x509_crt_t cert, int indx,
                                   void *oid, size_t * oid_size)
{
  int result;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_crt_get_extension_oid (cert, indx, oid, oid_size);
  if (result < 0)
    {
      return result;
    }

  return 0;

}

/**
 * gnutls_x509_crt_get_extension_info:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use (0) to get the first one.
 * @oid: a pointer to a structure to hold the OID
 * @oid_size: initially holds the maximum size of @oid, on return
 *   holds actual size of @oid.
 * @critical: output variable with critical flag, may be NULL.
 *
 * This function will return the requested extension OID in the
 * certificate, and the critical flag for it.  The extension OID will
 * be stored as a string in the provided buffer.  Use
 * gnutls_x509_crt_get_extension_data() to extract the data.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@oid_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will be
 * returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.  If you have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 **/
int
gnutls_x509_crt_get_extension_info (gnutls_x509_crt_t cert, int indx,
                                    void *oid, size_t * oid_size,
                                    unsigned int *critical)
{
  int result;
  char str_critical[10];
  char name[ASN1_MAX_NAME_SIZE];
  int len;

  if (!cert)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.extnID",
            indx + 1);

  len = *oid_size;
  result = asn1_read_value (cert->cert, name, oid, &len);
  *oid_size = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.critical",
            indx + 1);
  len = sizeof (str_critical);
  result = asn1_read_value (cert->cert, name, str_critical, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  if (critical)
    {
      if (str_critical[0] == 'T')
        *critical = 1;
      else
        *critical = 0;
    }

  return 0;

}

/**
 * gnutls_x509_crt_get_extension_data:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use (0) to get the first one.
 * @data: a pointer to a structure to hold the data (may be null)
 * @sizeof_data: initially holds the size of @oid
 *
 * This function will return the requested extension data in the
 * certificate.  The extension data will be stored as a string in the
 * provided buffer.
 *
 * Use gnutls_x509_crt_get_extension_info() to extract the OID and
 * critical flag.  Use gnutls_x509_crt_get_extension_by_oid() instead,
 * if you want to get data indexed by the extension OID rather than
 * sequence.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.  If you have reached the
 *   last extension available %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 *   will be returned.
 **/
int
gnutls_x509_crt_get_extension_data (gnutls_x509_crt_t cert, int indx,
                                    void *data, size_t * sizeof_data)
{
  int result, len;
  char name[ASN1_MAX_NAME_SIZE];

  if (!cert)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.extnValue",
            indx + 1);

  len = *sizeof_data;
  result = asn1_read_value (cert->cert, name, data, &len);
  *sizeof_data = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

static int
_gnutls_x509_crt_get_raw_dn2 (gnutls_x509_crt_t cert,
                              const char *whom, gnutls_datum_t * start)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, len1;
  int start1, end1;
  gnutls_datum_t signed_data = { NULL, 0 };

  /* get the issuer of 'cert'
   */
  if ((result =
       asn1_create_element (_gnutls_get_pkix (), "PKIX1.TBSCertificate",
                            &c2)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result =
    _gnutls_x509_get_signed_data (cert->cert, "tbsCertificate", &signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = asn1_der_decoding (&c2, signed_data.data, signed_data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  result =
    asn1_der_decoding_startEnd (c2, signed_data.data, signed_data.size,
                                whom, &start1, &end1);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  len1 = end1 - start1 + 1;

  _gnutls_set_datum (start, &signed_data.data[start1], len1);

  result = 0;

cleanup:
  asn1_delete_structure (&c2);
  _gnutls_free_datum (&signed_data);
  return result;
}

/**
 * gnutls_x509_crt_get_raw_issuer_dn:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @start: will hold the starting point of the DN
 *
 * This function will return a pointer to the DER encoded DN structure
 * and the length.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.or a negative error code on error.
 *
 **/
int
gnutls_x509_crt_get_raw_issuer_dn (gnutls_x509_crt_t cert,
                                   gnutls_datum_t * start)
{
  return _gnutls_x509_crt_get_raw_dn2 (cert, "issuer", start);
}

/**
 * gnutls_x509_crt_get_raw_dn:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @start: will hold the starting point of the DN
 *
 * This function will return a pointer to the DER encoded DN structure and
 * the length.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. or a negative error code on error.
 *
 **/
int
gnutls_x509_crt_get_raw_dn (gnutls_x509_crt_t cert, gnutls_datum_t * start)
{
  return _gnutls_x509_crt_get_raw_dn2 (cert, "subject", start);
}

static int
get_dn (gnutls_x509_crt_t cert, const char *whom, gnutls_x509_dn_t * dn)
{
  *dn = asn1_find_node (cert->cert, whom);
  if (!*dn)
    return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
  return 0;
}

/**
 * gnutls_x509_crt_get_subject:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @dn: output variable with pointer to opaque DN.
 *
 * Return the Certificate's Subject DN as an opaque data type.  You
 * may use gnutls_x509_dn_get_rdn_ava() to decode the DN. 
 *
 * Note that @dn should be treated as constant. Because points 
 * into the @cert object, you may not deallocate @cert 
 * and continue to access @dn.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
gnutls_x509_crt_get_subject (gnutls_x509_crt_t cert, gnutls_x509_dn_t * dn)
{
  return get_dn (cert, "tbsCertificate.subject.rdnSequence", dn);
}

/**
 * gnutls_x509_crt_get_issuer:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @dn: output variable with pointer to opaque DN
 *
 * Return the Certificate's Issuer DN as an opaque data type.  You may
 * use gnutls_x509_dn_get_rdn_ava() to decode the DN.
 *
 * Note that @dn should be treated as constant. Because points 
 * into the @cert object, you may not deallocate @cert 
 * and continue to access @dn.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
gnutls_x509_crt_get_issuer (gnutls_x509_crt_t cert, gnutls_x509_dn_t * dn)
{
  return get_dn (cert, "tbsCertificate.issuer.rdnSequence", dn);
}

/**
 * gnutls_x509_dn_get_rdn_ava:
 * @dn: input variable with opaque DN pointer
 * @irdn: index of RDN
 * @iava: index of AVA.
 * @ava: Pointer to structure which will hold output information.
 *
 * Get pointers to data within the DN.
 *
 * Note that @ava will contain pointers into the @dn structure, so you
 * should not modify any data or deallocate it.  Note also that the DN
 * in turn points into the original certificate structure, and thus
 * you may not deallocate the certificate and continue to access @dn.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
gnutls_x509_dn_get_rdn_ava (gnutls_x509_dn_t dn,
                            int irdn, int iava, gnutls_x509_ava_st * ava)
{
  ASN1_TYPE rdn, elem;
  long len;
  int lenlen, remlen, ret;
  char rbuf[ASN1_MAX_NAME_SIZE];
  unsigned char cls, *ptr;

  iava++;
  irdn++;                       /* 0->1, 1->2 etc */

  snprintf (rbuf, sizeof (rbuf), "rdnSequence.?%d.?%d", irdn, iava);
  rdn = asn1_find_node (dn, rbuf);
  if (!rdn)
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  snprintf (rbuf, sizeof (rbuf), "?%d.type", iava);
  elem = asn1_find_node (rdn, rbuf);
  if (!elem)
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  ava->oid.data = elem->value;
  ava->oid.size = elem->value_len;

  snprintf (rbuf, sizeof (rbuf), "?%d.value", iava);
  elem = asn1_find_node (rdn, rbuf);
  if (!elem)
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  /* The value still has the previous tag's length bytes, plus the
   * current value's tag and length bytes. Decode them.
   */

  ptr = elem->value;
  remlen = elem->value_len;
  len = asn1_get_length_der (ptr, remlen, &lenlen);
  if (len < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_DER_ERROR;
    }

  ptr += lenlen;
  remlen -= lenlen;
  ret = asn1_get_tag_der (ptr, remlen, &cls, &lenlen, &ava->value_tag);
  if (ret)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  ptr += lenlen;
  remlen -= lenlen;

  {
    signed long tmp;

    tmp = asn1_get_length_der (ptr, remlen, &lenlen);
    if (tmp < 0)
      {
        gnutls_assert ();
        return GNUTLS_E_ASN1_DER_ERROR;
      }
    ava->value.size = tmp;
  }
  ava->value.data = ptr + lenlen;

  return 0;
}

/**
 * gnutls_x509_crt_get_fingerprint:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @algo: is a digest algorithm
 * @buf: a pointer to a structure to hold the fingerprint (may be null)
 * @buf_size: initially holds the size of @buf
 *
 * This function will calculate and copy the certificate's fingerprint
 * in the provided buffer.
 *
 * If the buffer is null then only the size will be filled.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *buf_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_fingerprint (gnutls_x509_crt_t cert,
                                 gnutls_digest_algorithm_t algo,
                                 void *buf, size_t * buf_size)
{
  opaque *cert_buf;
  int cert_buf_size;
  int result;
  gnutls_datum_t tmp;

  if (buf_size == 0 || cert == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  cert_buf_size = 0;
  asn1_der_coding (cert->cert, "", NULL, &cert_buf_size, NULL);

  cert_buf = gnutls_malloc (cert_buf_size);
  if (cert_buf == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (cert->cert, "", cert_buf, &cert_buf_size, NULL);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (cert_buf);
      return _gnutls_asn2err (result);
    }

  tmp.data = cert_buf;
  tmp.size = cert_buf_size;

  result = gnutls_fingerprint (algo, &tmp, buf, buf_size);
  gnutls_free (cert_buf);

  return result;
}

/**
 * gnutls_x509_crt_export:
 * @cert: Holds the certificate
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a certificate PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the certificate to DER or PEM format.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN CERTIFICATE".
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 **/
int
gnutls_x509_crt_export (gnutls_x509_crt_t cert,
                        gnutls_x509_crt_fmt_t format, void *output_data,
                        size_t * output_data_size)
{
  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_export_int (cert->cert, format, "CERTIFICATE",
                                  output_data, output_data_size);
}

int
_gnutls_get_key_id (gnutls_pk_algorithm_t pk, gnutls_pk_params_st * params,
                    unsigned char *output_data,
                    size_t * output_data_size)
{
  int ret = 0;
  gnutls_datum_t der = { NULL, 0 };
  const gnutls_digest_algorithm_t hash = GNUTLS_DIG_SHA1;
  int digest_len = _gnutls_hash_get_algo_len(hash);

  if (output_data == NULL || *output_data_size < digest_len)
    {
      gnutls_assert ();
      *output_data_size = digest_len;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  ret = _gnutls_x509_encode_PKI_params(&der, pk, params);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_hash_fast(hash, der.data, der.size, output_data);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }
  *output_data_size = digest_len;

  ret = 0;

cleanup:

  _gnutls_free_datum (&der);
  return ret;
}

/**
 * gnutls_x509_crt_get_key_id:
 * @crt: Holds the certificate
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public
 * key parameters. This ID can be used in checking whether a
 * certificate corresponds to the given private key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 **/
int
gnutls_x509_crt_get_key_id (gnutls_x509_crt_t crt, unsigned int flags,
                            unsigned char *output_data,
                            size_t * output_data_size)
{
  int pk, ret = 0;
  gnutls_pk_params_st params;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  pk = gnutls_x509_crt_get_pk_algorithm (crt, NULL);
  if (pk < 0)
    {
      gnutls_assert ();
      return pk;
    }

  ret = _gnutls_x509_crt_get_mpis (crt, &params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
  
  ret = _gnutls_get_key_id(pk, &params, output_data, output_data_size);

  gnutls_pk_params_release(&params);

  return ret;
}


#ifdef ENABLE_PKI

/* This is exactly as gnutls_x509_crt_check_revocation() except that
 * it calls func.
 */
int
_gnutls_x509_crt_check_revocation (gnutls_x509_crt_t cert,
                                  const gnutls_x509_crl_t * crl_list,
                                  int crl_list_length,
                                  gnutls_verify_output_function func)
{
  opaque serial[128];
  opaque cert_serial[128];
  size_t serial_size, cert_serial_size;
  int ncerts, ret, i, j;
  gnutls_datum_t dn1, dn2;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  for (j = 0; j < crl_list_length; j++)
    {                           /* do for all the crls */

      /* Step 1. check if issuer's DN match
       */
      ret = gnutls_x509_crl_get_raw_issuer_dn (crl_list[j], &dn1);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn2);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);
      _gnutls_free_datum (&dn1);
      _gnutls_free_datum (&dn2);
      if (ret == 0)
        {
          /* issuers do not match so don't even
           * bother checking.
           */
          continue;
        }

      /* Step 2. Read the certificate's serial number
       */
      cert_serial_size = sizeof (cert_serial);
      ret = gnutls_x509_crt_get_serial (cert, cert_serial, &cert_serial_size);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      /* Step 3. cycle through the CRL serials and compare with
       *   certificate serial we have.
       */

      ncerts = gnutls_x509_crl_get_crt_count (crl_list[j]);
      if (ncerts < 0)
        {
          gnutls_assert ();
          return ncerts;
        }

      for (i = 0; i < ncerts; i++)
        {
          serial_size = sizeof (serial);
          ret =
            gnutls_x509_crl_get_crt_serial (crl_list[j], i, serial,
                                            &serial_size, NULL);

          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }

          if (serial_size == cert_serial_size)
            {
              if (memcmp (serial, cert_serial, serial_size) == 0)
                {
                  /* serials match */
                  if (func) func(cert, NULL, crl_list[j], GNUTLS_CERT_REVOKED|GNUTLS_CERT_INVALID);
                  return 1;     /* revoked! */
                }
            }
        }
      if (func) func(cert, NULL, crl_list[j], 0);

    }
  return 0;                     /* not revoked. */
}


/**
 * gnutls_x509_crt_check_revocation:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @crl_list: should contain a list of gnutls_x509_crl_t structures
 * @crl_list_length: the length of the crl_list
 *
 * This function will return check if the given certificate is
 * revoked.  It is assumed that the CRLs have been verified before.
 *
 * Returns: 0 if the certificate is NOT revoked, and 1 if it is.  A
 * negative error code is returned on error.
 **/
int
gnutls_x509_crt_check_revocation (gnutls_x509_crt_t cert,
                                  const gnutls_x509_crl_t * crl_list,
                                  int crl_list_length)
{
  return _gnutls_x509_crt_check_revocation(cert, crl_list, crl_list_length, NULL);
}

/**
 * gnutls_x509_crt_get_verify_algorithm:
 * @crt: Holds the certificate
 * @signature: contains the signature
 * @hash: The result of the call with the hash algorithm used for signature
 *
 * This function will read the certifcate and the signed data to
 * determine the hash algorithm used to generate the signature.
 *
 * Deprecated: Use gnutls_pubkey_get_verify_algorithm() instead.
 *
 * Returns: the 0 if the hash algorithm is found. A negative error code is
 * returned on error.
 *
 * Since: 2.8.0
 **/
int
gnutls_x509_crt_get_verify_algorithm (gnutls_x509_crt_t crt,
                                      const gnutls_datum_t * signature,
                                      gnutls_digest_algorithm_t * hash)
{
  gnutls_pk_params_st issuer_params;
  int ret;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_x509_crt_get_mpis (crt, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_x509_verify_algorithm ((gnutls_mac_algorithm_t *) hash,
                                       signature,
                                       gnutls_x509_crt_get_pk_algorithm (crt,
                                                                         NULL),
                                       &issuer_params);

  /* release allocated mpis */
  gnutls_pk_params_release(&issuer_params);

  return ret;
}



/**
 * gnutls_x509_crt_get_preferred_hash_algorithm:
 * @crt: Holds the certificate
 * @hash: The result of the call with the hash algorithm used for signature
 * @mand: If non (0) it means that the algorithm MUST use this hash. May be NULL.
 *
 * This function will read the certifcate and return the appropriate digest
 * algorithm to use for signing with this certificate. Some certificates (i.e.
 * DSA might not be able to sign without the preferred algorithm).
 *
 * Deprecated: Please use gnutls_pubkey_get_preferred_hash_algorithm().
 *
 * Returns: the 0 if the hash algorithm is found. A negative error code is
 * returned on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_get_preferred_hash_algorithm (gnutls_x509_crt_t crt,
                                              gnutls_digest_algorithm_t *
                                              hash, unsigned int *mand)
{
  gnutls_pk_params_st issuer_params;
  int ret;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_x509_crt_get_mpis (crt, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    _gnutls_pk_get_hash_algorithm (gnutls_x509_crt_get_pk_algorithm
                                   (crt, NULL), &issuer_params,
                                   hash, mand);

  /* release allocated mpis */
  gnutls_pk_params_release(&issuer_params);

  return ret;
}

/**
 * gnutls_x509_crt_verify_data:
 * @crt: Holds the certificate
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: contains the signature
 *
 * This function will verify the given signed data, using the
 * parameters from the certificate.
 *
 * Deprecated. Please use gnutls_pubkey_verify_data().
 *
 * Returns: In case of a verification failure %GNUTLS_E_PK_SIG_VERIFY_FAILED 
 * is returned, and a positive code on success.
 **/
int
gnutls_x509_crt_verify_data (gnutls_x509_crt_t crt, unsigned int flags,
                             const gnutls_datum_t * data,
                             const gnutls_datum_t * signature)
{
  int result;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_verify_data (GNUTLS_DIG_UNKNOWN, data, signature, crt);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return result;
}

/**
 * gnutls_x509_crt_verify_hash:
 * @crt: Holds the certificate
 * @flags: should be 0 for now
 * @hash: holds the hash digest to be verified
 * @signature: contains the signature
 *
 * This function will verify the given signed digest, using the
 * parameters from the certificate.
 *
 * Deprecated. Please use gnutls_pubkey_verify_data().
 *
 * Returns: In case of a verification failure %GNUTLS_E_PK_SIG_VERIFY_FAILED 
 * is returned, and a positive code on success.
 **/
int
gnutls_x509_crt_verify_hash (gnutls_x509_crt_t crt, unsigned int flags,
                             const gnutls_datum_t * hash,
                             const gnutls_datum_t * signature)
{
  int result;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_verify_hashed_data (hash, signature, crt);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return result;
}

/**
 * gnutls_x509_crt_get_crl_dist_points:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the distribution point (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the distribution point will be copied to
 * @ret_size: holds the size of ret.
 * @reason_flags: Revocation reasons flags.
 * @critical: will be non (0) if the extension is marked as critical (may be null)
 *
 * This function retrieves the CRL distribution points (2.5.29.31),
 * contained in the given certificate in the X509v3 Certificate
 * Extensions.
 *
 * @reason_flags should be an ORed sequence of
 * %GNUTLS_CRL_REASON_UNUSED, %GNUTLS_CRL_REASON_KEY_COMPROMISE,
 * %GNUTLS_CRL_REASON_CA_COMPROMISE,
 * %GNUTLS_CRL_REASON_AFFILIATION_CHANGED,
 * %GNUTLS_CRL_REASON_SUPERSEEDED,
 * %GNUTLS_CRL_REASON_CESSATION_OF_OPERATION,
 * %GNUTLS_CRL_REASON_CERTIFICATE_HOLD,
 * %GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN,
 * %GNUTLS_CRL_REASON_AA_COMPROMISE, or (0) for all possible reasons.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER and updates @ret_size if
 *   @ret_size is not enough to hold the distribution point, or the
 *   type of the distribution point if everything was ok. The type is
 *   one of the enumerated %gnutls_x509_subject_alt_name_t.  If the
 *   certificate does not have an Alternative name with the specified
 *   sequence number then %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is
 *   returned.
 **/
int
gnutls_x509_crt_get_crl_dist_points (gnutls_x509_crt_t cert,
                                     unsigned int seq, void *ret,
                                     size_t * ret_size,
                                     unsigned int *reason_flags,
                                     unsigned int *critical)
{
  int result;
  gnutls_datum_t dist_points = { NULL, 0 };
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  char name[ASN1_MAX_NAME_SIZE];
  int len;
  gnutls_x509_subject_alt_name_t type;
  uint8_t reasons[2];

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*ret_size > 0 && ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if (reason_flags)
    *reason_flags = 0;

  result =
    _gnutls_x509_crt_get_extension (cert, "2.5.29.31", 0, &dist_points,
                                    critical);
  if (result < 0)
    {
      return result;
    }

  if (dist_points.size == 0 || dist_points.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.CRLDistributionPoints", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&dist_points);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, dist_points.data, dist_points.size, NULL);
  _gnutls_free_datum (&dist_points);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  /* Return the different names from the first CRLDistr. point.
   * The whole thing is a mess.
   */
  _gnutls_str_cpy (name, sizeof (name), "?1.distributionPoint.fullName");

  result = _gnutls_parse_general_name (c2, name, seq, ret, ret_size, NULL, 0);
  if (result < 0)
    {
      asn1_delete_structure (&c2);
      return result;
    }

  type = result;


  /* Read the CRL reasons.
   */
  if (reason_flags)
    {
      _gnutls_str_cpy (name, sizeof (name), "?1.reasons");

      reasons[0] = reasons[1] = 0;

      len = sizeof (reasons);
      result = asn1_read_value (c2, name, reasons, &len);

      if (result != ASN1_VALUE_NOT_FOUND && result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          asn1_delete_structure (&c2);
          return _gnutls_asn2err (result);
        }

      *reason_flags = reasons[0] | (reasons[1] << 8);
    }

  return type;
}

/**
 * gnutls_x509_crt_get_key_purpose_oid:
 * @cert: should contain a #gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use (0) to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @oid_size: initially holds the size of @oid
 * @critical: output flag to indicate criticality of extension
 *
 * This function will extract the key purpose OIDs of the Certificate
 * specified by the given index.  These are stored in the Extended Key
 * Usage extension (2.5.29.37) See the GNUTLS_KP_* definitions for
 * human readable names.
 *
 * If @oid is null then only the size will be filled. If the @raw_flag
 * is not specified the output is always null terminated, although the
 * @oid_size will not include the null character.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 *   not long enough, and in that case the *oid_size will be updated
 *   with the required size.  On success 0 is returned.
 **/
int
gnutls_x509_crt_get_key_purpose_oid (gnutls_x509_crt_t cert,
                                     int indx, void *oid, size_t * oid_size,
                                     unsigned int *critical)
{
  char tmpstr[ASN1_MAX_NAME_SIZE];
  int result, len;
  gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (oid)
    memset (oid, 0, *oid_size);
  else
    *oid_size = 0;

  if ((result =
       _gnutls_x509_crt_get_extension (cert, "2.5.29.37", 0, &id,
                                       critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = asn1_create_element
    (_gnutls_get_pkix (), "PKIX1.ExtKeyUsageSyntax", &c2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&id);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&c2, id.data, id.size, NULL);
  _gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (result);
    }

  indx++;
  /* create a string like "?1"
   */
  snprintf (tmpstr, sizeof (tmpstr), "?%u", indx);

  len = *oid_size;
  result = asn1_read_value (c2, tmpstr, oid, &len);

  *oid_size = len;
  asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;

}

/**
 * gnutls_x509_crt_get_pk_rsa_raw:
 * @crt: Holds the certificate
 * @m: will hold the modulus
 * @e: will hold the public exponent
 *
 * This function will export the RSA public key's parameters found in
 * the given structure.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 **/
int
gnutls_x509_crt_get_pk_rsa_raw (gnutls_x509_crt_t crt,
                                gnutls_datum_t * m, gnutls_datum_t * e)
{
  int ret;
  gnutls_pk_params_st params;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gnutls_x509_crt_get_pk_algorithm (crt, NULL);
  if (ret != GNUTLS_PK_RSA)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_x509_crt_get_mpis (crt, &params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_mpi_dprint_lz (params.params[0], m);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_mpi_dprint_lz (params.params[1], e);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (m);
      goto cleanup;
    }

  ret = 0;

cleanup:
  gnutls_pk_params_release(&params);
  return ret;
}

/**
 * gnutls_x509_crt_get_pk_dsa_raw:
 * @crt: Holds the certificate
 * @p: will hold the p
 * @q: will hold the q
 * @g: will hold the g
 * @y: will hold the y
 *
 * This function will export the DSA public key's parameters found in
 * the given certificate.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 **/
int
gnutls_x509_crt_get_pk_dsa_raw (gnutls_x509_crt_t crt,
                                gnutls_datum_t * p, gnutls_datum_t * q,
                                gnutls_datum_t * g, gnutls_datum_t * y)
{
  int ret;
  gnutls_pk_params_st params;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gnutls_x509_crt_get_pk_algorithm (crt, NULL);
  if (ret != GNUTLS_PK_DSA)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_x509_crt_get_mpis (crt, &params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }


  /* P */
  ret = _gnutls_mpi_dprint_lz (params.params[0], p);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* Q */
  ret = _gnutls_mpi_dprint_lz (params.params[1], q);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      goto cleanup;
    }


  /* G */
  ret = _gnutls_mpi_dprint_lz (params.params[2], g);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (q);
      goto cleanup;
    }


  /* Y */
  ret = _gnutls_mpi_dprint_lz (params.params[3], y);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (g);
      _gnutls_free_datum (q);
      goto cleanup;
    }

  ret = 0;

cleanup:
  gnutls_pk_params_release(&params);
  return ret;

}

#endif
/**
 * gnutls_x509_crt_list_import2:
 * @certs: The structures to store the parsed certificate. Must not be initialized.
 * @size: It will contain the size of the list.
 * @data: The PEM encoded certificate.
 * @format: One of DER or PEM.
 * @flags: must be (0) or an OR'd sequence of gnutls_certificate_import_flags.
 *
 * This function will convert the given PEM encoded certificate list
 * to the native gnutls_x509_crt_t format. The output will be stored
 * in @certs.  They will be automatically initialized.
 *
 * If the Certificate is PEM encoded it should have a header of "X509
 * CERTIFICATE", or "CERTIFICATE".
 *
 * Returns: the number of certificates read or a negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_crt_list_import2 (gnutls_x509_crt_t ** certs,
                             unsigned int * size,
                             const gnutls_datum_t * data,
                             gnutls_x509_crt_fmt_t format, unsigned int flags)
{
unsigned int init = 1024;
int ret;

  *certs = gnutls_malloc(sizeof(gnutls_x509_crt_t)*init);
  if (*certs == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = gnutls_x509_crt_list_import(*certs, &init, data, format, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
  if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      *certs = gnutls_realloc_fast(*certs, sizeof(gnutls_x509_crt_t)*init);
      if (*certs == NULL)
        {
          gnutls_assert();
          return GNUTLS_E_MEMORY_ERROR;
        }
      
      ret = gnutls_x509_crt_list_import(*certs, &init, data, format, flags);
    }

  if (ret < 0)
    {
      gnutls_free(*certs);
      *certs = NULL;
      return ret;
    }

  *size = init;
  return 0;
}

static int check_if_sorted(gnutls_x509_crt_t * crt, int nr)
{
char prev_dn[MAX_DN];
char dn[MAX_DN];
size_t prev_dn_size, dn_size;
int i, ret;

  /* check if the X.509 list is ordered */
  if (nr > 1)
    {

      for (i=0;i<nr;i++)
        {
          if (i>0)
            {
              dn_size = sizeof(dn);
              ret = gnutls_x509_crt_get_dn(crt[i], dn, &dn_size);
              if (ret < 0)
                {
                  ret = gnutls_assert_val(ret);
                  goto cleanup;
                }
              
              if (dn_size != prev_dn_size || memcmp(dn, prev_dn, dn_size) != 0)
                {
                  ret = gnutls_assert_val(GNUTLS_E_CERTIFICATE_LIST_UNSORTED);
                  goto cleanup;
                }
            }

          prev_dn_size = sizeof(prev_dn);
          ret = gnutls_x509_crt_get_issuer_dn(crt[i], prev_dn, &prev_dn_size);
          if (ret < 0)
            {
              ret = gnutls_assert_val(ret);
              goto cleanup;
            }
        }
    }

  ret = 0;

cleanup:
  return ret;
}


/**
 * gnutls_x509_crt_list_import:
 * @certs: The structures to store the parsed certificate. Must not be initialized.
 * @cert_max: Initially must hold the maximum number of certs. It will be updated with the number of certs available.
 * @data: The PEM encoded certificate.
 * @format: One of DER or PEM.
 * @flags: must be (0) or an OR'd sequence of gnutls_certificate_import_flags.
 *
 * This function will convert the given PEM encoded certificate list
 * to the native gnutls_x509_crt_t format. The output will be stored
 * in @certs.  They will be automatically initialized.
 *
 * The flag %GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED will cause
 * import to fail if the certificates in the provided buffer are more
 * than the available structures. The %GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED
 * flag will cause the function to fail if the provided list is not
 * sorted from subject to issuer.
 *
 * If the Certificate is PEM encoded it should have a header of "X509
 * CERTIFICATE", or "CERTIFICATE".
 *
 * Returns: the number of certificates read or a negative error value.
 **/
int
gnutls_x509_crt_list_import (gnutls_x509_crt_t * certs,
                             unsigned int *cert_max,
                             const gnutls_datum_t * data,
                             gnutls_x509_crt_fmt_t format, unsigned int flags)
{
  int size;
  const char *ptr;
  gnutls_datum_t tmp;
  int ret, nocopy = 0;
  unsigned int count = 0, j;

  if (format == GNUTLS_X509_FMT_DER)
    {
      if (*cert_max < 1)
        {
          *cert_max = 1;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }

      count = 1;                /* import only the first one */

      ret = gnutls_x509_crt_init (&certs[0]);
      if (ret < 0)
        {
          gnutls_assert ();
          goto error;
        }

      ret = gnutls_x509_crt_import (certs[0], data, format);
      if (ret < 0)
        {
          gnutls_assert ();
          goto error;
        }

      *cert_max = 1;
      return 1;
    }

  /* move to the certificate
   */
  ptr = memmem (data->data, data->size,
                PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
  if (ptr == NULL)
    ptr = memmem (data->data, data->size,
                  PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

  if (ptr == NULL)
    return gnutls_assert_val(GNUTLS_E_NO_CERTIFICATE_FOUND);

  count = 0;

  do
    {
      if (count >= *cert_max)
        {
          if (!(flags & GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED))
            break;
          else
            nocopy = 1;
        }

      if (!nocopy)
        {
          ret = gnutls_x509_crt_init (&certs[count]);
          if (ret < 0)
            {
              gnutls_assert ();
              goto error;
            }

          tmp.data = (void *) ptr;
          tmp.size = data->size - (ptr - (char *) data->data);

          ret =
            gnutls_x509_crt_import (certs[count], &tmp, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              gnutls_assert ();
              goto error;
            }
        }

      /* now we move ptr after the pem header 
       */
      ptr++;
      /* find the next certificate (if any)
       */
      size = data->size - (ptr - (char *) data->data);

      if (size > 0)
        {
          char *ptr2;

          ptr2 = memmem (ptr, size, PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
          if (ptr2 == NULL)
            ptr2 = memmem (ptr, size, PEM_CERT_SEP2,
                           sizeof (PEM_CERT_SEP2) - 1);

          ptr = ptr2;
        }
      else
        ptr = NULL;

      count++;
    }
  while (ptr != NULL);

  *cert_max = count;

  if (flags & GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED)
    {
      ret = check_if_sorted(certs, *cert_max);
      if (ret < 0)
        {
          gnutls_assert();
          goto error;
        }
    }

  if (nocopy == 0)
    return count;
  else
    return GNUTLS_E_SHORT_MEMORY_BUFFER;

error:
  for (j = 0; j < count; j++)
    gnutls_x509_crt_deinit (certs[j]);
  return ret;
}

/**
 * gnutls_x509_crt_get_subject_unique_id:
 * @crt: Holds the certificate
 * @buf: user allocated memory buffer, will hold the unique id
 * @buf_size: size of user allocated memory buffer (on input), will hold
 * actual size of the unique ID on return.
 *
 * This function will extract the subjectUniqueID value (if present) for
 * the given certificate.
 *
 * If the user allocated memory buffer is not large enough to hold the
 * full subjectUniqueID, then a GNUTLS_E_SHORT_MEMORY_BUFFER error will be
 * returned, and buf_size will be set to the actual length.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 **/
int
gnutls_x509_crt_get_subject_unique_id (gnutls_x509_crt_t crt, char *buf,
                                       size_t * buf_size)
{
  int result;
  gnutls_datum_t datum = { NULL, 0 };

  result =
    _gnutls_x509_read_value (crt->cert, "tbsCertificate.subjectUniqueID",
                             &datum, 2);

  if (datum.size > *buf_size)
    {                           /* then we're not going to fit */
      *buf_size = datum.size;
      buf[0] = '\0';
      result = GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
  else
    {
      *buf_size = datum.size;
      memcpy (buf, datum.data, datum.size);
    }

  _gnutls_free_datum (&datum);

  return result;
}

/**
 * gnutls_x509_crt_get_issuer_unique_id:
 * @crt: Holds the certificate
 * @buf: user allocated memory buffer, will hold the unique id
 * @buf_size: size of user allocated memory buffer (on input), will hold
 * actual size of the unique ID on return.
 *
 * This function will extract the issuerUniqueID value (if present) for
 * the given certificate.
 *
 * If the user allocated memory buffer is not large enough to hold the
 * full subjectUniqueID, then a GNUTLS_E_SHORT_MEMORY_BUFFER error will be
 * returned, and buf_size will be set to the actual length.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_get_issuer_unique_id (gnutls_x509_crt_t crt, char *buf,
                                      size_t * buf_size)
{
  int result;
  gnutls_datum_t datum = { NULL, 0 };

  result =
    _gnutls_x509_read_value (crt->cert, "tbsCertificate.issuerUniqueID",
                             &datum, 2);

  if (datum.size > *buf_size)
    {                           /* then we're not going to fit */
      *buf_size = datum.size;
      buf[0] = '\0';
      result = GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
  else
    {
      *buf_size = datum.size;
      memcpy (buf, datum.data, datum.size);
    }

  _gnutls_free_datum (&datum);

  return result;
}

static int
_gnutls_parse_aia (ASN1_TYPE src,
		   unsigned int seq,
		   int what,
		   gnutls_datum_t * data)
{
  int len;
  char nptr[ASN1_MAX_NAME_SIZE];
  int result;
  gnutls_datum_t d;
  const char *oid = NULL;

  seq++;                        /* 0->1, 1->2 etc */
  switch (what)
    {
    case GNUTLS_IA_ACCESSMETHOD_OID:
      snprintf (nptr, sizeof (nptr), "?%u.accessMethod", seq);
      break;

    case GNUTLS_IA_ACCESSLOCATION_GENERALNAME_TYPE:
      snprintf (nptr, sizeof (nptr), "?%u.accessLocation", seq);
      break;

    case GNUTLS_IA_CAISSUERS_URI:
      oid = GNUTLS_OID_AD_CAISSUERS;
      /* fall through */

    case GNUTLS_IA_OCSP_URI:
      if (oid == NULL)
	oid = GNUTLS_OID_AD_OCSP;
      {
	char *tmpoid[20];
	snprintf (nptr, sizeof (nptr), "?%u.accessMethod", seq);
	len = sizeof (tmpoid);
	result = asn1_read_value (src, nptr, tmpoid, &len);
	if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
	  return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	if (result != ASN1_SUCCESS)
	  {
	    gnutls_assert ();
	    return _gnutls_asn2err (result);
	  }
	if (len != strlen (oid) + 1 || memcmp (tmpoid, oid, len) != 0)
	  return GNUTLS_E_UNKNOWN_ALGORITHM;
      }
      /* fall through */

      case GNUTLS_IA_URI:
	snprintf (nptr, sizeof (nptr),
		  "?%u.accessLocation.uniformResourceIdentifier", seq);
	break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = 0;
  result = asn1_read_value (src, nptr, NULL, &len);
  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  if (result != ASN1_MEM_ERROR)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }
  d.size = len;
  d.data = gnutls_malloc (d.size);
  if (d.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  result = asn1_read_value (src, nptr, d.data, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (d.data);
      return _gnutls_asn2err (result);
    }

  if (data)
    {
      data->data = d.data;
      data->size = d.size;
    }
  else
    gnutls_free (d.data);

  return GNUTLS_E_SUCCESS;
}

/**
 * gnutls_x509_crt_get_authority_info_access:
 * @crt: Holds the certificate
 * @seq: specifies the sequence number of the access descriptor (0 for the first one, 1 for the second etc.)
 * @what: what data to get, a #gnutls_info_access_what_t type.
 * @data: output data to be freed with gnutls_free().
 * @critical: pointer to output integer that is set to non-0 if the extension is marked as critical (may be %NULL)
 *
 * This function extracts the Authority Information Access (AIA)
 * extension, see RFC 5280 section 4.2.2.1 for more information.  The
 * AIA extension holds a sequence of AccessDescription (AD) data:
 *
 * <informalexample><programlisting>
 * AuthorityInfoAccessSyntax  ::=
 *         SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 * AccessDescription  ::=  SEQUENCE {
 *         accessMethod          OBJECT IDENTIFIER,
 *         accessLocation        GeneralName  }
 * </programlisting></informalexample>
 *
 * The @seq input parameter is used to indicate which member of the
 * sequence the caller is interested in.  The first member is 0, the
 * second member 1 and so on.  When the @seq value is out of bounds,
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * The type of data returned in @data is specified via @what which
 * should be #gnutls_info_access_what_t values.
 *
 * If @what is %GNUTLS_IA_ACCESSMETHOD_OID then @data will hold the
 * accessMethod OID (e.g., "1.3.6.1.5.5.7.48.1").
 *
 * If @what is %GNUTLS_IA_ACCESSLOCATION_GENERALNAME_TYPE, @data will
 * hold the accessLocation GeneralName type (e.g.,
 * "uniformResourceIdentifier").
 *
 * If @what is %GNUTLS_IA_URI, @data will hold the accessLocation URI
 * data.  Requesting this @what value leads to an error if the
 * accessLocation is not of the "uniformResourceIdentifier" type.
 *
 * If @what is %GNUTLS_IA_OCSP_URI, @data will hold the OCSP URI.
 * Requesting this @what value leads to an error if the accessMethod
 * is not 1.3.6.1.5.5.7.48.1 aka OSCP, or if accessLocation is not of
 * the "uniformResourceIdentifier" type.
 *
 * If @what is %GNUTLS_IA_CAISSUERS_URI, @data will hold the caIssuers
 * URI.  Requesting this @what value leads to an error if the
 * accessMethod is not 1.3.6.1.5.5.7.48.2 aka caIssuers, or if
 * accessLocation is not of the "uniformResourceIdentifier" type.
 *
 * More @what values may be allocated in the future as needed.
 *
 * If @data is NULL, the function does the same without storing the
 * output data, that is, it will set @critical and do error checking
 * as usual.
 *
 * The value of the critical flag is returned in *@critical.  Supply a
 * NULL @critical if you want the function to make sure the extension
 * is non-critical, as required by RFC 5280.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, %GNUTLS_E_INVALID_REQUEST on
 * invalid @crt, %GNUTLS_E_CONSTRAINT_ERROR if the extension is
 * incorrectly marked as critical (use a non-NULL @critical to
 * override), %GNUTLS_E_UNKNOWN_ALGORITHM if the requested OID does
 * not match (e.g., when using %GNUTLS_IA_OCSP_URI), otherwise a
 * negative error code.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_crt_get_authority_info_access (gnutls_x509_crt_t crt,
					   unsigned int seq,
					   int what,
					   gnutls_datum_t * data,
					   int *critical)
{
  int ret;
  gnutls_datum_t aia;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((ret = _gnutls_x509_crt_get_extension (crt, GNUTLS_OID_AIA, 0, &aia,
					     critical)) < 0)
    return ret;

  if (aia.size == 0 || aia.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (critical && *critical)
    return GNUTLS_E_CONSTRAINT_ERROR;

  ret = asn1_create_element (_gnutls_get_pkix (),
			     "PKIX1.AuthorityInfoAccessSyntax", &c2);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      _gnutls_free_datum (&aia);
      return _gnutls_asn2err (ret);
    }

  ret = asn1_der_decoding (&c2, aia.data, aia.size, NULL);
  /* asn1_print_structure (stdout, c2, "", ASN1_PRINT_ALL); */
  _gnutls_free_datum (&aia);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&c2);
      return _gnutls_asn2err (ret);
    }

  ret = _gnutls_parse_aia (c2, seq, what, data);
  asn1_delete_structure (&c2);
  if (ret < 0)
    gnutls_assert ();

  return ret;
}
