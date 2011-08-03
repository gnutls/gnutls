/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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

/* All functions which relate to X.509 certificate verification stuff are
 * included here
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>         /* MAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <x509_int.h>
#include <common.h>
#include <gnutls_pk.h>

static int is_crl_issuer (gnutls_x509_crl_t crl,
                          gnutls_x509_crt_t issuer_cert);

static int _gnutls_verify_crl2 (gnutls_x509_crl_t crl,
                                const gnutls_x509_crt_t * trusted_cas,
                                int tcas_size, unsigned int flags,
                                unsigned int *output);

/* Checks if two certs are identical.  Return 0 on match. */
int
check_if_same_cert (gnutls_x509_crt_t cert1, gnutls_x509_crt_t cert2)
{
  gnutls_datum_t cert1bin = { NULL, 0 }, cert2bin =
  {
  NULL, 0};
  int result;
  opaque serial1[128], serial2[128];
  size_t serial1_size, serial2_size;

  serial1_size = sizeof (serial1);
  result = gnutls_x509_crt_get_serial (cert1, serial1, &serial1_size);
  if (result < 0)
    {
      gnutls_assert ();
      goto cmp;
    }

  serial2_size = sizeof (serial2);
  result = gnutls_x509_crt_get_serial (cert2, serial2, &serial2_size);
  if (result < 0)
    {
      gnutls_assert ();
      goto cmp;
    }

  if (serial2_size != serial1_size
      || memcmp (serial1, serial2, serial1_size) != 0)
    {
      return 1;
    }

cmp:
  result = _gnutls_x509_der_encode (cert1->cert, "", &cert1bin, 0);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_der_encode (cert2->cert, "", &cert2bin, 0);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  if ((cert1bin.size == cert2bin.size) &&
      (memcmp (cert1bin.data, cert2bin.data, cert1bin.size) == 0))
    result = 0;
  else
    result = 1;

cleanup:
  _gnutls_free_datum (&cert1bin);
  _gnutls_free_datum (&cert2bin);
  return result;
}

/* Checks if the issuer of a certificate is a
 * Certificate Authority, or if the certificate is the same
 * as the issuer (and therefore it doesn't need to be a CA).
 *
 * Returns true or false, if the issuer is a CA,
 * or not.
 */
static int
check_if_ca (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
             unsigned int flags)
{
  gnutls_datum_t cert_signed_data = { NULL, 0 };
  gnutls_datum_t issuer_signed_data = { NULL, 0 };
  gnutls_datum_t cert_signature = { NULL, 0 };
  gnutls_datum_t issuer_signature = { NULL, 0 };
  int result;

  /* Check if the issuer is the same with the
   * certificate. This is added in order for trusted
   * certificates to be able to verify themselves.
   */

  result =
    _gnutls_x509_get_signed_data (issuer->cert, "tbsCertificate",
                                  &issuer_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signed_data (cert->cert, "tbsCertificate",
                                  &cert_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signature (issuer->cert, "signature", &issuer_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signature (cert->cert, "signature", &cert_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* If the subject certificate is the same as the issuer
   * return true.
   */
  if (!(flags & GNUTLS_VERIFY_DO_NOT_ALLOW_SAME))
    if (cert_signed_data.size == issuer_signed_data.size)
      {
        if ((memcmp (cert_signed_data.data, issuer_signed_data.data,
                     cert_signed_data.size) == 0) &&
            (cert_signature.size == issuer_signature.size) &&
            (memcmp (cert_signature.data, issuer_signature.data,
                     cert_signature.size) == 0))
          {
            result = 1;
            goto cleanup;
          }
      }

  result = gnutls_x509_crt_get_ca_status (issuer, NULL);
  if (result == 1)
    {
      result = 1;
      goto cleanup;
    }
  /* Handle V1 CAs that do not have a basicConstraint, but accept
     these certs only if the appropriate flags are set. */
  else if ((result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) &&
           ((flags & GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT) ||
            (!(flags & GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT) &&
             (gnutls_x509_crt_check_issuer (issuer, issuer) == 1))))
    {
      gnutls_assert ();
      result = 1;
      goto cleanup;
    }
  else
    gnutls_assert ();

  result = 0;

cleanup:
  _gnutls_free_datum (&cert_signed_data);
  _gnutls_free_datum (&issuer_signed_data);
  _gnutls_free_datum (&cert_signature);
  _gnutls_free_datum (&issuer_signature);
  return result;
}


/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight (DER) compare of the issuer/subject fields in
 * the given certificates.
 *
 * Returns 1 if they match and (0) if they don't match. Otherwise
 * a negative error code is returned to indicate error.
 */
static int
is_issuer (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer_cert)
{
  gnutls_datum_t dn1 = { NULL, 0 }, dn2 =
  {
  NULL, 0};
  int ret;

  ret = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_get_raw_dn (issuer_cert, &dn2);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);

cleanup:
  _gnutls_free_datum (&dn1);
  _gnutls_free_datum (&dn2);
  return ret;

}

/* Checks if the DN of two certificates is the same.
 * Returns 1 if they match and (0) if they don't match. Otherwise
 * a negative error code is returned to indicate error.
 */
int
_gnutls_is_same_dn (gnutls_x509_crt_t cert1, gnutls_x509_crt_t cert2)
{
  gnutls_datum_t dn1 = { NULL, 0 }, dn2 =
  {
  NULL, 0};
  int ret;

  ret = gnutls_x509_crt_get_raw_dn (cert1, &dn1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_get_raw_dn (cert2, &dn2);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);

cleanup:
  _gnutls_free_datum (&dn1);
  _gnutls_free_datum (&dn2);
  return ret;
}

/* Finds an issuer of the certificate. If multiple issuers
 * are present, returns one that is activated and not expired.
 */
static inline gnutls_x509_crt_t
find_issuer (gnutls_x509_crt_t cert,
             const gnutls_x509_crt_t * trusted_cas, int tcas_size)
{
int i;
gnutls_x509_crt_t issuer = NULL;

  /* this is serial search. 
   */

  for (i = 0; i < tcas_size; i++)
    {
      if (is_issuer (cert, trusted_cas[i]) == 1)
        {
          if (issuer == NULL) 
            {
              issuer = trusted_cas[i];
            }
          else
            {
              time_t now = gnutls_time(0);

              if (now < gnutls_x509_crt_get_expiration_time(trusted_cas[i]) && 
                now >= gnutls_x509_crt_get_activation_time(trusted_cas[i]))
                {
                  issuer = trusted_cas[i];
                }
            }
        }
    }

  return issuer;
}

static unsigned int
check_time (gnutls_x509_crt_t crt, time_t now)
{
  int status = 0;
  time_t t;

  t = gnutls_x509_crt_get_activation_time (crt);
  if (t == (time_t) - 1 || now < t)
    {
      status |= GNUTLS_CERT_NOT_ACTIVATED;
      status |= GNUTLS_CERT_INVALID;
      return status;
    }

  t = gnutls_x509_crt_get_expiration_time (crt);
  if (t == (time_t) - 1 || now > t)
    {
      status |= GNUTLS_CERT_EXPIRED;
      status |= GNUTLS_CERT_INVALID;
      return status;
    }

  return 0;
}

/* 
 * Verifies the given certificate again a certificate list of
 * trusted CAs.
 *
 * Returns only 0 or 1. If 1 it means that the certificate 
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 *
 * Output will hold some extra information about the verification
 * procedure. Issuer will hold the actual issuer from the trusted list.
 */
static int
_gnutls_verify_certificate2 (gnutls_x509_crt_t cert,
                             const gnutls_x509_crt_t * trusted_cas,
                             int tcas_size, unsigned int flags,
                             unsigned int *output,
                             gnutls_x509_crt_t * _issuer,
                             time_t now,
                             gnutls_verify_output_function func)
{
  gnutls_datum_t cert_signed_data = { NULL, 0 };
  gnutls_datum_t cert_signature = { NULL, 0 };
  gnutls_x509_crt_t issuer = NULL;
  int issuer_version, result, hash_algo;
  unsigned int out = 0;

  if (output)
    *output = 0;

  if (tcas_size >= 1)
    issuer = find_issuer (cert, trusted_cas, tcas_size);
  else
    {
      gnutls_assert ();
      out = GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      if (output)
        *output |= out;
      result = 0;
      goto cleanup;
    }

  /* issuer is not in trusted certificate
   * authorities.
   */
  if (issuer == NULL)
    {
      out = GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      if (output)
        *output |= out;
      gnutls_assert ();
      result = 0;
      goto cleanup;
    }

  if (_issuer != NULL)
    *_issuer = issuer;

  issuer_version = gnutls_x509_crt_get_version (issuer);
  if (issuer_version < 0)
    {
      gnutls_assert ();
      return issuer_version;
    }

  if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN) &&
      ((flags & GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT)
       || issuer_version != 1))
    {
      if (check_if_ca (cert, issuer, flags) == 0)
        {
          gnutls_assert ();
          out = GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID;
          if (output)
            *output |= out;
          result = 0;
          goto cleanup;
        }
    }

  result =
    _gnutls_x509_get_signed_data (cert->cert, "tbsCertificate",
                                  &cert_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signature (cert->cert, "signature", &cert_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signature_algorithm(cert->cert, "signatureAlgorithm.algorithm");
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  hash_algo = _gnutls_sign_get_hash_algorithm(result);

  result =
    _gnutls_x509_verify_data (hash_algo, &cert_signed_data, &cert_signature,
                                   issuer);
  if (result == GNUTLS_E_PK_SIG_VERIFY_FAILED)
    {
      gnutls_assert ();
      out |= GNUTLS_CERT_INVALID;
      /* error. ignore it */
      if (output)
        *output |= out;
      result = 0;
    }
  else if (result < 0)
    {
      gnutls_assert();
      goto cleanup;
    }

  /* If the certificate is not self signed check if the algorithms
   * used are secure. If the certificate is self signed it doesn't
   * really matter.
   */
  if (is_issuer (cert, cert) == 0)
    {
      int sigalg;

      sigalg = gnutls_x509_crt_get_signature_algorithm (cert);

      if (((sigalg == GNUTLS_SIGN_RSA_MD2) &&
           !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2)) ||
          ((sigalg == GNUTLS_SIGN_RSA_MD5) &&
           !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)))
        {
          out = GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID;
          if (output)
            *output |= out;
          result = 0;
        }
    }

  /* Check activation/expiration times
   */
  if (!(flags & GNUTLS_VERIFY_DISABLE_TIME_CHECKS))
    {
      /* check the time of the issuer first */
      if (!(flags & GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS))
        {
          out |= check_time (issuer, now);
          if (out != 0)
            {
              result = 0;
              if (output) *output |= out;
            }
        }

      out |= check_time (cert, now);
      if (out != 0)
        {
          result = 0;
          if (output) *output |= out;
        }
    }

cleanup:
  if (result >= 0 && func) func(cert, issuer, NULL, out);
  _gnutls_free_datum (&cert_signed_data);
  _gnutls_free_datum (&cert_signature);

  return result;
}

/**
 * gnutls_x509_crt_check_issuer:
 * @cert: is the certificate to be checked
 * @issuer: is the certificate of a possible issuer
 *
 * This function will check if the given certificate was issued by the
 * given issuer.
 *
 * Returns: It will return true (1) if the given certificate is issued
 *   by the given issuer, and false (0) if not.  A negative error code is
 *   returned in case of an error.
 **/
int
gnutls_x509_crt_check_issuer (gnutls_x509_crt_t cert,
                              gnutls_x509_crt_t issuer)
{
  return is_issuer (cert, issuer);
}

/* Verify X.509 certificate chain.
 *
 * Note that the return value is an OR of GNUTLS_CERT_* elements.
 *
 * This function verifies a X.509 certificate list. The certificate
 * list should lead to a trusted certificate in order to be trusted.
 */
unsigned int
_gnutls_x509_verify_certificate (const gnutls_x509_crt_t * certificate_list,
                                 int clist_size,
                                 const gnutls_x509_crt_t * trusted_cas,
                                 int tcas_size,
                                 unsigned int flags, 
                                 gnutls_verify_output_function func)
{
  int i = 0, ret;
  unsigned int status = 0, output;
  time_t now = gnutls_time (0);
  gnutls_x509_crt_t issuer = NULL;

  if (clist_size > 1)
    {
      /* Check if the last certificate in the path is self signed.
       * In that case ignore it (a certificate is trusted only if it
       * leads to a trusted party by us, not the server's).
       *
       * This prevents from verifying self signed certificates against
       * themselves. This (although not bad) caused verification
       * failures on some root self signed certificates that use the
       * MD2 algorithm.
       */
      if (gnutls_x509_crt_check_issuer (certificate_list[clist_size - 1],
                                        certificate_list[clist_size - 1]) > 0)
        {
          clist_size--;
        }
    }

  /* We want to shorten the chain by removing the cert that matches
   * one of the certs we trust and all the certs after that i.e. if
   * cert chain is A signed-by B signed-by C signed-by D (signed-by
   * self-signed E but already removed above), and we trust B, remove
   * B, C and D. */
  if (!(flags & GNUTLS_VERIFY_DO_NOT_ALLOW_SAME))
    i = 0;                      /* also replace the first one */
  else
    i = 1;                      /* do not replace the first one */

  for (; i < clist_size; i++)
    {
      int j;

      for (j = 0; j < tcas_size; j++)
        {
          if (check_if_same_cert (certificate_list[i], trusted_cas[j]) == 0)
            {
              /* explicity time check for trusted CA that we remove from
               * list. GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS
               */
              if (!(flags & GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS)
                  && !(flags & GNUTLS_VERIFY_DISABLE_TIME_CHECKS))
                {
                  status |= check_time (trusted_cas[j], now);
                  if (status != 0)
                    {
                      if (func) func(certificate_list[i], trusted_cas[j], NULL, status);
                      return status;
                    }
                }

              if (func) func(certificate_list[i], trusted_cas[j], NULL, status);
              clist_size = i;
              break;
            }
        }
      /* clist_size may have been changed which gets out of loop */
    }

  if (clist_size == 0)
    {
      /* The certificate is already present in the trusted certificate list.
       * Nothing to verify. */
      return status;
    }

  /* Verify the last certificate in the certificate path
   * against the trusted CA certificate list.
   *
   * If no CAs are present returns CERT_INVALID. Thus works
   * in self signed etc certificates.
   */
  output = 0;
  ret = _gnutls_verify_certificate2 (certificate_list[clist_size - 1],
                                     trusted_cas, tcas_size, flags, &output,
                                     &issuer, now, func);
  if (ret == 0)
    {
      /* if the last certificate in the certificate
       * list is invalid, then the certificate is not
       * trusted.
       */
      gnutls_assert ();
      status |= output;
      status |= GNUTLS_CERT_INVALID;
      return status;
    }

  /* Verify the certificate path (chain)
   */
  for (i = clist_size - 1; i > 0; i--)
    {
      output = 0;
      if (i - 1 < 0)
        break;

      /* note that here we disable this V1 CA flag. So that no version 1
       * certificates can exist in a supplied chain.
       */
      if (!(flags & GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT))
        flags &= ~(GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);
      if ((ret =
           _gnutls_verify_certificate2 (certificate_list[i - 1],
                                        &certificate_list[i], 1, flags,
                                        &output, NULL, now, func)) == 0)
        {
          status |= output;
          status |= GNUTLS_CERT_INVALID;
          return status;
        }
    }

  return 0;
}

/* This will return the appropriate hash to verify the given signature.
 * If signature is NULL it will return an (or the) appropriate hash for
 * the given parameters.
 */
int
_gnutls_x509_verify_algorithm (gnutls_mac_algorithm_t * hash,
                               const gnutls_datum_t * signature,
                               gnutls_pk_algorithm_t pk,
                               gnutls_pk_params_st * issuer_params)
{
  opaque digest[MAX_HASH_SIZE];
  gnutls_datum_t decrypted;
  int digest_size;
  int ret;

  switch (pk)
    {
    case GNUTLS_PK_DSA:
    case GNUTLS_PK_ECC:

      if (hash)
        *hash = _gnutls_dsa_q_to_hash (pk, issuer_params, NULL);

      ret = 0;
      break;
    case GNUTLS_PK_RSA:
      if (signature == NULL)
        {                       /* return a sensible algorithm */
          if (hash)
            *hash = GNUTLS_DIG_SHA256;
          return 0;
        }

      ret =
        _gnutls_pkcs1_rsa_decrypt (&decrypted, signature,
                                   issuer_params, 1);


      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }

      digest_size = sizeof (digest);
      if ((ret =
           decode_ber_digest_info (&decrypted, hash, digest,
                                   &digest_size)) != 0)
        {
          gnutls_assert ();
          _gnutls_free_datum (&decrypted);
          goto cleanup;
        }

      _gnutls_free_datum (&decrypted);
      if (digest_size != _gnutls_hash_get_algo_len (*hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_ASN1_GENERIC_ERROR;
          goto cleanup;
        }

      ret = 0;
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
    }

cleanup:

  return ret;

}

/* verifies if the certificate is properly signed.
 * returns GNUTLS_E_PK_VERIFY_SIG_FAILED on failure and 1 on success.
 * 
 * 'data' is the signed data
 * 'signature' is the signature!
 */
int
_gnutls_x509_verify_data (gnutls_digest_algorithm_t algo,
                          const gnutls_datum_t * data,
                          const gnutls_datum_t * signature,
                          gnutls_x509_crt_t issuer)
{
  gnutls_pk_params_st issuer_params;
  int ret;

  /* Read the MPI parameters from the issuer's certificate.
   */
  ret =
    _gnutls_x509_crt_get_mpis (issuer, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    pubkey_verify_data (gnutls_x509_crt_get_pk_algorithm (issuer, NULL), algo,
                        data, signature, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  /* release all allocated MPIs
   */
  gnutls_pk_params_release(&issuer_params);

  return ret;
}

int
_gnutls_x509_verify_hashed_data (const gnutls_datum_t * hash,
                                 const gnutls_datum_t * signature,
                                 gnutls_x509_crt_t issuer)
{
  gnutls_pk_params_st issuer_params;
  int ret;

  /* Read the MPI parameters from the issuer's certificate.
   */
  ret =
    _gnutls_x509_crt_get_mpis (issuer, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    pubkey_verify_hashed_data (gnutls_x509_crt_get_pk_algorithm (issuer, NULL),
                               hash, signature, &issuer_params);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  /* release all allocated MPIs
   */
  gnutls_pk_params_release(&issuer_params);

  return ret;
}

/**
 * gnutls_x509_crt_list_verify:
 * @cert_list: is the certificate list to be verified
 * @cert_list_length: holds the number of certificate in cert_list
 * @CA_list: is the CA list which will be used in verification
 * @CA_list_length: holds the number of CA certificate in CA_list
 * @CRL_list: holds a list of CRLs.
 * @CRL_list_length: the length of CRL list.
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 *
 * This function will try to verify the given certificate list and
 * return its status.  If no flags are specified (0), this function
 * will use the basicConstraints (2.5.29.19) PKIX extension. This
 * means that only a certificate authority is allowed to sign a
 * certificate.
 *
 * You must also check the peer's name in order to check if the verified
 * certificate belongs to the actual peer.
 *
 * The certificate verification output will be put in @verify and will
 * be one or more of the gnutls_certificate_status_t enumerated
 * elements bitwise or'd.  For a more detailed verification status use
 * gnutls_x509_crt_verify() per list element.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_list_verify (const gnutls_x509_crt_t * cert_list,
                             int cert_list_length,
                             const gnutls_x509_crt_t * CA_list,
                             int CA_list_length,
                             const gnutls_x509_crl_t * CRL_list,
                             int CRL_list_length, unsigned int flags,
                             unsigned int *verify)
{
int i, ret;

  if (cert_list == NULL || cert_list_length == 0)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;

  /* Verify certificate 
   */
  *verify =
    _gnutls_x509_verify_certificate (cert_list, cert_list_length,
                                     CA_list, CA_list_length, 
                                     flags, NULL);

  /* Check for revoked certificates in the chain. 
   */
#ifdef ENABLE_PKI
  for (i = 0; i < cert_list_length; i++)
    {
      ret = gnutls_x509_crt_check_revocation (cert_list[i],
                                              CRL_list, CRL_list_length);
      if (ret == 1)
        {                       /* revoked */
          *verify |= GNUTLS_CERT_REVOKED;
          *verify |= GNUTLS_CERT_INVALID;
        }
    }
#endif

  return 0;
}

/**
 * gnutls_x509_crt_verify:
 * @cert: is the certificate to be verified
 * @CA_list: is one certificate that is considered to be trusted one
 * @CA_list_length: holds the number of CA certificate in CA_list
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 *
 * This function will try to verify the given certificate and return
 * its status.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_verify (gnutls_x509_crt_t cert,
                        const gnutls_x509_crt_t * CA_list,
                        int CA_list_length, unsigned int flags,
                        unsigned int *verify)
{
  /* Verify certificate 
   */
  *verify =
    _gnutls_x509_verify_certificate (&cert, 1,
                                     CA_list, CA_list_length, 
                                     flags, NULL);
  return 0;
}



#ifdef ENABLE_PKI

/**
 * gnutls_x509_crl_check_issuer:
 * @crl: is the CRL to be checked
 * @issuer: is the certificate of a possible issuer
 *
 * This function will check if the given CRL was issued by the given
 * issuer certificate.  It will return true (1) if the given CRL was
 * issued by the given issuer, and false (0) if not.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crl_check_issuer (gnutls_x509_crl_t crl,
                              gnutls_x509_crt_t issuer)
{
  return is_crl_issuer (crl, issuer);
}

/**
 * gnutls_x509_crl_verify:
 * @crl: is the crl to be verified
 * @CA_list: is a certificate list that is considered to be trusted one
 * @CA_list_length: holds the number of CA certificates in CA_list
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the crl verification output.
 *
 * This function will try to verify the given crl and return its status.
 * See gnutls_x509_crt_list_verify() for a detailed description of
 * return values.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crl_verify (gnutls_x509_crl_t crl,
                        const gnutls_x509_crt_t * CA_list,
                        int CA_list_length, unsigned int flags,
                        unsigned int *verify)
{
  int ret;
  /* Verify crl 
   */
  ret = _gnutls_verify_crl2 (crl, CA_list, CA_list_length, flags, verify);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}


/* The same as above, but here we've got a CRL.
 */
static int
is_crl_issuer (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer_cert)
{
  gnutls_datum_t dn1 = { NULL, 0 }, dn2 =
  {
  NULL, 0};
  int ret;

  ret = gnutls_x509_crl_get_raw_issuer_dn (crl, &dn1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_get_raw_dn (issuer_cert, &dn2);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);

cleanup:
  _gnutls_free_datum (&dn1);
  _gnutls_free_datum (&dn2);

  return ret;
}

static inline gnutls_x509_crt_t
find_crl_issuer (gnutls_x509_crl_t crl,
                 const gnutls_x509_crt_t * trusted_cas, int tcas_size)
{
  int i;

  /* this is serial search. 
   */

  for (i = 0; i < tcas_size; i++)
    {
      if (is_crl_issuer (crl, trusted_cas[i]) == 1)
        return trusted_cas[i];
    }

  gnutls_assert ();
  return NULL;
}

/* 
 * Returns only 0 or 1. If 1 it means that the CRL
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 *
 * Output will hold information about the verification
 * procedure. 
 */
static int
_gnutls_verify_crl2 (gnutls_x509_crl_t crl,
                     const gnutls_x509_crt_t * trusted_cas,
                     int tcas_size, unsigned int flags, unsigned int *output)
{
/* CRL is ignored for now */
  gnutls_datum_t crl_signed_data = { NULL, 0 };
  gnutls_datum_t crl_signature = { NULL, 0 };
  gnutls_x509_crt_t issuer;
  int result, hash_algo;

  if (output)
    *output = 0;

  if (tcas_size >= 1)
    issuer = find_crl_issuer (crl, trusted_cas, tcas_size);
  else
    {
      gnutls_assert ();
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      return 0;
    }

  /* issuer is not in trusted certificate
   * authorities.
   */
  if (issuer == NULL)
    {
      gnutls_assert ();
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      return 0;
    }

  if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN))
    {
      if (gnutls_x509_crt_get_ca_status (issuer, NULL) != 1)
        {
          gnutls_assert ();
          if (output)
            *output |= GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID;
          return 0;
        }
    }

  result =
    _gnutls_x509_get_signed_data (crl->crl, "tbsCertList", &crl_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signature (crl->crl, "signature", &crl_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signature_algorithm(crl->crl, "signatureAlgorithm.algorithm");
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  hash_algo = _gnutls_sign_get_hash_algorithm(result);

  result =
    _gnutls_x509_verify_data (hash_algo, &crl_signed_data, &crl_signature,
                                   issuer);
  if (result == GNUTLS_E_PK_SIG_VERIFY_FAILED)
    {
      gnutls_assert ();
      /* error. ignore it */
      if (output)
        *output |= GNUTLS_CERT_INVALID;
      result = 0;
    }
  else if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  {
    int sigalg;

    sigalg = gnutls_x509_crl_get_signature_algorithm (crl);

    if (((sigalg == GNUTLS_SIGN_RSA_MD2) &&
         !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2)) ||
        ((sigalg == GNUTLS_SIGN_RSA_MD5) &&
         !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)))
      {
        if (output)
          *output |= GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID;
        result = 0;
      }
  }

cleanup:
  _gnutls_free_datum (&crl_signed_data);
  _gnutls_free_datum (&crl_signature);

  return result;
}

#endif
