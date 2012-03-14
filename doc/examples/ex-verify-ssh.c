/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "examples.h"

/* This function will verify the peer's certificate, check
 * if the hostname matches. In addition it will perform an
 * SSH-style authentication, where ultimately trusted keys
 * are only the keys that have been seen before.
 */
int
_ssh_verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  int ret;
  gnutls_x509_crt_t cert;
  const char *hostname;

  /* read hostname */
  hostname = gnutls_session_get_ptr (session);

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers2 (session, &status);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (status & GNUTLS_CERT_INVALID)
    printf ("The certificate is not trusted.\n");

  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    printf ("The certificate hasn't got a known issuer.\n");

  if (status & GNUTLS_CERT_REVOKED)
    printf ("The certificate has been revoked.\n");

  if (status & GNUTLS_CERT_EXPIRED)
    printf ("The certificate has expired\n");

  if (status & GNUTLS_CERT_NOT_ACTIVATED)
    printf ("The certificate is not yet activated\n");

  /* Up to here the process is the same for X.509 certificates and
   * OpenPGP keys. From now on X.509 certificates are assumed. This can
   * be easily extended to work with openpgp keys as well.
   */
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_x509_crt_init (&cert) < 0)
    {
      printf ("error in initialization\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list == NULL)
    {
      printf ("No certificate was found!\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  /* This is not a real world example, since we only check the first 
   * certificate in the given chain.
   */
  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
    {
      printf ("error parsing certificate\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (!gnutls_x509_crt_check_hostname (cert, hostname))
    {
      printf ("The certificate's owner does not match hostname '%s'\n",
              hostname);
      status |= GNUTLS_CERT_INVALID;
    }

  gnutls_x509_crt_deinit (cert);
  
  /* service may be obtained alternatively using getservbyport() */
  ret = gnutls_verify_stored_pubkey(NULL, NULL, hostname, "https", 
                                    GNUTLS_CRT_X509, &cert_list[0], 0);
  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND)
    {
      printf("Host %s is not known.", hostname);
      if (status == 0)
        printf("Its certificate is valid for %s.\n", hostname);
      
      /* the certificate must be printed and user must be asked on
       * whether it is trustworthy. --see gnutls_x509_crt_print() */
      
      /* if not trusted */
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  else if (ret == GNUTLS_E_CERTIFICATE_KEY_MISMATCH)
    {
      printf("Warning: host %s is known but has another key associated.", hostname);
      printf("It might be that the server has multiple keys, or you are under attack\n");
      if (status == 0)
        printf("Its certificate is valid for %s.\n", hostname);
      
      /* the certificate must be printed and user must be asked on
       * whether it is trustworthy. --see gnutls_x509_crt_print() */
      
      /* if not trusted */
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  else if (ret < 0)
    {
      printf("gnutls_verify_stored_pubkey: %s\n", gnutls_strerror(ret));
      return ret;
    }
  
  /* user trusts the key -> store it */
  if (ret != 0)
    {
      ret = gnutls_store_pubkey(NULL, NULL, hostname, "https", 
                                GNUTLS_CRT_X509, &cert_list[0], 
                                0, 0);
      if (ret < 0)
        printf("gnutls_store_pubkey: %s\n", gnutls_strerror(ret));
    }

  /* notify gnutls to continue handshake normally */
  return 0;
}

