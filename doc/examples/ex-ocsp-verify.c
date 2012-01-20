/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

#include "read-file.h"

/* This program will read a file (argv[1]) containing an OCSP response
   and another file (argv[2]) containing a set of OCSP trust anchors.
   The tool will try to verify the OCSP response against the set of
   trust anchors.  It will also parse the OCSP response and check that
   the X.509 certificate is still valid, or print why it is not valid
   (according to the OCSP response).  */

int
main (int argc, char *argv[])
{
  int rc;
  gnutls_datum_t tmp;
  gnutls_ocsp_resp_t ocspresp = NULL;
  gnutls_x509_trust_list_t trustlist = NULL;
  gnutls_x509_crt_t *trustcerts = NULL;
  unsigned int ntrustcerts = 0;
  unsigned verify, i;
  size_t s;

  rc = gnutls_global_init ();
  if (rc < 0)
    goto done;

  /* Read OCSP response and print it. */

  rc = gnutls_ocsp_resp_init (&ocspresp);
  if (rc < 0)
    goto done;

  tmp.data = read_binary_file (argv[1], &s);
  if (tmp.data == NULL)
    {
      printf ("cannot read OCSP response\n");
      goto done;
    }
  tmp.size = s;

  rc = gnutls_ocsp_resp_import (ocspresp, &tmp);
  free (tmp.data);
  if (rc < 0)
    goto done;

  rc = gnutls_ocsp_resp_print (ocspresp, GNUTLS_OCSP_PRINT_FULL, &tmp);
  if (rc < 0)
    goto done;

  printf ("ocsp response: %.*s\n", tmp.size, tmp.data);

  gnutls_free (tmp.data);

  if (argc < 3)
    {
      printf ("Done...\n");
      goto done;
    }

  /* Read X.509 trustlist. */

  rc = gnutls_x509_trust_list_init (&trustlist, 0);
  if (rc < 0)
    goto done;

  tmp.data = read_binary_file (argv[2], &s);
  if (tmp.data == NULL)
    {
      printf ("cannot read OCSP response\n");
      goto done;
    }
  tmp.size = s;

  rc = gnutls_x509_crt_list_import2 (&trustcerts, &ntrustcerts, &tmp,
				     GNUTLS_X509_FMT_PEM, 0);
  free (tmp.data);
  if (rc < 0)
    goto done;

  for (i = 0; i < ntrustcerts; i++)
    {
      gnutls_datum_t out;

      rc = gnutls_x509_crt_print (trustcerts[i],
				  GNUTLS_CRT_PRINT_ONELINE, &out);
      if (rc < 0)
	goto done;

      printf ("Trust anchor %d: %.*s\n", i, out.size, out.data);
      gnutls_free (out.data);
    }

  rc = gnutls_x509_trust_list_add_cas (trustlist, trustcerts, ntrustcerts, 0);
  gnutls_free (trustcerts);
  if (rc < 0)
    goto done;

  printf ("Loaded %d trust anchors\n", ntrustcerts);

  /* Verify it */

  rc = gnutls_ocsp_resp_verify (ocspresp, trustlist, &verify, 0);
  if (rc < 0)
    goto done;

  if (verify == 0)
    printf ("Verification success!\n");
  else
    printf ("Verification error!\n");

  if (verify & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
    printf ("Signer cert not found\n");

  if (verify & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
    printf ("Signer cert keyusage error\n");

  if (verify & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
    printf ("Signer cert is not trusted\n");

  if (verify & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
    printf ("Insecure algorithm\n");

  if (verify & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
    printf ("Signature failure\n");

  if (verify & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
    printf ("Signer cert not yet activated\n");

  if (verify & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
    printf ("Signer cert expired\n");

  rc = 0;

 done:
  if (rc != 0)
    printf ("error (%d): %s\n", rc, gnutls_strerror (rc));
  gnutls_x509_trust_list_deinit (trustlist, 1);
  gnutls_ocsp_resp_deinit (ocspresp);
  gnutls_global_deinit ();

  return rc == 0 ? 0 : 1;
}
