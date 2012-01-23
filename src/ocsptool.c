/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

/* Gnulib portability files. */
#include <error.h>
#include <progname.h>
#include <version-etc.h>
#include <read-file.h>

#include <ocsptool-common.h>
#include <ocsptool-args.h>

FILE *outfile;
FILE *infile;
static unsigned int encoding;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

static void
request_info (void)
{
  gnutls_ocsp_req_t req;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  ret = gnutls_ocsp_req_init (&req);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_req_init: %s", gnutls_strerror (ret));

  if (HAVE_OPT(LOAD_REQUEST))
    dat.data = (void*)read_binary_file (OPT_ARG(LOAD_REQUEST), &size);
  else
    dat.data = (void*)fread_file (infile, &size);
  if (dat.data == NULL)
    error (EXIT_FAILURE, errno, "reading request");
  dat.size = size;

  ret = gnutls_ocsp_req_import (req, &dat);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing request: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_req_print (req, GNUTLS_OCSP_PRINT_FULL, &dat);
  if (ret != 0)
    error (EXIT_FAILURE, 0, "ocsp_req_print: %s", gnutls_strerror (ret));

  printf ("%.*s", dat.size, dat.data);
  gnutls_free (dat.data);

  gnutls_ocsp_req_deinit (req);
}

static void
response_info (void)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_init: %s", gnutls_strerror (ret));

  if (HAVE_OPT(LOAD_RESPONSE))
    dat.data = (void*)read_binary_file (OPT_ARG(LOAD_RESPONSE), &size);
  else
    dat.data = (void*)fread_file (infile, &size);
  if (dat.data == NULL)
    error (EXIT_FAILURE, errno, "reading response");
  dat.size = size;

  ret = gnutls_ocsp_resp_import (resp, &dat);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing response: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_resp_print (resp, GNUTLS_OCSP_PRINT_FULL, &dat);
  if (ret != 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_print: %s", gnutls_strerror (ret));

  printf ("%.*s", dat.size, dat.data);
  gnutls_free (dat.data);

  gnutls_ocsp_resp_deinit (resp);
}

static gnutls_x509_crt_t
load_issuer (void)
{
  gnutls_x509_crt_t crt;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (!HAVE_OPT(LOAD_ISSUER))
    error (EXIT_FAILURE, 0, "missing --load-issuer");

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

  dat.data = (void*)read_binary_file (OPT_ARG(LOAD_ISSUER), &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-issuer: %s", OPT_ARG(LOAD_ISSUER));

  ret = gnutls_x509_crt_import (crt, &dat, encoding);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-issuer: %s: %s",
           OPT_ARG(LOAD_ISSUER), gnutls_strerror (ret));

  return crt;
}

static gnutls_x509_crt_t
load_cert (void)
{
  gnutls_x509_crt_t crt;
  int ret;
  gnutls_datum_t dat;
  size_t size;

  if (!HAVE_OPT(LOAD_CERT))
    error (EXIT_FAILURE, 0, "missing --load-cert");

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

  dat.data = (void*)read_binary_file (OPT_ARG(LOAD_CERT), &size);
  dat.size = size;

  if (!dat.data)
    error (EXIT_FAILURE, errno, "reading --load-cert: %s", OPT_ARG(LOAD_CERT));

  ret = gnutls_x509_crt_import (crt, &dat, encoding);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing --load-cert: %s: %s",
           OPT_ARG(LOAD_CERT), gnutls_strerror (ret));

  return crt;
}

static void
generate_request (void)
{
  gnutls_ocsp_req_t req;
  int ret;
  gnutls_datum_t dat;
  gnutls_x509_crt_t issuer, cert;

  ret = gnutls_ocsp_req_init (&req);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_req_init: %s", gnutls_strerror (ret));

  issuer = load_issuer ();
  cert = load_cert ();

  ret = gnutls_ocsp_req_add_cert (req, GNUTLS_DIG_SHA1,
				  issuer, cert);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_req_add_cert: %s", gnutls_strerror (ret));

  gnutls_x509_crt_deinit (cert);
  gnutls_x509_crt_deinit (issuer);

  if (ENABLED_OPT(NONCE))
    {
      unsigned char noncebuf[23];
      gnutls_datum_t nonce = { noncebuf, sizeof (noncebuf) };

      ret = gnutls_rnd (GNUTLS_RND_RANDOM, nonce.data, nonce.size);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_rnd: %s", gnutls_strerror (ret));

      ret = gnutls_ocsp_req_set_nonce (req, 0, &nonce);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "ocsp_req_set_nonce: %s",
	       gnutls_strerror (ret));
    }

  ret = gnutls_ocsp_req_export (req, &dat);
  if (ret != 0)
    error (EXIT_FAILURE, 0, "ocsp_req_export: %s", gnutls_strerror (ret));

  fwrite (dat.data, 1, dat.size, outfile);

  gnutls_free (dat.data);

  gnutls_ocsp_req_deinit (req);
}

static void
print_verify_res (unsigned int output)
{
  int comma = 0;

  if (output)
    {
      printf ("Failure");
      comma = 1;
    }
  else
    {
      printf ("Success");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
    {
      if (comma)
        printf (", ");
      printf ("Signer cert not found");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
    {
      if (comma)
        printf (", ");
      printf ("Signer cert keyusage error");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
    {
      if (comma)
        printf (", ");
      printf ("Signer cert is not trusted");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
    {
      if (comma)
        printf (", ");
      printf ("Insecure algorithm");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
    {
      if (comma)
        printf (", ");
      printf ("Signature failure");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
    {
      if (comma)
        printf (", ");
      printf ("Signer cert not yet activated");
      comma = 1;
    }

  if (output & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
    {
      if (comma)
        printf (", ");
      printf ("Signer cert expired");
      comma = 1;
    }
}

static void
verify_response (void)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  gnutls_datum_t dat;
  size_t size;
  gnutls_x509_crt_t *x509_ca_list = NULL;
  unsigned int x509_ncas = 0;
  gnutls_x509_trust_list_t list;
  gnutls_x509_crt_t signer;
  unsigned verify;

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_init: %s", gnutls_strerror (ret));

  if (HAVE_OPT(LOAD_RESPONSE))
    dat.data = (void*)read_binary_file (OPT_ARG(LOAD_RESPONSE), &size);
  else
    dat.data = (void*)fread_file (infile, &size);
  if (dat.data == NULL)
    error (EXIT_FAILURE, errno, "reading response");
  dat.size = size;

  ret = gnutls_ocsp_resp_import (resp, &dat);
  free (dat.data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing response: %s", gnutls_strerror (ret));

  if (!HAVE_OPT(LOAD_SIGNER) && HAVE_OPT(LOAD_TRUST))
    {
      dat.data = (void*)read_binary_file (OPT_ARG(LOAD_TRUST), &size);
      if (dat.data == NULL)
	error (EXIT_FAILURE, errno, "reading --load-trust: %s", OPT_ARG(LOAD_TRUST));
      dat.size = size;

      ret = gnutls_x509_trust_list_init (&list, 0);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_x509_trust_list_init: %s",
	       gnutls_strerror (ret));

      ret = gnutls_x509_crt_list_import2 (&x509_ca_list, &x509_ncas, &dat,
					  GNUTLS_X509_FMT_PEM, 0);
      if (ret < 0 || x509_ncas < 1)
	error (EXIT_FAILURE, 0, "error parsing CAs: %s",
	       gnutls_strerror (ret));

      if (HAVE_OPT(VERBOSE))
	{
	  unsigned int i;
	  for (i = 0; i < x509_ncas; i++)
	    {
	      gnutls_datum_t out;

	      ret = gnutls_x509_crt_print (x509_ca_list[i],
					   GNUTLS_CRT_PRINT_ONELINE, &out);
	      if (ret < 0)
		error (EXIT_FAILURE, 0, "gnutls_x509_crt_print: %s",
		       gnutls_strerror (ret));

	      printf ("Trust anchor %d: %.*s\n", i, out.size, out.data);
	      gnutls_free (out.data);
	    }
	}

      ret = gnutls_x509_trust_list_add_cas (list, x509_ca_list, x509_ncas, 0);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_x509_trust_add_cas: %s",
	       gnutls_strerror (ret));

      if (HAVE_OPT(VERBOSE))
	fprintf (stdout, "Loaded %d trust anchors\n", x509_ncas);

      ret = gnutls_ocsp_resp_verify (resp, list, &verify, 0);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_ocsp_resp_verify: %s",
	       gnutls_strerror (ret));
    }
  else if (!HAVE_OPT(LOAD_TRUST) && HAVE_OPT(LOAD_SIGNER))
    {
      ret = gnutls_x509_crt_init (&signer);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));

      dat.data = (void*)read_binary_file (OPT_ARG(LOAD_SIGNER), &size);
      if (dat.data == NULL)
	error (EXIT_FAILURE, errno, "reading --load-signer: %s", OPT_ARG(LOAD_SIGNER));
      dat.size = size;

      ret = gnutls_x509_crt_import (signer, &dat, encoding);
      free (dat.data);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "importing --load-signer: %s: %s",
	       OPT_ARG(LOAD_SIGNER), gnutls_strerror (ret));

      if (HAVE_OPT(VERBOSE))
	{
	  gnutls_datum_t out;

	  ret = gnutls_x509_crt_print (signer, GNUTLS_CRT_PRINT_ONELINE, &out);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "gnutls_x509_crt_print: %s",
		   gnutls_strerror (ret));

	  printf ("Signer: %.*s\n", out.size, out.data);
	  gnutls_free (out.data);
	}

      ret = gnutls_ocsp_resp_verify_direct (resp, signer, &verify, 0);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_ocsp_resp_verify_direct: %s",
	       gnutls_strerror (ret));
    }
  else
    error (EXIT_FAILURE, 0, "missing --load-trust or --load-signer");

  printf ("Verifying OCSP Response: ");
  print_verify_res (verify);
  printf (".\n");

  gnutls_ocsp_resp_deinit (resp);
}

int
main (int argc, char **argv)
{
  int ret;

  set_program_name (argv[0]);

  if ((ret = gnutls_global_init ()) < 0)
    error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));

  optionProcess( &ocsptoolOptions, argc, argv);

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (OPT_VALUE_DEBUG);

  if (HAVE_OPT(OUTFILE))
    {
      outfile = fopen (OPT_ARG(OUTFILE), "wb");
      if (outfile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(OUTFILE));
    }
  else
    outfile = stdout;

  if (HAVE_OPT(INFILE))
    {
      infile = fopen (OPT_ARG(INFILE), "rb");
      if (infile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(INFILE));
    }
  else
    infile = stdin;

  if (ENABLED_OPT(INDER))
    encoding = GNUTLS_X509_FMT_DER;
  else
    encoding = GNUTLS_X509_FMT_PEM;

  if (HAVE_OPT(REQUEST_INFO))
    request_info ();
  else if (HAVE_OPT(RESPONSE_INFO))
    response_info ();
  else if (HAVE_OPT(GENERATE_REQUEST))
    generate_request ();
  else if (HAVE_OPT(VERIFY_RESPONSE))
    verify_response ();
  else 
    {
      USAGE(1);
    }

  return 0;
}

