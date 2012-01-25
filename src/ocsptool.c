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
#include <socket.h>

#include <ocsptool-common.h>
#include <ocsptool-args.h>

FILE *outfile;
FILE *infile;
static unsigned int encoding;
unsigned int verbose = 0;

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
_response_info (const gnutls_datum_t* data)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  gnutls_datum buf;

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_init: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_resp_import (resp, data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing response: %s", gnutls_strerror (ret));

  if (ENABLED_OPT(VERBOSE))
    ret = gnutls_ocsp_resp_print (resp, GNUTLS_OCSP_PRINT_FULL, &buf);
  else
    ret = gnutls_ocsp_resp_print (resp, GNUTLS_OCSP_PRINT_COMPACT, &buf);
  if (ret != 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_print: %s", gnutls_strerror (ret));

  printf ("%.*s", buf.size, buf.data);
  gnutls_free (buf.data);

  gnutls_ocsp_resp_deinit (resp);
}

static void
response_info (void)
{
  gnutls_datum_t dat;
  size_t size;

  if (HAVE_OPT(LOAD_RESPONSE))
    dat.data = (void*)read_binary_file (OPT_ARG(LOAD_RESPONSE), &size);
  else
    dat.data = (void*)fread_file (infile, &size);
  if (dat.data == NULL)
    error (EXIT_FAILURE, errno, "reading response");
  dat.size = size;

  _response_info(&dat);
  gnutls_free (dat.data);
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
_generate_request (gnutls_datum_t * rdata)
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
    
  gnutls_x509_crt_deinit (issuer);
  gnutls_x509_crt_deinit (cert);

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

  gnutls_ocsp_req_deinit (req);

  memcpy(rdata, &dat, sizeof(*rdata));
  return;
}

static void
generate_request (void)
{
  gnutls_datum_t dat;
  
  _generate_request(&dat);

  fwrite (dat.data, 1, dat.size, outfile);

  gnutls_free (dat.data);
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

static int
_verify_response (gnutls_datum_t *data)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  size_t size;
  gnutls_x509_crt_t *x509_ca_list = NULL;
  unsigned int x509_ncas = 0;
  gnutls_x509_trust_list_t list;
  gnutls_x509_crt_t signer;
  unsigned verify;
  gnutls_datum_t dat;

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_init: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_resp_import (resp, data);
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
  
  return verify;
}

static void
verify_response (void)
{
  gnutls_datum_t dat;
  size_t size;

  if (HAVE_OPT(LOAD_RESPONSE))
    dat.data = (void*)read_binary_file (OPT_ARG(LOAD_RESPONSE), &size);
  else
    dat.data = (void*)fread_file (infile, &size);
  if (dat.data == NULL)
    error (EXIT_FAILURE, errno, "reading response");
  dat.size = size;
  
  _verify_response(&dat);
}

static size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
gnutls_datum_t *ud = userp;
  
  size *= nmemb;

  ud->data = realloc(ud->data, size+ud->size);
  if (ud->data == NULL)
    {
      fprintf(stderr, "Not enough memory for the request\n");
      exit(1);
    }

  memcpy(&ud->data[ud->size], buffer, size);
  ud->size += size;
  
  return size;
}

/* returns the host part of a URL */
static const char* host_from_url(const char* url, unsigned int* port)
{
static char hostname[512];
char * p;

  *port = 0;

  if ((p=strstr(url, "http://")) != NULL)
    {
      snprintf(hostname, sizeof(hostname), "%s", p+7);
      p = strchr(hostname, '/');
      if (p != NULL) *p = 0;

      p = strchr(hostname, ':');
      if (p != NULL) {
        *p = 0;
        *port = atoi(p+1);
      }
      
      return hostname;
    }
  else
    {
      return url;
    }
}

#define MAX_BUF 4*1024
#define HEADER_PATTERN "POST / HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "Accept: */*\r\n" \
  "Content-Type: application/ocsp-request\r\n" \
  "Content-Length: %u\r\n" \
  "Connection: close\r\n\r\n"
static char buffer[MAX_BUF + 1];

static void ask_server(const char* _url)
{
gnutls_datum_t ud, resp_data;
int ret, v;
gnutls_datum_t req;
char* url = (void*)_url;
char headers[1024];
char service[16];
const char *hostname;
unsigned int headers_size = 0, port;
socket_st hd;

  sockets_init ();

  if (url == NULL)
    {
      /* try to read URL from issuer certificate */
      gnutls_x509_crt_t issuer = load_issuer();
      gnutls_datum_t data;
      
      ret = gnutls_x509_crt_get_authority_info_access(issuer, 0, 
                                  GNUTLS_IA_OCSP_URI, &data, NULL);
      if (ret < 0)
        {
          fprintf(stderr, "Cannot find URL from issuer: %s\n", gnutls_strerror(ret));
          exit(1);  
        }
      
      url = malloc(data.size+1);
      memcpy(url, data.data, data.size);
      url[data.size] = 0;
      
      gnutls_free(data.data);
      
      gnutls_x509_crt_deinit(issuer);
    }
    
  hostname = host_from_url(url, &port);
  if (port != 0)
    snprintf(service, sizeof(service), "%u", port);
  else strcpy(service, "80");
  
  fprintf(stderr, "Connecting to %s\n", hostname);

  memset(&ud, 0, sizeof(ud));

  _generate_request(&req);

  snprintf(headers, sizeof(headers), HEADER_PATTERN, hostname, (unsigned int)req.size);
  headers_size = strlen(headers);
  
  socket_open(&hd, hostname, service, 0);
  socket_connect (&hd);
  
  socket_send(&hd, headers, headers_size);
  socket_send(&hd, req.data, req.size);
  
  do {
    ret = socket_recv(&hd, buffer, sizeof(buffer));
    if (ret > 0) get_data(buffer, ret, 1, &ud);
  } while(ret > 0);
  
  if (ret < 0 || ud.size == 0)
    {
      perror("recv");
      exit(1);
    }
  
  socket_bye(&hd);
  
  resp_data.data = memmem(ud.data, ud.size, "\r\n\r\n", 4);
  if (resp_data.data == NULL)
    {
      fprintf(stderr, "Cannot interpret HTTP response\n");
      exit(1);
    }
  
  resp_data.data += 4;
  resp_data.size = ud.size - (resp_data.data - ud.data);
  
  _response_info (&resp_data);

  if (HAVE_OPT(LOAD_SIGNER))
    {
      fprintf(outfile, "\n");
      v = _verify_response(&resp_data);
    }
  else
    {
      fprintf(stderr, "\nResponse could not be verified (use --load-signer).\n");
      v = 0;
    }
    
  if (HAVE_OPT(OUTFILE) && v == 0)
    {
      fwrite(resp_data.data, 1, resp_data.size, outfile);
    }
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
  else if (HAVE_OPT(ASK))
    ask_server(OPT_ARG(ASK));
  else 
    {
      USAGE(1);
    }

  return 0;
}

