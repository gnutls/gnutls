/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
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

#define MAX_BUF 4*1024
#define HEADER_PATTERN "POST / HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "Accept: */*\r\n" \
  "Content-Type: application/ocsp-request\r\n" \
  "Content-Length: %u\r\n" \
  "Connection: close\r\n\r\n"
static char buffer[MAX_BUF + 1];

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

void
_generate_request (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
                   gnutls_datum_t * rdata, int nonce)
{
  gnutls_ocsp_req_t req;
  int ret;

  ret = gnutls_ocsp_req_init (&req);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_req_init: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_req_add_cert (req, GNUTLS_DIG_SHA1,
  				      issuer, cert);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_req_add_cert: %s", gnutls_strerror (ret));
    
  if (nonce)
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

  ret = gnutls_ocsp_req_export (req, rdata);
  if (ret != 0)
    error (EXIT_FAILURE, 0, "ocsp_req_export: %s", gnutls_strerror (ret));

  gnutls_ocsp_req_deinit (req);
  return;
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

/* Returns 0 on ok, and -1 on error */
int send_ocsp_request(const char* server,
                       gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
                       gnutls_datum_t * resp_data, int nonce)
{
gnutls_datum_t ud;
int ret;
gnutls_datum_t req;
char* url = (void*)server;
char headers[1024];
char service[16];
unsigned char * p;
const char *hostname;
unsigned int headers_size = 0, port;
socket_st hd;

  sockets_init ();

  if (url == NULL)
    {
      /* try to read URL from issuer certificate */
      gnutls_datum_t data;
      
      ret = gnutls_x509_crt_get_authority_info_access(cert, 0, 
                                  GNUTLS_IA_OCSP_URI, &data, NULL);
      
      if (ret < 0)
        ret = gnutls_x509_crt_get_authority_info_access(issuer, 0, 
                                    GNUTLS_IA_OCSP_URI, &data, NULL);
      if (ret < 0)
        {
          fprintf(stderr, "Cannot find URL from issuer: %s\n", gnutls_strerror(ret));
          return -1;
        }
      
      url = malloc(data.size+1);
      memcpy(url, data.data, data.size);
      url[data.size] = 0;
      
      gnutls_free(data.data);
    }
    
  hostname = host_from_url(url, &port);
  if (port != 0)
    snprintf(service, sizeof(service), "%u", port);
  else strcpy(service, "80");
  
  fprintf(stderr, "Connecting to OCSP server: %s...\n", hostname);

  memset(&ud, 0, sizeof(ud));

  _generate_request(cert, issuer, &req, nonce);

  snprintf(headers, sizeof(headers), HEADER_PATTERN, hostname, (unsigned int)req.size);
  headers_size = strlen(headers);
  
  socket_open(&hd, hostname, service, 0);
  
  socket_send(&hd, headers, headers_size);
  socket_send(&hd, req.data, req.size);
  
  do {
    ret = socket_recv(&hd, buffer, sizeof(buffer));
    if (ret > 0) get_data(buffer, ret, 1, &ud);
  } while(ret > 0);
  
  if (ret < 0 || ud.size == 0)
    {
      perror("recv");
      return -1;
    }
  
  socket_bye(&hd);
  
  p = memmem(ud.data, ud.size, "\r\n\r\n", 4);
  if (p == NULL)
    {
      fprintf(stderr, "Cannot interpret HTTP response\n");
      return -1;
    }
  
  p += 4;
  resp_data->size = ud.size - (p - ud.data);
  resp_data->data = malloc(resp_data->size);
  if (resp_data->data == NULL)
    return -1;
  
  memcpy(resp_data->data, p, resp_data->size);

  free(ud.data);
  
  return 0;
}

void
print_ocsp_verify_res (unsigned int output)
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

/* three days */
#define OCSP_VALIDITY_SECS (3*60*60*24)

/* Returns:
 *  0: certificate is revoked
 *  1: certificate is ok
 *  -1: dunno
 */
int
check_ocsp_response (gnutls_x509_crt_t cert,
                     gnutls_x509_crt_t issuer,
                     gnutls_datum_t *data)
{
  gnutls_ocsp_resp_t resp;
  int ret;
  unsigned int status, cert_status;
  time_t rtime, vtime, ntime, now;
  
  now = time(0);

  ret = gnutls_ocsp_resp_init (&resp);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "ocsp_resp_init: %s", gnutls_strerror (ret));

  ret = gnutls_ocsp_resp_import (resp, data);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "importing response: %s", gnutls_strerror (ret));
  
  ret = gnutls_ocsp_resp_check_crt(resp, 0, cert);
  if (ret < 0)
    {
      printf ("*** Got OCSP response on an unrelated certificate (ignoring)\n");
      ret = -1;
      goto cleanup;
    }

  ret = gnutls_ocsp_resp_verify_direct( resp, issuer, &status, 0);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_ocsp_resp_verify_direct: %s",
      gnutls_strerror (ret));

  if (status != 0)
    {
      printf ("*** Verifying OCSP Response: ");
      print_ocsp_verify_res (status);
      printf (".\n");
    }

  /* do not print revocation data if response was not verified */
  if (status != 0)
    {
      ret = -1;
      goto cleanup;
    }

  ret = gnutls_ocsp_resp_get_single(resp, 0, NULL, NULL, NULL, NULL,
        &cert_status, &vtime, &ntime, &rtime, NULL);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "reading response: %s", gnutls_strerror (ret));
  
  if (cert_status == GNUTLS_OCSP_CERT_REVOKED)
    {
      printf("*** Certificate was revoked at %s", ctime(&rtime));
      ret = 0;
      goto cleanup;
    }
  
  if (ntime == -1)
    {
      if (now - vtime > OCSP_VALIDITY_SECS)
        {
          printf("*** The OCSP response is old (was issued at: %s) ignoring", ctime(&vtime));
          ret = -1;
          goto cleanup;
        }
    }
  else
    {
      /* there is a newer OCSP answer, don't trust this one */
      if (ntime < now)
        {
          printf("*** The OCSP response was issued at: %s, but there is a newer issue at %s", ctime(&vtime), ctime(&ntime));
          ret = -1;
          goto cleanup;
        }
    }
  
  printf("- OCSP server flags certificate not revoked as of %s", ctime(&vtime));
  ret = 1;
cleanup:
  gnutls_ocsp_resp_deinit (resp);
  
  return ret;
}

