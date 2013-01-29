/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/xssl.h>
#include "examples.h"

/* A simple TLS client, with X.509 authentication. Certificate verification
 * is explicit.
 */

extern int tcp_connect (void);
extern void tcp_close (int sd);

int main (void)
{
  int ret;
  char *line = NULL;
  size_t line_len;
  xssl_cred_t cred;
  xssl_t sb;
  unsigned int status;
  int fd;

  gnutls_global_init ();
  
  fd = tcp_connect ();

  ret = xssl_cred_init(&cred, GNUTLS_VMETHOD_SYSTEM_CAS, NULL, 0);
  if (ret < 0)
    exit(1);

  /* Initialize TLS session
   */
  ret = xssl_client_init(&sb, "www.example.com", NULL, 
                         (gnutls_transport_ptr_t)fd,
			 NULL, cred, &status, 0);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_AUTH_ERROR)
        {
          gnutls_datum_t txt;
          
          gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509,
            &txt, 0);
          
          fprintf(stderr, "Verification error (%x): %s\n", status, txt.data);
          gnutls_free(txt.data);
        }
      exit(1);
    }

#define REQ "GET / HTTP/1.0\r\n"
  ret = xssl_write(sb, REQ, sizeof(REQ)-1);
  if (ret < 0)
    exit(1);

  do
    {
      ret = xssl_getline(sb, &line, &line_len);
      if (ret < 0)
        exit(1);
      
      fprintf(stderr, "received: %s\n", line);
    }
  while (ret >= 0);

  gnutls_free(line);

  xssl_deinit(sb);

  tcp_close (fd);

  xssl_cred_deinit (cred);

  gnutls_global_deinit ();
}


