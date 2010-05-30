/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Parts copied from GnuTLS example programs. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>

#include "utils.h"

#include "ex-session-info.c"
#include "ex-x509-info.c"
#include "tcp.c"

pid_t child;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "%s |<%d>| %s", child ? "server" : "client", level, str);
}

/* A very basic TLS client, with anonymous authentication.
 */

#define MAX_BUF 1024
#define MSG "Hello TLS"

static unsigned char cert_txt[] =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
  "Version: GnuPG v1.0.6 (GNU/Linux)\n"
  "Comment: For info see http://www.gnupg.org\n"
  "\n"
  "mQGiBDxnlY0RBACAsWUhi/goBvpvTBgL8fFPwBAuD04VYFEtC7+4pBp6kFsHjUR7\n"
  "TTUkBsOk2PvMHrDdv0+C4x2CH8YGP1e+O0f2yLWk8Uu+kkF12yiqbbvDEiCdeJT6\n"
  "c3vIstY8vJ9Jso5g/LB8Xggq88R7jXFS3hH+WC5v/6P6SARfzXl457cVewCgvxSf\n"
  "Gsm9mFospJ0B3RGyg5MB0d8D/RQQryJCGdR2nLe4VfctPL2QBD/1XhtubqEbetaV\n"
  "PxssqrJdA+eplBRT7UHokSBahM8gmSmNuSrLDujPfEtaMg6YIkB+Kq0VeJLE0cXT\n"
  "ZIH29KJlI/qk1xG4K7D6B0cKaHC/L4BIoKcQLJzfTIPw3frS4jVeNaQZNHSVqZ8/\n"
  "VmOMA/9rkNtccQ4RVd9WTFoHKvT4vfiISEOIzKGmcBY9Hymq7MCci3mNe4CDImkv\n"
  "ZgnjDlJAM91CX1ODthPLBqvyhnMhhxDnaDl4Nh42uPMSr9JEW2IwoIbFne10ihGT\n"
  "O4lBS1C28UfSGEMm/8JBMtxAjbYy3BYzUtCMA+bGBG6Voe5i5LQlRHIuIFdobyAo\n"
  "Tm8gY29tbWVudHMpIDx3aG9Ad2hvaXMub3JnPohdBBMRAgAdBQI8Z5WNBQkDwmcA\n"
  "BQsHCgMEAxUDAgMWAgECF4AACgkQNRRc6qfZPD+WWACfeJnLyfbpTDB7mDh3aATb\n"
  "+0PXz28AoKRdApBVM6Bty+vWyXH6HfF6ZTj+\n"
  "=m8dH\n" "-----END PGP PUBLIC KEY BLOCK-----\n";
const gnutls_datum_t cert = { cert_txt, sizeof (cert_txt) };

static unsigned char key_txt[] =
  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
  "Version: GnuPG v1.0.6 (GNU/Linux)\n"
  "Comment: For info see http://www.gnupg.org\n"
  "\n"
  "lQG7BDxnlY0RBACAsWUhi/goBvpvTBgL8fFPwBAuD04VYFEtC7+4pBp6kFsHjUR7\n"
  "TTUkBsOk2PvMHrDdv0+C4x2CH8YGP1e+O0f2yLWk8Uu+kkF12yiqbbvDEiCdeJT6\n"
  "c3vIstY8vJ9Jso5g/LB8Xggq88R7jXFS3hH+WC5v/6P6SARfzXl457cVewCgvxSf\n"
  "Gsm9mFospJ0B3RGyg5MB0d8D/RQQryJCGdR2nLe4VfctPL2QBD/1XhtubqEbetaV\n"
  "PxssqrJdA+eplBRT7UHokSBahM8gmSmNuSrLDujPfEtaMg6YIkB+Kq0VeJLE0cXT\n"
  "ZIH29KJlI/qk1xG4K7D6B0cKaHC/L4BIoKcQLJzfTIPw3frS4jVeNaQZNHSVqZ8/\n"
  "VmOMA/9rkNtccQ4RVd9WTFoHKvT4vfiISEOIzKGmcBY9Hymq7MCci3mNe4CDImkv\n"
  "ZgnjDlJAM91CX1ODthPLBqvyhnMhhxDnaDl4Nh42uPMSr9JEW2IwoIbFne10ihGT\n"
  "O4lBS1C28UfSGEMm/8JBMtxAjbYy3BYzUtCMA+bGBG6Voe5i5AAAnjMCLPrxGdgE\n"
  "I0xXdwCQ4Sh2diNECAj9JiM6RFNBX2ZhY3RvcjoAAK9cun7/j4AUMmdvIy5UMJph\n"
  "A6eq6atP/SYjOkRTQV9mYWN0b3I6AACvVjUuomodmmyCggPHWdeVSzpX3ODEHf0m\n"
  "IzpEU0FfZmFjdG9yOgAAr2Iv9H2aSH+vJKGYW/BO4ehQwwFck7u0JURyLiBXaG8g\n"
  "KE5vIGNvbW1lbnRzKSA8d2hvQHdob2lzLm9yZz6IXQQTEQIAHQUCPGeVjQUJA8Jn\n"
  "AAULBwoDBAMVAwIDFgIBAheAAAoJEDUUXOqn2Tw/llgAnjBPQdWxIqBCQGlcI2K/\n"
  "gLkZR1ARAJ9kaAeJYERc0bV/vlm0ot7UDdr+bQ==\n"
  "=4M0W\n" "-----END PGP PRIVATE KEY BLOCK-----\n";
const gnutls_datum_t key = { key_txt, sizeof (key_txt) };

static void
client (void)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  gnutls_certificate_credentials_t xcred;

  gnutls_global_init ();

  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (2);

  gnutls_certificate_allocate_credentials (&xcred);

  /* sets the trusted cas file
   */
  if (debug)
    success ("Setting key files...\n");

  ret = gnutls_certificate_set_openpgp_key_mem (xcred, &cert, &key,
						GNUTLS_OPENPGP_FMT_BASE64);
  if (ret < 0)
    {
      fail ("Could not set key files...\n");
    }

  /* Initialize TLS session
   */
  gnutls_init (&session, GNUTLS_CLIENT);

  /* Use default priorities */
  gnutls_set_default_priority (session);

  /* put the x509 credentials to the current session
   */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  /* connect to the peer
   */
  if (debug)
    success ("Connecting...\n");
  sd = tcp_connect ();

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  /* Perform the TLS handshake
   */
  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      fail ("client: Handshake failed\n");
      gnutls_perror (ret);
      goto end;
    }
  else if (debug)
    {
      success ("client: Handshake was completed\n");
    }

  if (debug)
    success ("client: TLS version is: %s\n",
	     gnutls_protocol_get_name (gnutls_protocol_get_version
				       (session)));

  /* see the Getting peer's information example */
  if (debug)
    print_info (session);

  gnutls_record_send (session, MSG, strlen (MSG));

  ret = gnutls_record_recv (session, buffer, MAX_BUF);
  if (ret == 0)
    {
      if (debug)
	success ("client: Peer has closed the TLS connection\n");
      goto end;
    }
  else if (ret < 0)
    {
      fail ("client: Error: %s\n", gnutls_strerror (ret));
      goto end;
    }

  if (debug)
    {
      printf ("- Received %d bytes: ", ret);
      for (ii = 0; ii < ret; ii++)
	{
	  fputc (buffer[ii], stdout);
	}
      fputs ("\n", stdout);
    }

  gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:

  tcp_close (sd);

  gnutls_deinit (session);

  gnutls_certificate_free_credentials (xcred);

  gnutls_global_deinit ();
}

/* This is a sample TLS 1.0 echo server, using X.509 authentication.
 */

#define SA struct sockaddr
#define MAX_BUF 1024
#define PORT 5556		/* listen to 5556 port */
#define DH_BITS 1024

/* These are global */
gnutls_certificate_credentials_t pgp_cred;

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  gnutls_set_default_priority (session);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, pgp_cred);

  /* request client certificate if any.
   */
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

  gnutls_dh_set_prime_bits (session, DH_BITS);

  return session;
}

static gnutls_dh_params_t dh_params;

static int
generate_dh_params (void)
{
  const gnutls_datum_t p3 = { (char *) pkcs3, strlen (pkcs3) };
  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  gnutls_dh_params_init (&dh_params);
  return gnutls_dh_params_import_pkcs3 (dh_params, &p3, GNUTLS_X509_FMT_PEM);
}

int err, listen_sd, i;
int sd, ret;
struct sockaddr_in sa_serv;
struct sockaddr_in sa_cli;
int client_len;
char topbuf[512];
gnutls_session_t session;
char buffer[MAX_BUF + 1];
int optval = 1;

static unsigned char server_crt_txt[] =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
  "Version: GnuPG v1.4.6 (GNU/Linux)\n"
  "\n"
  "mNEER2PogwEGINdIR4u5PR4SwADWwj/ztgtoi7XVbmlfbQTHpBYFxTSC88pISSNy\n"
  "V/rgnlqunYP77F7aHL4KUReN3v9sKw01xSGEfox/JmlqUUg6CVvTjdeLfkuVIBnH\n"
  "j+2KMlaxezp7IxtPaTXpXcSf8iOuVq7UX7p6tKbppKXO5GgmfA88VUVvGBs1/PQp\n"
  "WKQdGrj+6I3RRmDN/hna1jGU/N23230Hbx+bu7g9cviiSh10ri7rdDhVJ67tRkRG\n"
  "Usy3XO6dWC7EmzZlEO8AEQEAAbQQdGVzdDMuZ251dGxzLm9yZ4kBAAQTAQIAJgUC\n"
  "R2PogwIbAwUJCWYBgAYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEKAh4/gImZBR\n"
  "96QGH3E3zynETuQS3++hGMvMXq2mDJeT2e8964y/ifIOBpr2K2isuLYnrtGKyxi+\n"
  "ZptyHv6ymR3bDvio50cjnoT/WK1onosOJvtijGBS+U/ooq3im7ExpeQYXc/zpYsX\n"
  "OmB5m6BvdomUp2PMqdxsmOPoaRkSYx5R2Rlo/z3csodl6sp3k465Y/jg7L4gkxDz\n"
  "XJM+CS1xMhcOF0gBhppqLnG67x0ow847Pydstzkw0sOqedkLPuScaHNnlAWQ7QH6\n"
  "mbbpqHJwekS4jQRHiKV8AQQA0iZ81WXypLI4ZE2+hYfBCnfMVfQF/vPgvASxhwri\n"
  "GDa9Zc2f/VfakfNiwZgHH6iCeppHBiP2jljnbuOsL6f1R+0FsnyTVwHbuEU7IU2y\n"
  "+J0/s0z3wcx9sx8T7brP5z5F2hdagBsD9YFGCifHDAEew4mmAisY0i2QHVIuXJFj\n"
  "4RMAEQEAAYkBhwQYAQIADwUCR4ilfAIbAgUJEOrPgACoCRCgIeP4CJmQUZ0gBBkB\n"
  "AgAGBQJHiKV8AAoJEIN7b7QuD+F2AEcEAKAjhO9kSOE8UuwEOKlwsWL9LUUSkHJj\n"
  "c/ca0asLAerzrHsldRAcwCbWkVxBBHySw2CLFjzpgdXhwRtsytMgHaapfAPbinAW\n"
  "jCPIEJx2gDZeZnTgi4DVbZn5E3UzHGyL69MEoXr5t+vpiemQFd/nGD+h/Q2A76od\n"
  "gvAryRvS1Soj8bcGHjUflayXGOSvaD8P2V5Vz0hS82QZcqWxD8qUBqbcB8atokmO\n"
  "IYxhKyRmO58T5Ma+iaxBTUIwee+pBYDgdH6E2dh9xLlwwzZKaCcIRCQcObkLsMVo\n"
  "fZJo+m0Xf8zI57NeQF+hXJhW7lIrWgQVr8IVp/lgo76acLHfL/t1n0Nhg4r2srz2\n"
  "fpP2w5laQ0qImYLnZhGFHU+rJUyFaHfhD8/svN2LuZkO570pjV/K68EaHnEfk5b8\n"
  "jWu/euohwcCwf20M1kTo3Bg=\n"
  "=Xjon\n" "-----END PGP PUBLIC KEY BLOCK-----\n";
const gnutls_datum_t server_crt = { server_crt_txt, sizeof (server_crt_txt) };

static unsigned char server_key_txt[] =
  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
  "Version: GnuPG v1.4.6 (GNU/Linux)\n"
  "\n"
  "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\n"
  "=mZnW\n" "-----END PGP PRIVATE KEY BLOCK-----\n";
const gnutls_datum_t server_key = { server_key_txt, sizeof (server_key_txt) };

static void
server_start (void)
{
  /* Socket operations
   */
  listen_sd = socket (AF_INET, SOCK_STREAM, 0);
  if (err == -1)
    {
      perror ("socket");
      fail ("server: socket failed\n");
      return;
    }

  memset (&sa_serv, '\0', sizeof (sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons (PORT);	/* Server Port number */

  setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval,
	      sizeof (int));

  err = bind (listen_sd, (SA *) & sa_serv, sizeof (sa_serv));
  if (err == -1)
    {
      perror ("bind");
      fail ("server: bind failed\n");
      return;
    }

  err = listen (listen_sd, 1024);
  if (err == -1)
    {
      perror ("listen");
      fail ("server: listen failed\n");
      return;
    }

  if (debug)
    success ("server: ready. Listening to port '%d'.\n", PORT);
}

static void
server (void)
{
  /* this must be called once in the program
   */
  gnutls_global_init ();

  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (2);

  gnutls_certificate_allocate_credentials (&pgp_cred);

  ret = gnutls_certificate_set_openpgp_key_mem2 (pgp_cred, &server_crt,
						 &server_key, "auto",
						 GNUTLS_OPENPGP_FMT_BASE64);
  if (err < 0)
    {
      fail ("Could not set server key files...\n");
    }

  if (debug)
    success ("Launched, setting DH parameters...\n");

  generate_dh_params ();

  gnutls_certificate_set_dh_params (pgp_cred, dh_params);

  client_len = sizeof (sa_cli);

  session = initialize_tls_session ();

  sd = accept (listen_sd, (SA *) & sa_cli, &client_len);

  if (debug)
    success ("server: connection from %s, port %d\n",
	     inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf,
			sizeof (topbuf)), ntohs (sa_cli.sin_port));

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      close (sd);
      gnutls_deinit (session);
      fail ("server: Handshake has failed (%s)\n\n", gnutls_strerror (ret));
      return;
    }
  if (debug)
    success ("server: Handshake was completed\n");

  if (debug)
    success ("server: TLS version is: %s\n",
	     gnutls_protocol_get_name (gnutls_protocol_get_version
				       (session)));

  /* see the Getting peer's information example */
  if (debug)
    print_info (session);

  i = 0;
  for (;;)
    {
      memset (buffer, 0, MAX_BUF + 1);
      ret = gnutls_record_recv (session, buffer, MAX_BUF);

      if (ret == 0)
	{
	  if (debug)
	    success ("server: Peer has closed the GnuTLS connection\n");
	  break;
	}
      else if (ret < 0)
	{
	  fail ("server: Received corrupted data(%d). Closing...\n", ret);
	  break;
	}
      else if (ret > 0)
	{
	  /* echo data back to the client
	   */
	  gnutls_record_send (session, buffer, strlen (buffer));
	}
    }
  /* do not wait for the peer to close the connection.
   */
  gnutls_bye (session, GNUTLS_SHUT_WR);

  close (sd);
  gnutls_deinit (session);

  close (listen_sd);

  gnutls_certificate_free_credentials (pgp_cred);

  gnutls_dh_params_deinit (dh_params);

  gnutls_global_deinit ();

  if (debug)
    success ("server: finished\n");
}


void
doit (void)
{
  server_start ();
  if (error_count)
    return;

  child = fork ();
  if (child < 0)
    {
      perror ("fork");
      fail ("fork");
      return;
    }

  if (child)
    {
      int status;
      /* parent */
      server ();
      wait (&status);
    }
  else
    client ();
}
