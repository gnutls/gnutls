/*
 * Copyright (C) 2008, 2010 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson, Nikos Mavrogiannopoulos
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "utils.h"
#include "eagain-common.h"

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

static int handshake = 0;

#define MAX_BUF 1024
#define MSG "Hello TLS, and hi and how are you and more data here... and more... and even more and even more more data..."

void
doit (void)
{
  /* Server stuff. */
  gnutls_anon_server_credentials_t s_anoncred;
  const gnutls_datum_t p3 = { (char *) pkcs3, strlen (pkcs3) };
  static gnutls_dh_params_t dh_params;
  gnutls_session_t server;
  int sret, cret;
  /* Client stuff. */
  gnutls_anon_client_credentials_t c_anoncred;
  gnutls_session_t client;
  /* Need to enable anonymous KX specifically. */
  char buffer[MAX_BUF + 1];
  ssize_t ns;
  int ret, transferred = 0, msglen;

  /* General init. */
  gnutls_global_init ();
  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (99);

  /* Init server */
  gnutls_anon_allocate_server_credentials (&s_anoncred);
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_import_pkcs3 (dh_params, &p3, GNUTLS_X509_FMT_PEM);
  gnutls_anon_set_server_dh_params (s_anoncred, dh_params);
  gnutls_init (&server, GNUTLS_SERVER|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
  ret = gnutls_priority_set_direct (server, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-DH", NULL);
  if (ret < 0)
    exit(1);
  gnutls_credentials_set (server, GNUTLS_CRD_ANON, s_anoncred);
  gnutls_dh_set_prime_bits (server, 1024);
  gnutls_transport_set_push_function (server, server_push);
  gnutls_transport_set_pull_function (server, server_pull);
  gnutls_transport_set_pull_timeout_function (server, server_pull_timeout_func);

  /* Init client */
  gnutls_anon_allocate_client_credentials (&c_anoncred);
  gnutls_init (&client, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
  cret = gnutls_priority_set_direct (client, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-DH", NULL);
  if (cret < 0)
    exit(1);
  gnutls_credentials_set (client, GNUTLS_CRD_ANON, c_anoncred);
  gnutls_transport_set_push_function (client, client_push);
  gnutls_transport_set_pull_function (client, client_pull);
  gnutls_transport_set_pull_timeout_function (client, client_pull_timeout_func);

  handshake = 1;
  sret = cret = GNUTLS_E_AGAIN;
  do
    {
      if (cret == GNUTLS_E_AGAIN)
        {
          //success ("loop invoking client:\n");
          cret = gnutls_handshake (client);
          //success ("client %d: %s\n", cret, gnutls_strerror (cret));
        }

      if (sret == GNUTLS_E_AGAIN)
        {
          //success ("loop invoking server:\n");
          sret = gnutls_handshake (server);
          //success ("server %d: %s\n", sret, gnutls_strerror (sret));
        }
    }
  while ((cret == GNUTLS_E_AGAIN && gnutls_error_is_fatal(sret)==0) || (sret == GNUTLS_E_AGAIN && gnutls_error_is_fatal(cret)==0));

  if (cret < 0 || sret < 0)
    {
      fprintf(stderr, "client: %s\n", gnutls_strerror(cret));
      fprintf(stderr, "server: %s\n", gnutls_strerror(sret));
      fail("Handshake failed\n");
      exit(1);
    }

  handshake = 0;
  if (debug)
    success ("Handshake established\n");

  do
    {
      ret = gnutls_record_send (client, MSG, strlen (MSG));
    }
  while(ret == GNUTLS_E_AGAIN);
  //success ("client: sent %d\n", ns);

  do
    {
      //success("transferred: %d\n", transferred);

      do
        {
          ret = gnutls_record_recv (server, buffer, MAX_BUF);
        }
      while(ret == GNUTLS_E_AGAIN);

      if (ret == 0)
        fail ("server: didn't receive any data\n");
      else if (ret < 0)
        {
          //      if (debug)
          //          fputs ("#", stdout);
          fail ("server: error: %s\n", gnutls_strerror (ret));
        }
      else
        {
          transferred += ret;
            //        if (debug)
              //          fputs ("*", stdout);
        }

      msglen = strlen (MSG);
      do
        {
          ns = gnutls_record_send (server, MSG, msglen);
        }
      while (ns == GNUTLS_E_AGAIN);

      do
        {
          ret = gnutls_record_recv (client, buffer, MAX_BUF);
        }
      while(ret == GNUTLS_E_AGAIN);


      if (ret == 0)
        {
          fail ("client: Peer has closed the TLS connection\n");
        }
      else if (ret < 0)
        {
          if (debug)
            fputs ("!", stdout);
          fail ("client: Error: %s\n", gnutls_strerror (ret));
        }
      else
        {
          if (msglen != ret || memcmp (buffer, MSG, msglen) != 0)
            {
              fail ("client: Transmitted data do not match\n");
            }

          /* echo back */
          do
            {
              ns = gnutls_record_send (client, buffer, msglen);
            }
          while (ns == GNUTLS_E_AGAIN);

          transferred += ret;
          if (debug)
            fputs (".", stdout);
        }
    }
  while (transferred < 70000);
  if (debug)
    fputs ("\n", stdout);

  gnutls_bye (client, GNUTLS_SHUT_WR);
  gnutls_bye (server, GNUTLS_SHUT_WR);

  gnutls_deinit (client);
  gnutls_deinit (server);

  gnutls_anon_free_client_credentials (c_anoncred);
  gnutls_anon_free_server_credentials (s_anoncred);

  gnutls_dh_params_deinit (dh_params);

  gnutls_global_deinit ();
}
