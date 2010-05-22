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
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>

#include <gcrypt.h>

#include "utils.h"

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

static int handshake = 0;

char *to_server;
size_t to_server_len;

char *to_client;
size_t to_client_len;


static ssize_t
client_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
//  success ("client_pull len %d has %d\n", len, to_client_len);
  unsigned char rnd;
  gcry_create_nonce (&rnd, 1);

  if (handshake == 0 && rnd % 2 == 0)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  if (to_client_len < len)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  memcpy (data, to_client, len);

  memmove (to_client, to_client + len, to_client_len - len);
  to_client_len -= len;

  return len;
}

static ssize_t
client_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  char *tmp;
  size_t newlen = to_server_len + len;
//  success ("client_push len %d has %d\n", len, to_server_len);
//  hexprint (data, len);

  tmp = realloc (to_server, newlen);
  if (!tmp)
    {
      fail ("Memory allocation failure...\n");
      exit (1);
    }
  to_server = tmp;

  memcpy (to_server + to_server_len, data, len);
  to_server_len = newlen;

  return len;
}

static ssize_t
server_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  //success ("server_pull len %d has %d\n", len, to_server_len);
  unsigned char rnd;

  gcry_create_nonce (&rnd, 1);
  if (handshake == 0 && rnd % 2 == 0)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  if (to_server_len < len)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  memcpy (data, to_server, len);

  memmove (to_server, to_server + len, to_server_len - len);
  to_server_len -= len;

  return len;
}

static ssize_t
server_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  unsigned char rnd;
  char *tmp;
  size_t newlen = to_client_len + len;

  //success ("server_push len %d has %d\n", len, to_client_len);
  gcry_create_nonce (&rnd, 1);
  if (handshake == 0 && rnd % 2 == 0)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

//  hexprint (data, len);

  tmp = realloc (to_client, newlen);
  if (!tmp)
    {
      fail ("Memory allocation failure...\n");
      exit (1);
    }
  to_client = tmp;

  memcpy (to_client + to_client_len, data, len);
  to_client_len = newlen;

  return len;
}

#define MAX_BUF 1024
#define MSG "Hello TLS"

void
doit (void)
{
  /* Server stuff. */
  gnutls_anon_server_credentials_t s_anoncred;
  const gnutls_datum_t p3 = { (char *) pkcs3, strlen (pkcs3) };
  static gnutls_dh_params_t dh_params;
  gnutls_session_t server;
  int sret = GNUTLS_E_AGAIN;
  /* Client stuff. */
  gnutls_anon_client_credentials_t c_anoncred;
  gnutls_session_t client;
  int cret = GNUTLS_E_AGAIN;
  /* Need to enable anonymous KX specifically. */
  const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
  char buffer[MAX_BUF + 1];
  ssize_t ns;
  int ret, transferred = 0;

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
  gnutls_init (&server, GNUTLS_SERVER);
  gnutls_set_default_priority (server);
  gnutls_kx_set_priority (server, kx_prio);
  gnutls_credentials_set (server, GNUTLS_CRD_ANON, s_anoncred);
  gnutls_dh_set_prime_bits (server, 1024);
  gnutls_transport_set_push_function (server, server_push);
  gnutls_transport_set_pull_function (server, server_pull);

  /* Init client */
  gnutls_anon_allocate_client_credentials (&c_anoncred);
  gnutls_init (&client, GNUTLS_CLIENT);
  gnutls_set_default_priority (client);
  gnutls_kx_set_priority (client, kx_prio);
  gnutls_credentials_set (client, GNUTLS_CRD_ANON, c_anoncred);
  gnutls_transport_set_push_function (client, client_push);
  gnutls_transport_set_pull_function (client, client_pull);

  handshake = 1;
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
  while (cret == GNUTLS_E_AGAIN || sret == GNUTLS_E_AGAIN);
  handshake = 0;
  if (debug)
    success ("Handshake established\n");

  ns = gnutls_record_send (client, MSG, strlen (MSG));
  //success ("client: sent %d\n", ns);

  do
    {
      //success("transferred: %d\n", transferred);

      ret = gnutls_record_recv (server, buffer, MAX_BUF);
      if (ret == 0)
	fail ("server: didn't receive any data\n");
      else if (ret < 0)
	{
	  if (ret != GNUTLS_E_AGAIN)
	    {
	      fail ("server: error: %s\n", gnutls_strerror (ret));
	      break;
	    }
	}
      else
	{
	  transferred += ret;
	  if (debug)
	    fputs ("*", stdout);
	}

      ns = gnutls_record_send (server, MSG, strlen (MSG));
      //success ("server: sent %d\n", ns);

      ret = gnutls_record_recv (client, buffer, MAX_BUF);
      if (ret == 0)
	{
	  fail ("client: Peer has closed the TLS connection\n");
	}
      else if (ret < 0)
	{
	  if (ret != GNUTLS_E_AGAIN)
	    {
	      fail ("client: Error: %s\n", gnutls_strerror (ret));
	      break;
	    }
	}
      else
	{
	  transferred += ret;
	  if (debug)
	    fputs (".", stdout);
	}
    }
  while (transferred < 7000);
  if (debug)
    fputs ("\n", stdout);

  gnutls_bye (client, GNUTLS_SHUT_RDWR);
  gnutls_bye (server, GNUTLS_SHUT_RDWR);

  gnutls_deinit (client);
  gnutls_deinit (server);

  free (to_server);
  free (to_client);

  gnutls_anon_free_client_credentials (c_anoncred);
  gnutls_anon_free_server_credentials (s_anoncred);

  gnutls_dh_params_deinit (dh_params);

  gnutls_global_deinit ();
}
