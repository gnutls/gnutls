/*
 * Copyright (C) 2008-2012 Free Software Foundation, Inc.
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
#include "loss-common.h"

const char * prefix = NULL;
int counter;
int packet_to_lose;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "%s|<%d>| %s", prefix, level, str);
}

static gnutls_anon_server_credentials_t s_anoncred;
static gnutls_anon_client_credentials_t c_anoncred;

static void try1 (int packet)
{
  /* Server stuff. */
  gnutls_session_t server;
  int sret, cret;
  /* Client stuff. */
  gnutls_session_t client;
  /* Need to enable anonymous KX specifically. */
  int ret;

  counter = 0;
  packet_to_lose = packet;
  reset_counters();
  
  gnutls_init (&server, GNUTLS_SERVER|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
  ret = gnutls_priority_set_direct (server, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL", NULL);
  if (ret < 0)
    exit(1);
  gnutls_credentials_set (server, GNUTLS_CRD_ANON, s_anoncred);
  gnutls_transport_set_push_function (server, server_push);
  gnutls_transport_set_pull_function (server, server_pull);
  gnutls_transport_set_pull_timeout_function (server, server_pull_timeout_func);
  gnutls_transport_set_ptr (server, (gnutls_transport_ptr_t)server);

  /* Init client */
  gnutls_init (&client, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
  cret = gnutls_priority_set_direct (client, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL", NULL);
  if (cret < 0)
    exit(1);
  gnutls_credentials_set (client, GNUTLS_CRD_ANON, c_anoncred);
  gnutls_transport_set_push_function (client, client_push);
  gnutls_transport_set_pull_function (client, client_pull);
  gnutls_transport_set_pull_timeout_function (client, client_pull_timeout_func);
  gnutls_transport_set_ptr (client, (gnutls_transport_ptr_t)client);

  HANDSHAKE(client, server);

  if (debug)
    success ("Handshake established\n");

  gnutls_bye (client, GNUTLS_SHUT_WR);
  gnutls_bye (server, GNUTLS_SHUT_WR);

  gnutls_deinit (client);
  gnutls_deinit (server);
}

void
doit (void)
{
  /* General init. */
  gnutls_global_init ();
  if (debug)
    {
      gnutls_global_set_log_function (tls_log_func);
      gnutls_global_set_log_level (9);
    }

  gnutls_anon_allocate_server_credentials (&s_anoncred);
  gnutls_anon_allocate_client_credentials (&c_anoncred);

  try1(1);
  try1(2);
  try1(3);
  try1(4);
  try1(5);

  gnutls_anon_free_client_credentials (c_anoncred);
  gnutls_anon_free_server_credentials (s_anoncred);

  gnutls_global_deinit ();
}
