/*
 * Copyright (C) 2008-2012 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/sbuf.h>
#include "eagain-common.h"

#include "utils.h"

const char* side = "";

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "%s|<%d>| %s", side, level, str);
}

#define MAX_BUF 60*1024

static unsigned char server_buf[MAX_BUF];
static unsigned char client_buf[MAX_BUF];

#define LINE1 "hello there people\n"
#define LINE2 "how are you doing today, all well?\n"

void
doit (void)
{
  /* Server stuff. */
  gnutls_anon_server_credentials_t s_anoncred;
  const gnutls_datum_t p3 = { (unsigned char *) pkcs3, strlen (pkcs3) };
  static gnutls_dh_params_t dh_params;
  gnutls_session_t server;
  gnutls_sbuf_t ssbuf;
  int sret = GNUTLS_E_AGAIN;
  /* Client stuff. */
  gnutls_anon_client_credentials_t c_anoncred;
  gnutls_session_t client;
  int cret = GNUTLS_E_AGAIN;
  /* Need to enable anonymous KX specifically. */
  int ret;
  ssize_t left, spos, cpos;
  char *abuf = NULL;
  size_t abuf_size = 0;

  /* General init. */
  gnutls_global_init ();
  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (4711);

  /* Init server */
  gnutls_anon_allocate_server_credentials (&s_anoncred);
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_import_pkcs3 (dh_params, &p3, GNUTLS_X509_FMT_PEM);
  gnutls_anon_set_server_dh_params (s_anoncred, dh_params);
  gnutls_init (&server, GNUTLS_SERVER);
  gnutls_priority_set_direct (server, "NONE:+VERS-TLS-ALL:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-DH", NULL);
  gnutls_credentials_set (server, GNUTLS_CRD_ANON, s_anoncred);
  gnutls_dh_set_prime_bits (server, 1024);
  gnutls_transport_set_push_function (server, server_push);
  gnutls_transport_set_pull_function (server, server_pull);
  gnutls_transport_set_ptr (server, (gnutls_transport_ptr_t)server);
  
  gnutls_sbuf_init(&ssbuf, server, GNUTLS_SBUF_QUEUE_FLUSHES);
  
  gnutls_rnd(GNUTLS_RND_NONCE, server_buf, sizeof(server_buf));

  /* Init client */
  gnutls_anon_allocate_client_credentials (&c_anoncred);
  gnutls_init (&client, GNUTLS_CLIENT);
  gnutls_priority_set_direct (client, "NONE:+VERS-TLS-ALL:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-DH", NULL);
  gnutls_credentials_set (client, GNUTLS_CRD_ANON, c_anoncred);
  gnutls_transport_set_push_function (client, client_push);
  gnutls_transport_set_pull_function (client, client_pull);
  gnutls_transport_set_ptr (client, (gnutls_transport_ptr_t)client);

  memset(client_buf, 0, sizeof(client_buf));

  HANDSHAKE(client, server);

  if (debug)
    success ("Handshake established\n");

#define SEND_SIZE 100
  left = sizeof(server_buf);
  spos = 0;
  cpos = 0;
  while (left > 0)
    {
      if (left > SEND_SIZE)
        {
          ret = gnutls_sbuf_write(ssbuf, server_buf+spos, SEND_SIZE);
        }
      else
        {
          ret = gnutls_sbuf_write(ssbuf, server_buf+spos, left);
        }

      if (ret >= 0)
        {
          left -= ret;
          spos += ret;
          ret = gnutls_sbuf_flush(ssbuf);
        }

      if (ret < 0)
        {
          fail("Error sending %s\n", gnutls_strerror(ret));
          abort();
        }
      
      if (ret > 0)
        { /* received in client side */
          ret = gnutls_record_recv(client, client_buf+cpos, sizeof(client_buf)-cpos);
          if (ret > 0)
            cpos += ret;

          if (ret < 0)
            {
              fail("Error receiving %s\n", gnutls_strerror(ret));
              abort();
            }
        }
    }
    
  if (memcmp(client_buf, server_buf, sizeof(server_buf)) != 0)
    {
      fail("Data do not match!\n");
      abort();
    }
  
  gnutls_record_send(client, LINE1, sizeof(LINE1)-1);
  gnutls_record_send(client, LINE2, sizeof(LINE2)-1);
  
  ret = gnutls_sbuf_getline(ssbuf, &abuf, &abuf_size);
  if (ret < 0)
    {
      fail("sbuf_getline error %s!\n", gnutls_strerror(ret));
      abort();
    }

  if (strcmp(abuf, LINE1) != 0)
    {
      fail("LINE1 Data do not match!\n");
      abort();
    }

  ret = gnutls_sbuf_getline(ssbuf, &abuf, &abuf_size);
  if (ret < 0)
    {
      fail("sbuf_getline error %s!\n", gnutls_strerror(ret));
      abort();
    }

  if (strcmp(abuf, LINE2) != 0)
    {
      fail("LINE2 Data do not match!\n");
      abort();
    }

  gnutls_free(abuf);
  gnutls_bye (client, GNUTLS_SHUT_RDWR);
  gnutls_bye (server, GNUTLS_SHUT_RDWR);

  gnutls_sbuf_deinit (ssbuf);
  gnutls_deinit (client);
  gnutls_deinit (server);

  gnutls_anon_free_client_credentials (c_anoncred);
  gnutls_anon_free_server_credentials (s_anoncred);

  gnutls_dh_params_deinit (dh_params);

  gnutls_global_deinit ();
}
