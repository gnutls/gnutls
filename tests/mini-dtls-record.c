/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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

#if defined(_WIN32)

int
main ()
{
    exit (77);
}

#else

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "utils.h"

static int test_finished = 0;
static void terminate (void);

/* This program tests the rehandshake in DTLS
 */

/*
static void
tls_audit_log_func (gnutls_session_t session, const char *str)
{
  fprintf (stderr, "|<%p>| %s", session, str);
}
*/

static void
server_log_func (int level, const char *str)
{
    fprintf (stderr, "server|<%d>| %s", level, str);
}

static void
client_log_func (int level, const char *str)
{
    fprintf (stderr, "client|<%d>| %s", level, str);
}

/* These are global */
static pid_t child;

/* A test client/server app for DTLS duplicate packet detection.
 */

#define MAX_BUF 1024

#define MAX_SEQ 128

static int msg_seq[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 16, 5, 32, 11, 11, 11, 11, 12, 10, 13, 14, 
  15, 16, 17, 19, 20, 18, 22, 24, 23, 25, 26, 27, 29, 28, 29, 29, 30, 31, 32, 33, 34, 35, 37, 36, 38, 39, 
  42, 37, 40, 41, 41, -1};
static unsigned int current = 0;
static unsigned int pos = 0;

unsigned char* stored_messages[MAX_SEQ];
unsigned int stored_sizes[MAX_SEQ];

static ssize_t
odd_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
ssize_t ret;
unsigned i;

  if (msg_seq[current] == -1 || test_finished != 0)
    {
      test_finished = 1;
      return len;
    }
  
  stored_messages[current] = malloc(len);
  memcpy(stored_messages[current], data, len);
  stored_sizes[current] = len;
  
  if (pos != current)
    {
      for (i=pos;i<=current;i++)
        {
          if (stored_messages[msg_seq[i]] != NULL)
            {
              do
                {
                  ret = send((long int)tr, stored_messages[msg_seq[i]], stored_sizes[msg_seq[i]], 0);
                }
              while(ret == -1 && errno == EAGAIN);
              pos++;
            }
          else
            break;
        }
    }
  else if (msg_seq[current] == (int)current)
    {
      do
        {
          ret = send((long int)tr, data, len, 0);
        }
      while(ret == -1 && errno == EAGAIN);

      current++;
      pos++;
    
      return ret;
    }
  else if (stored_messages[msg_seq[current]] != NULL)
    {
      do
        {
          ret = send((long int)tr, stored_messages[msg_seq[current]], stored_sizes[msg_seq[current]], 0);
        }
      while(ret == -1 && errno == EAGAIN);
      current++;
      pos++;
      return ret;
    }

  current++;

  return len;
}

static ssize_t
n_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  return send((unsigned long)tr, data, len, 0);
}

/* The first five messages are handshake. Thus corresponds to msg_seq+5 */
static int recv_msg_seq[] = { 1, 2, 3, 4, 5, 6, 12, 28, 7, 8, 9, 10, 11, 13, 15, 16, 14, 18, 20, 19, 21, 22, 
 23, 25, 24, 26, 27, 29, 30, 31, 33, 32, 34, 35, 38, 36, 37, -1};

static void
client (int fd)
{
    gnutls_session_t session;
    int ret;
    char buffer[MAX_BUF + 1];
    gnutls_anon_client_credentials_t anoncred;
    unsigned char seq[8];
    uint64_t useq;
    unsigned current = 0;
    struct timespec ts;
    
    memset(buffer, 0, sizeof(buffer));
    
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000*1000;
    /* Need to enable anonymous KX specifically. */

/*    gnutls_global_set_audit_log_function (tls_audit_log_func); */
    gnutls_global_init ();

    if (debug)
      {
          gnutls_global_set_log_function (client_log_func);
          gnutls_global_set_log_level (99);
      }

    gnutls_anon_allocate_client_credentials (&anoncred);

    /* Initialize TLS session
     */
    gnutls_init (&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
    gnutls_heartbeat_enable (session, GNUTLS_HB_PEER_ALLOWED_TO_SEND);
    gnutls_dtls_set_mtu (session, 1500);

    /* Use default priorities */
    gnutls_priority_set_direct (session,
                                "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL",
                                NULL);

    /* put the anonymous credentials to the current session
     */
    gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);

    /* Perform the TLS handshake
     */
    do
      {
          ret = gnutls_handshake (session);
      }
    while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

    if (ret < 0)
      {
          fail ("client: Handshake failed\n");
          gnutls_perror (ret);
          exit (1);
      }
    else
      {
          if (debug)
              success ("client: Handshake was completed\n");
      }

    gnutls_record_send( session, buffer, 1);

    if (debug)
        success ("client: DTLS version is: %s\n",
                 gnutls_protocol_get_name (gnutls_protocol_get_version
                                           (session)));
    do
      {
        ret = gnutls_record_recv_seq (session, buffer, sizeof (buffer), seq);

        if (ret > 0)
          {
            useq = seq[3] | (seq[2] << 8) | (seq[1] << 16) | (seq[0] << 24);
            useq <<= 32;
            useq |= seq[7] | (seq[6] << 8) | (seq[5] << 16) | (seq[4] << 24);
        
            if (recv_msg_seq[current] == -1)
              {
                fail("received message sequence differs\n");
                terminate();
              }
        
            if ((uint32_t)recv_msg_seq[current] != (uint32_t)useq)
              {
                fail("received message sequence differs\n");
                terminate();
              }

            current++;
          }
          nanosleep(&ts, NULL);
      }
    while ((ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED || ret > 0));

    gnutls_bye (session, GNUTLS_SHUT_WR);

    close (fd);

    gnutls_deinit (session);

    gnutls_anon_free_client_credentials (anoncred);

    gnutls_global_deinit ();
}


static void
terminate (void)
{
    int status;

    kill (child, SIGTERM);
    wait (&status);
    exit (1);
}

static void
server (int fd)
{
    int ret;
    gnutls_session_t session;
    gnutls_anon_server_credentials_t anoncred;
    struct timespec ts;
    char c;
    
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000*1000;

    gnutls_global_init ();

    if (debug)
      {
          gnutls_global_set_log_function (server_log_func);
          gnutls_global_set_log_level (4711);
      }

    gnutls_anon_allocate_server_credentials (&anoncred);

    gnutls_init (&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
    gnutls_transport_set_push_function (session, odd_push);
    gnutls_heartbeat_enable (session, GNUTLS_HB_PEER_ALLOWED_TO_SEND);
    gnutls_dtls_set_mtu (session, 1500);

    /* avoid calling all the priority functions, since the defaults
     * are adequate.
     */
    gnutls_priority_set_direct (session,
                                "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL",
                                NULL);
    gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);

    do
      {
          ret = gnutls_handshake (session);
      }
    while (ret < 0 && gnutls_error_is_fatal (ret) == 0);
    if (ret < 0)
      {
          close (fd);
          gnutls_deinit (session);
          fail ("server: Handshake has failed (%s)\n\n",
                gnutls_strerror (ret));
          terminate ();
      }
    if (debug)
        success ("server: Handshake was completed\n");

    if (debug)
        success ("server: TLS version is: %s\n",
                 gnutls_protocol_get_name (gnutls_protocol_get_version
                                           (session)));

    gnutls_record_recv(session, &c, 1);
    do
      {
          do
            {
                ret = gnutls_record_send( session, &c, 1);
            }
          while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

          if (ret < 0)
            {
                fail ("send: %s\n", gnutls_strerror (ret));
                terminate ();
            }
          nanosleep(&ts, NULL);
      }
    while (test_finished == 0);

    gnutls_transport_set_push_function (session, n_push);
    nanosleep(&ts, NULL);
    do
      {
        ret = gnutls_bye (session, GNUTLS_SHUT_WR);
      }
    while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

    close (fd);
    gnutls_deinit (session);

    gnutls_anon_free_server_credentials (anoncred);

    gnutls_global_deinit ();

    if (debug)
        success ("server: finished\n");
}

static void
start (void)
{
    int fd[2];
    int ret;

    ret = socketpair (AF_UNIX, SOCK_DGRAM, 0, fd);
#if 0
    ret = socketpair (AF_UNIX, SOCK_STREAM, 0, fd);
#endif
    if (ret < 0)
      {
          perror ("socketpair");
          exit (1);
      }

    child = fork ();
    if (child < 0)
      {
          perror ("fork");
          fail ("fork");
          exit (1);
      }

    if (child)
      {
          int status;
          /* parent */

          server (fd[0]);
          wait (&status);
          if (WEXITSTATUS (status) != 0)
              fail ("Child died with status %d\n", WEXITSTATUS (status));
      }
    else
      {
          close (fd[0]);
          client (fd[1]);
          exit (0);
      }
}

void
doit (void)
{
    start ();
}

#endif /* _WIN32 */
