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

int main()
{
  exit(77);
}

#else

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "utils.h"

/* This program simulates packet loss in DTLS datagrams using
 * the blocking functions. Idea taken from test app of
 * Sean Buckheister.
 */

static void print_type(const unsigned char* buf, int size)
{
  if (buf[0] == 22 && size >= 13) {
    if (buf[13] == 1)
      fprintf(stderr, "Client Hello\n");
    else if (buf[13] == 2)
      fprintf(stderr, "Server Hello\n");
    else if (buf[13] == 12)
      fprintf(stderr, "Server Key exchange\n");
    else if (buf[13] == 14)
      fprintf(stderr, "Server Hello Done\n");
    else if (buf[13] == 11)
      fprintf(stderr, "Certificate\n");
    else if (buf[13] == 16)
      fprintf(stderr, "Client Key Exchange\n");
    else if (buf[4] == 1)
      fprintf(stderr, "Finished\n");
    else if (buf[13] == 11)
      fprintf(stderr, "Server Hello Done\n");
    else
      fprintf(stderr, "Unknown handshake\n");
  } else if (buf[0] == 20) {
    fprintf(stderr, "Change Cipher Spec\n");
  } else
    fprintf(stderr, "Unknown\n");
}

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

/* A very basic TLS client, with anonymous authentication.
 */

#define MAX_BUF 1024
#define MSG "Hello TLS"

static int counter;
static int packet_to_lose;
gnutls_session_t session;

static ssize_t
push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
int fd = (long int)tr;

  counter++;

  if (packet_to_lose != -1 && packet_to_lose == counter) {
    if (debug)
      {
        fprintf(stderr, "Discarding packet %d: ", counter);
        print_type(data, len);
      }
    return len;
  }
  return send(fd, data, len, 0);
}

static void
client (int fd, int packet)
{
  int ret, ii;
  char buffer[MAX_BUF + 1];
  gnutls_anon_client_credentials_t anoncred;
  /* Need to enable anonymous KX specifically. */

  gnutls_global_init ();

  if (debug)
    {
      gnutls_global_set_log_function (client_log_func);
      gnutls_global_set_log_level (4711);
    }

  gnutls_anon_allocate_client_credentials (&anoncred);

  /* Initialize TLS session
   */
  gnutls_init (&session, GNUTLS_CLIENT|GNUTLS_DATAGRAM);
  gnutls_dtls_set_mtu( session, 1500);

  /* Use default priorities */
  gnutls_priority_set_direct (session, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL", NULL);

  /* put the anonymous credentials to the current session
   */
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  counter = 0;
  packet_to_lose = packet;

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);
  gnutls_transport_set_push_function (session, push);

  /* Perform the TLS handshake
   */
  do 
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0)
    {
      fail ("client: Handshake failed\n");
      gnutls_perror (ret);
      exit(1);
    }
  else
    {
      if (debug)
        success ("client: Handshake was completed\n");
    }

  if (debug)
    success ("client: TLS version is: %s\n",
             gnutls_protocol_get_name (gnutls_protocol_get_version
                                       (session)));

  do {
    ret = gnutls_record_send (session, MSG, strlen (MSG));
  } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

  do {
    ret = gnutls_record_recv (session, buffer, MAX_BUF);
  } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

  if (ret == 0)
    {
      if (debug)
        success ("client: Peer has closed the TLS connection\n");
      goto end;
    }
  else if (ret < 0)
    {
      fail ("client: Error: %s\n", gnutls_strerror (ret));
      exit(1);
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

  close (fd);

  gnutls_deinit (session);

  gnutls_anon_free_client_credentials (anoncred);

  gnutls_global_deinit ();
}


/* These are global */
gnutls_anon_server_credentials_t anoncred;
pid_t child;

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER|GNUTLS_DATAGRAM);
  gnutls_dtls_set_mtu( session, 1500);

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  gnutls_priority_set_direct (session, "NONE:+VERS-DTLS1.0:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-ECDH:+CURVE-ALL", NULL);

  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  return session;
}

static void terminate(void)
{
int status;

  kill(child, SIGTERM);
  wait(&status);
  exit(1);
}

static void
server (int fd, int packet)
{
int ret;
char buffer[MAX_BUF + 1];
  /* this must be called once in the program
   */
  gnutls_global_init ();

  if (debug)
    {
      gnutls_global_set_log_function (server_log_func);
      gnutls_global_set_log_level (4711);
    }

  gnutls_anon_allocate_server_credentials (&anoncred);

  session = initialize_tls_session ();

  counter = 0;
  packet_to_lose = packet;

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);
  gnutls_transport_set_push_function (session, push);

  do 
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  if (ret < 0)
    {
      close (fd);
      gnutls_deinit (session);
      fail ("server: Handshake has failed (%s)\n\n", gnutls_strerror (ret));
      terminate();
    }
  if (debug)
    success ("server: Handshake was completed\n");

  if (debug)
    success ("server: TLS version is: %s\n",
             gnutls_protocol_get_name (gnutls_protocol_get_version
                                       (session)));

  /* see the Getting peer's information example */
  /* print_info(session); */

  for (;;)
    {
      memset (buffer, 0, MAX_BUF + 1);
      
      do {
        ret = gnutls_record_recv (session, buffer, MAX_BUF);
      } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

      if (ret == 0)
        {
          if (debug)
            success ("server: Peer has closed the GnuTLS connection\n");
          break;
        }
      else if (ret < 0)
        {
          fail ("server: Received corrupted data(%d). Closing...\n", ret);
          terminate();
        }
      else if (ret > 0)
        {
          /* echo data back to the client
           */
          do {
            ret = gnutls_record_send (session, buffer, strlen (buffer));
          } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
        }
    }
  /* do not wait for the peer to close the connection.
   */
  gnutls_bye (session, GNUTLS_SHUT_WR);

  close (fd);
  gnutls_deinit (session);

  gnutls_anon_free_server_credentials (anoncred);

  gnutls_global_deinit ();

  if (debug)
    success ("server: finished\n");
}

static void start (int server_packet, int client_packet)
{
  int fd[2];
  int ret;
  
  if (debug)
    fprintf(stderr, "\nWill discard %s packet %d\n", 
      (client_packet!=-1)?"client":"server", (client_packet!=-1)?client_packet:server_packet);
  
  ret = socketpair(AF_LOCAL, SOCK_DGRAM, 0, fd);
  if (ret < 0)
    {
      perror("socketpair");
      exit(1);
    }

  child = fork ();
  if (child < 0)
    {
      perror ("fork");
      fail ("fork");
      exit(1);
    }

  if (child)
    {
      int status;
      /* parent */
      server (fd[0], server_packet);
      wait (&status);
      if (WEXITSTATUS(status) != 0)
        fail("Child died with status %d\n", WEXITSTATUS(status));
    }
  else 
    {
      client (fd[1], client_packet);
      exit(0);
    }
}

void
doit (void)
{
  start(-1, 1);
  start(-1, 2);
  start(-1, 3);
  start(-1, 4);

  start(1, -1);
  start(2, -1);
  start(3, -1);
  start(4, -1);
  start(5, -1);
}

#endif /* _WIN32 */
