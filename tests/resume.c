/*
 * Copyright (C) 2004, 2005, 2007, 2008 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Parts copied from GnuTLS example programs. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "utils.h"

static void wrap_db_init (void);
static void wrap_db_deinit (void);
static int wrap_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data);
static gnutls_datum_t wrap_db_fetch (void *dbf, gnutls_datum_t key);
static int wrap_db_delete (void *dbf, gnutls_datum_t key);

#define TLS_SESSION_CACHE 50

/* A very basic TLS client, with anonymous authentication.
 */

#define MAX_BUF 1024
#define MSG "Hello TLS"

/* Connects to the peer and returns a socket
 * descriptor.
 */
int
tcp_connect (void)
{
  const char *PORT = "5556";
  const char *SERVER = "127.0.0.1";
  int err, sd;
  struct sockaddr_in sa;

  /* connects to server
   */
  sd = socket (AF_INET, SOCK_STREAM, 0);

  memset (&sa, '\0', sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (atoi (PORT));
  inet_pton (AF_INET, SERVER, &sa.sin_addr);

  err = connect (sd, (struct sockaddr *) &sa, sizeof (sa));
  if (err < 0)
    {
      fprintf (stderr, "Connect error\n");
      exit (1);
    }

  return sd;
}

/* closes the given socket descriptor.
 */
void
tcp_close (int sd)
{
  shutdown (sd, SHUT_RDWR);	/* no more receptions */
  close (sd);
}

void
client (void)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  gnutls_anon_client_credentials_t anoncred;
  /* Need to enable anonymous KX specifically. */
  const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };

  /* variables used in session resuming
   */
  int t;
  gnutls_datum session_data;

  gnutls_global_init ();

  gnutls_anon_allocate_client_credentials (&anoncred);

  for (t = 0; t < 2; t++)
    {				/* connect 2 times to the server */

      /* connect to the peer
       */
      sd = tcp_connect ();

      /* Initialize TLS session
       */
      gnutls_init (&session, GNUTLS_CLIENT);

      /* Use default priorities */
      gnutls_set_default_priority (session);
      gnutls_kx_set_priority (session, kx_prio);

      /* put the anonymous credentials to the current session
       */
      gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

      if (t > 0)
	{
	  /* if this is not the first time we connect */
	  gnutls_session_set_data (session, session_data.data,
				   session_data.size);
	  gnutls_free (session_data.data);
	}

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
      else
	{
	  success ("client: Handshake was completed\n");
	}

      if (t == 0)
	{			/* the first time we connect */
	  /* get the session data size */
	  ret = gnutls_session_get_data2 (session, &session_data);
	  if (ret < 0)
	    fail ("Getting resume data failed\n");
	}
      else
	{			/* the second time we connect */

	  /* check if we actually resumed the previous session */
	  if (gnutls_session_is_resumed (session) != 0)
	    {
	      success ("- Previous session was resumed\n");
	    }
	  else
	    {
	      success ("*** Previous session was NOT resumed\n");
	    }
	}

      gnutls_record_send (session, MSG, strlen (MSG));

      ret = gnutls_record_recv (session, buffer, MAX_BUF);
      if (ret == 0)
	{
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
    }

  gnutls_anon_free_client_credentials (anoncred);
}

/* This is a sample TLS 1.0 echo server, for anonymous authentication only.
 */

#define SA struct sockaddr
#define MAX_BUF 1024
#define PORT 5556		/* listen to 5556 port */
#define DH_BITS 1024

/* These are global */
gnutls_anon_server_credentials_t anoncred;

gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;
  const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };

  gnutls_init (&session, GNUTLS_SERVER);

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  gnutls_set_default_priority (session);
  gnutls_kx_set_priority (session, kx_prio);

  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  gnutls_dh_set_prime_bits (session, DH_BITS);

  if (TLS_SESSION_CACHE != 0)
    {
      gnutls_db_set_retrieve_function (session, wrap_db_fetch);
      gnutls_db_set_remove_function (session, wrap_db_delete);
      gnutls_db_set_store_function (session, wrap_db_store);
      gnutls_db_set_ptr (session, NULL);
    }

  return session;
}

static gnutls_dh_params_t dh_params;

static int
generate_dh_params (void)
{
  const gnutls_datum_t p3 = { pkcs3, strlen (pkcs3) };
  /* Generate Diffie Hellman parameters - for use with DHE
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

void
global_start (void)
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

  setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (int));

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

  success ("server: ready. Listening to port '%d'.\n", PORT);
}

void
global_stop (void)
{
  success ("global stop\n");

  gnutls_anon_free_server_credentials (anoncred);

  gnutls_dh_params_deinit (dh_params);

  gnutls_global_deinit ();
}

void
server (void)
{
  /* this must be called once in the program, it is mostly for the server.
   */
  gnutls_global_init ();

  gnutls_anon_allocate_server_credentials (&anoncred);

  success ("Launched, generating DH parameters...\n");

  generate_dh_params ();

  gnutls_anon_set_server_dh_params (anoncred, dh_params);

  if (TLS_SESSION_CACHE != 0)
    {
      wrap_db_init ();
    }

  int t;

  for (t = 0; t < 2; t++)
    {
      client_len = sizeof (sa_cli);

      session = initialize_tls_session ();

      sd = accept (listen_sd, (SA *) & sa_cli, &client_len);

      success ("server: connection from %s, port %d\n",
	       inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf,
			  sizeof (topbuf)), ntohs (sa_cli.sin_port));

      gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
      ret = gnutls_handshake (session);
      if (ret < 0)
	{
	  close (sd);
	  gnutls_deinit (session);
	  fail ("server: Handshake has failed (%s)\n\n",
		gnutls_strerror (ret));
	  return;
	}
      success ("server: Handshake was completed\n");

      /* see the Getting peer's information example */
      /* print_info(session); */

      i = 0;
      for (;;)
	{
	  bzero (buffer, MAX_BUF + 1);
	  ret = gnutls_record_recv (session, buffer, MAX_BUF);

	  if (ret == 0)
	    {
	      success ("server: Peer has closed the GNUTLS connection\n");
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
    }

  close (listen_sd);

  if (TLS_SESSION_CACHE != 0)
    {
      wrap_db_deinit ();
    }

  success ("server: finished\n");
}

void
doit (void)
{
  pid_t child;

  global_start ();
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

  global_stop ();
}

/* Functions and other stuff needed for session resuming.
 * This is done using a very simple list which holds session ids
 * and session data.
 */

#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

typedef struct
{
  unsigned char session_id[MAX_SESSION_ID_SIZE];
  unsigned int session_id_size;

  char session_data[MAX_SESSION_DATA_SIZE];
  int session_data_size;
} CACHE;

static CACHE *cache_db;
static int cache_db_ptr = 0;

static void
wrap_db_init (void)
{

  /* allocate cache_db */
  cache_db = calloc (1, TLS_SESSION_CACHE * sizeof (CACHE));
}

static void
wrap_db_deinit (void)
{
  if (cache_db)
    free (cache_db);
  cache_db = NULL;
  return;
}

static int
wrap_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data)
{
  success ("resume db storing... (%d-%d)\n", key.size, data.size);

  if (debug)
    {
      unsigned int i;
      printf ("key:\n");
      for (i = 0; i < key.size; i++)
	{
	  printf ("%02x ", key.data[i] & 0xFF);
	  if ((i + 1) % 16 == 0)
	    printf ("\n");
	}
      printf ("\n");
      printf ("data:\n");
      for (i = 0; i < data.size; i++)
	{
	  printf ("%02x ", data.data[i] & 0xFF);
	  if ((i + 1) % 16 == 0)
	    printf ("\n");
	}
      printf ("\n");
    }

  if (cache_db == NULL)
    return -1;

  if (key.size > MAX_SESSION_ID_SIZE)
    return -1;
  if (data.size > MAX_SESSION_DATA_SIZE)
    return -1;

  memcpy (cache_db[cache_db_ptr].session_id, key.data, key.size);
  cache_db[cache_db_ptr].session_id_size = key.size;

  memcpy (cache_db[cache_db_ptr].session_data, data.data, data.size);
  cache_db[cache_db_ptr].session_data_size = data.size;

  cache_db_ptr++;
  cache_db_ptr %= TLS_SESSION_CACHE;

  return 0;
}

static gnutls_datum_t
wrap_db_fetch (void *dbf, gnutls_datum_t key)
{
  gnutls_datum_t res = { NULL, 0 };
  int i;

  success ("resume db fetch... (%d)\n", key.size);
  if (debug)
    {
      unsigned int i;
      printf ("key:\n");
      for (i = 0; i < key.size; i++)
	{
	  printf ("%02x ", key.data[i] & 0xFF);
	  if ((i + 1) % 16 == 0)
	    printf ("\n");
	}
      printf ("\n");
    }

  if (cache_db == NULL)
    return res;

  for (i = 0; i < TLS_SESSION_CACHE; i++)
    {
      if (key.size == cache_db[i].session_id_size &&
	  memcmp (key.data, cache_db[i].session_id, key.size) == 0)
	{
	  success ("resume db fetch... return info\n");

	  res.size = cache_db[i].session_data_size;

	  res.data = gnutls_malloc (res.size);
	  if (res.data == NULL)
	    return res;

	  memcpy (res.data, cache_db[i].session_data, res.size);

	  if (debug)
	    {
	      unsigned int i;
	      printf ("data:\n");
	      for (i = 0; i < res.size; i++)
		{
		  printf ("%02x ", res.data[i] & 0xFF);
		  if ((i + 1) % 16 == 0)
		    printf ("\n");
		}
	      printf ("\n");
	    }

	  return res;
	}
    }
  return res;
}

static int
wrap_db_delete (void *dbf, gnutls_datum_t key)
{
  int i;

  if (cache_db == NULL)
    return -1;

  for (i = 0; i < TLS_SESSION_CACHE; i++)
    {
      if (key.size == cache_db[i].session_id_size &&
	  memcmp (key.data, cache_db[i].session_id, key.size) == 0)
	{

	  cache_db[i].session_id_size = 0;
	  cache_db[i].session_data_size = 0;

	  return 0;
	}
    }

  return -1;

}
