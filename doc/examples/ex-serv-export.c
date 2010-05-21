/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"
#define CAFILE "ca.pem"
#define CRLFILE "crl.pem"

/* This is a sample TLS 1.0 echo server.
 * Export-grade ciphersuites and session resuming are supported.
 */

#define SA struct sockaddr
#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024
#define PORT 5556		/* listen to 5556 port */
#define DH_BITS 1024

/* These are global */
gnutls_certificate_credentials_t cert_cred;

static void wrap_db_init (void);
static void wrap_db_deinit (void);
static int wrap_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data);
static gnutls_datum_t wrap_db_fetch (void *dbf, gnutls_datum_t key);
static int wrap_db_delete (void *dbf, gnutls_datum_t key);

#define TLS_SESSION_CACHE 50

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  /* Use the default priorities, plus, export cipher suites.
   */
  gnutls_priority_set_direct (session, "EXPORT", NULL);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, cert_cred);

  /* request client certificate if any.
   */
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

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

gnutls_dh_params_t dh_params;
/* Export-grade cipher suites require temporary RSA
 * keys.
 */
gnutls_rsa_params_t rsa_params;

static char srp_dh_group2048[] =
  "-----BEGIN DH PARAMETERS-----\n"
  "MIIBBwKCAQCsa9tBMkqam/Fm3l4TiVgvr3K2ZRmH7gf8MZKUPbVgUKNzKcu0oJnt\n"
  "gZPgdXdnoT3VIxKrSwMxDc1/SKnaBP1Q6Ag5ae23Z7DPYJUXmhY6s2YaBfvV+qro\n"
  "KRipli8Lk7hV+XmT7Jde6qgNdArb9P90c1nQQdXDPqcdKB5EaxR3O8qXtDoj+4AW\n"
  "dr0gekNsZIHx0rkHhxdGGludMuaI+HdIVEUjtSSw1X1ep3onddLs+gMs+9v1L7N4\n"
  "YWAnkATleuavh05zA85TKZzMBBx7wwjYKlaY86jQw4JxrjX46dv7tpS1yAPYn3rk\n"
  "Nd4jbVJfVHWbZeNy/NaO8g+nER+eSv9zAgEC\n" "-----END DH PARAMETERS-----\n";

static int
generate_dh_params (void)
{
  gnutls_datum_t dparams = { srp_dh_group2048, sizeof (srp_dh_group2048) };
  /* Here instead of generating Diffie-Hellman parameters (for use with DHE
   * kx algorithms) we import them.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_import_pkcs3 (dh_params, &dparams, GNUTLS_X509_FMT_PEM);

  return 0;
}

static int
generate_rsa_params (void)
{
  gnutls_rsa_params_init (&rsa_params);

  /* Generate RSA parameters - for use with RSA-export
   * cipher suites. This is an RSA private key and should be 
   * discarded and regenerated once a day, once every 500 
   * transactions etc. Depends on the security requirements.
   */

  gnutls_rsa_params_generate2 (rsa_params, 512);

  return 0;
}

int
main (void)
{
  int err, listen_sd;
  int sd, ret;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  int client_len;
  char topbuf[512];
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  int optval = 1;
  char name[256];

  strcpy (name, "Echo Server");

  /* this must be called once in the program
   */
  gnutls_global_init ();


  gnutls_certificate_allocate_credentials (&cert_cred);

  gnutls_certificate_set_x509_trust_file (cert_cred, CAFILE,
					  GNUTLS_X509_FMT_PEM);

  gnutls_certificate_set_x509_crl_file (cert_cred, CRLFILE,
					GNUTLS_X509_FMT_PEM);

  gnutls_certificate_set_x509_key_file (cert_cred, CERTFILE, KEYFILE,
					GNUTLS_X509_FMT_PEM);

  generate_dh_params ();
  generate_rsa_params ();

  if (TLS_SESSION_CACHE != 0)
    {
      wrap_db_init ();
    }

  gnutls_certificate_set_dh_params (cert_cred, dh_params);
  gnutls_certificate_set_rsa_export_params (cert_cred, rsa_params);

  /* Socket operations
   */
  listen_sd = socket (AF_INET, SOCK_STREAM, 0);
  SOCKET_ERR (listen_sd, "socket");

  memset (&sa_serv, '\0', sizeof (sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons (PORT);	/* Server Port number */

  setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval,
	      sizeof (int));

  err = bind (listen_sd, (SA *) & sa_serv, sizeof (sa_serv));
  SOCKET_ERR (err, "bind");
  err = listen (listen_sd, 1024);
  SOCKET_ERR (err, "listen");

  printf ("%s ready. Listening to port '%d'.\n\n", name, PORT);

  client_len = sizeof (sa_cli);
  for (;;)
    {
      session = initialize_tls_session ();

      sd = accept (listen_sd, (SA *) & sa_cli, &client_len);

      printf ("- connection from %s, port %d\n",
	      inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf,
			 sizeof (topbuf)), ntohs (sa_cli.sin_port));

      gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
      ret = gnutls_handshake (session);
      if (ret < 0)
	{
	  close (sd);
	  gnutls_deinit (session);
	  fprintf (stderr, "*** Handshake has failed (%s)\n\n",
		   gnutls_strerror (ret));
	  continue;
	}
      printf ("- Handshake was completed\n");

      /* print_info(session); */

      for (;;)
	{
	  memset (buffer, 0, MAX_BUF + 1);
	  ret = gnutls_record_recv (session, buffer, MAX_BUF);

	  if (ret == 0)
	    {
	      printf ("\n- Peer has closed the TLS connection\n");
	      break;
	    }
	  else if (ret < 0)
	    {
	      fprintf (stderr, "\n*** Received corrupted "
		       "data(%d). Closing the connection.\n\n", ret);
	      break;
	    }
	  else if (ret > 0)
	    {
	      /* echo data back to the client
	       */
	      gnutls_record_send (session, buffer, strlen (buffer));
	    }
	}
      printf ("\n");
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

  gnutls_certificate_free_credentials (cert_cred);

  gnutls_global_deinit ();

  return 0;

}


/* Functions and other stuff needed for session resuming.
 * This is done using a very simple list which holds session ids
 * and session data.
 */

#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

typedef struct
{
  char session_id[MAX_SESSION_ID_SIZE];
  size_t session_id_size;

  char session_data[MAX_SESSION_DATA_SIZE];
  size_t session_data_size;
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
  free (cache_db);
  cache_db = NULL;
  return;
}

static int
wrap_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data)
{

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

  if (cache_db == NULL)
    return res;

  for (i = 0; i < TLS_SESSION_CACHE; i++)
    {
      if (key.size == cache_db[i].session_id_size &&
	  memcmp (key.data, cache_db[i].session_id, key.size) == 0)
	{


	  res.size = cache_db[i].session_data_size;

	  res.data = gnutls_malloc (res.size);
	  if (res.data == NULL)
	    return res;

	  memcpy (res.data, cache_db[i].session_data, res.size);

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
