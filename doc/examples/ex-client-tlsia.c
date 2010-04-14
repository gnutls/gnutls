/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>

/* A basic TLS client, with anonymous authentication and TLS/IA handshake.
 */

#define MAX_BUF 1024
#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int tcp_connect (void);
extern void tcp_close (int sd);

static int
client_avp (gnutls_session_t session, void *ptr,
	    const char *last, size_t lastlen, char **new, size_t * newlen)
{

  if (last)
    printf ("- received %d bytes AVP: `%.*s'\n",
	    (int) lastlen, (int) lastlen, last);
  else
    printf ("- new application phase\n");

  *new = gnutls_strdup ("client avp");
  if (!*new)
    return -1;
  *newlen = strlen (*new);

  printf ("- sending %d bytes AVP: `%s'\n", (int) *newlen, *new);

  gnutls_ia_permute_inner_secret (session, 3, "foo");

  return 0;

}

int
main (void)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  gnutls_anon_client_credentials_t anoncred;
  gnutls_ia_client_credentials_t iacred;
  /* Need to enable anonymous KX specifically. */

  gnutls_global_init ();

  gnutls_anon_allocate_client_credentials (&anoncred);
  gnutls_ia_allocate_client_credentials (&iacred);

  /* Set TLS/IA stuff
   */
  gnutls_ia_set_client_avp_function (iacred, client_avp);

  /* Initialize TLS session 
   */
  gnutls_init (&session, GNUTLS_CLIENT);

  /* Use default priorities */
  gnutls_priority_set_direct (session, "NORMAL:+ANON-DH", NULL);

  /* put the anonymous and TLS/IA credentials to the current session
   */
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);
  gnutls_credentials_set (session, GNUTLS_CRD_IA, iacred);

  /* connect to the peer
   */
  sd = tcp_connect ();

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  /* Perform the TLS handshake
   */
  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      fprintf (stderr, "*** Handshake failed\n");
      gnutls_perror (ret);
      goto end;
    }
  else
    {
      printf ("- Handshake was completed\n");
    }

  if (!gnutls_ia_handshake_p (session))
    {
      fprintf (stderr, "*** TLS/IA not negotiated...\n");
      goto end;
    }
  else
    {
      printf ("- Starting TLS/IA handshake...\n");

      ret = gnutls_ia_handshake (session);

      if (ret < 0)
	{
	  fprintf (stderr, "*** TLS/IA handshake failed\n");
	  gnutls_perror (ret);
	  goto end;
	}
      else
	{
	  printf ("- TLS/IA Handshake was completed\n");
	}
    }


  gnutls_record_send (session, MSG, strlen (MSG));

  ret = gnutls_record_recv (session, buffer, MAX_BUF);
  if (ret == 0)
    {
      printf ("- Peer has closed the TLS connection\n");
      goto end;
    }
  else if (ret < 0)
    {
      fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
      goto end;
    }

  printf ("- Received %d bytes: ", ret);
  for (ii = 0; ii < ret; ii++)
    {
      fputc (buffer[ii], stdout);
    }
  fputs ("\n", stdout);

  gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:

  tcp_close (sd);

  gnutls_deinit (session);

  gnutls_ia_free_client_credentials (iacred);
  gnutls_anon_free_client_credentials (anoncred);

  gnutls_global_deinit ();

  return 0;
}
