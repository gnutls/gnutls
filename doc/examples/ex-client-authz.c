#if HAVE_CONFIG_H
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

/* A basic TLS client, with X.509 authentication, and support for
   the authorization extension.
 */

#define MAX_BUF 1024
#define CAFILE "ca.pem"
#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int tcp_connect (void);
extern void tcp_close (int sd);

int server_authorized_p = 0;

int
authz_recv_callback (gnutls_session_t session,
		     const int *authz_formats,
		     gnutls_datum_t *infos,
		     const int *hashtypes,
		     gnutls_datum_t *hash)
{
  size_t i, j;

  /* This function receives authorization data. */

  for (i = 0; authz_formats[i]; i++)
    {
      printf ("- Received authorization data, format %02x of %d bytes\n",
	      authz_formats[i], infos[i].size);

      printf ("  data: ");
      for (j = 0; j < infos[i].size; j++)
	printf ("%02x", infos[i].data[j]);
      printf ("\n");

      if (hash[i].size > 0)
	{
	  printf (" hash: ");
	  for (j = 0; j < hash[i].size; j++)
	    printf ("%02x", hash[i].data[j]);
	  printf (" type %02x\n", hashtypes[i]);
	}
    }

  /* You would typically actually _validate_ the data here... if you
     need access to authentication details, store the authorization
     data and do the validation inside main(). */

  server_authorized_p = 1;

  return 0;
}

int
authz_send_callback (gnutls_session_t session,
		     const int *client_formats,
		     const int *server_formats)
{
  const char *str = "saml assertion";
  /* Send the authorization data here. client_formats and
     server_formats contains a list of negotiated authorization
     formats.  */
  return gnutls_authz_send_saml_assertion (session, str, sizeof (str));
}

int
main (void)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  gnutls_certificate_credentials_t xcred;
  const int authz_client_formats[] = {
    GNUTLS_AUTHZ_SAML_ASSERTION,
  };
  const int authz_server_formats[] = {
    GNUTLS_AUTHZ_X509_ATTR_CERT,
    GNUTLS_AUTHZ_SAML_ASSERTION,
    GNUTLS_AUTHZ_X509_ATTR_CERT_URL,
    GNUTLS_AUTHZ_SAML_ASSERTION_URL
  };

  gnutls_global_init ();

  /* X509 stuff */
  gnutls_certificate_allocate_credentials (&xcred);

  /* sets the trusted cas file
   */
  gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);

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
  sd = tcp_connect ();

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  gnutls_authz_enable (session, authz_client_formats, authz_server_formats,
		       authz_recv_callback, authz_send_callback);

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

  if (!server_authorized_p)
    {
      fprintf (stderr, "*** Not authorized, giving up...\n");
      ret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
			       GNUTLS_A_ACCESS_DENIED);
      if (ret < 0)
	{
	  gnutls_perror (ret);
	  goto end;
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

  gnutls_certificate_free_credentials (xcred);

  gnutls_global_deinit ();

  return 0;
}
