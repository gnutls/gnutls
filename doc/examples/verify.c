#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "examples.h"

int verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  int ret, type;
  const char *hostname;
  gnutls_datum_t out;

  /* read hostname */
  hostname = gnutls_session_get_ptr (session);

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers3 (session, hostname, &status);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  type = gnutls_certificate_type_get (session);

  ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  
  printf ("%s", out.data);
  
  gnutls_free(out.data);

  if (status != 0) /* Certificate is not trusted */
      return GNUTLS_E_CERTIFICATE_ERROR;

  /* notify gnutls to continue handshake normally */
  return 0;
}
