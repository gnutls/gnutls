#include <stdio.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>

int
main (int argc, char *argv[])
{
  gnutls_certificate_credentials_t x509cred;
  char *file, *password;
  int ret;

  ret = gnutls_global_init ();
  if (ret < 0)
    return 1;

  ret = gnutls_certificate_allocate_credentials (&x509cred);
  if (ret < 0)
    return 1;

  file = getenv ("PKCS12FILE");
  password = getenv ("PKCS12PASSWORD");

  if (!file)
    file = "client.p12";
  if (!password)
    password = "foobar";

  printf ("Reading PKCS#12 blob from `%s' using password `%s'.\n",
	  file, password);
  ret = gnutls_certificate_set_x509_simple_pkcs12_file (x509cred,
							file,
							GNUTLS_X509_FMT_DER,
							password);
  if (ret < 0)
    {
      printf ("x509_pkcs12 (%d): %s\n", ret, gnutls_strerror (ret));
    }

  gnutls_certificate_free_credentials (x509cred);

  gnutls_global_deinit ();

  return 0;
}
