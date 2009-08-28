#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/x509.h>

#define MAX_FILE_SIZE 16*1024

struct file_res
{
  char *test_file;
  int result;
};

static struct file_res test_files[] = {
  {"test1.pem", 0},
  {"test2.pem", GNUTLS_CERT_NOT_TRUSTED},
  {"test3.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED},
  {"test10.pem", 0},
  {"test13.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED},
  {"test20.pem", GNUTLS_CERT_REVOKED | GNUTLS_CERT_NOT_TRUSTED},
  {"test21.pem", GNUTLS_CERT_REVOKED | GNUTLS_CERT_NOT_TRUSTED},
  {"test22.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED},
  {"test23.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED},
  {"test24.pem", 0},
  {"test25.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED},
  {"test26.pem", 0},
  {NULL, 0}
};

#define CA_FILE "ca.pem"

int _verify_x509_file (const char *certfile, const char *cafile);


static void
print_res (int x)
{
  if (x & GNUTLS_CERT_INVALID)
    printf ("- certificate is invalid\n");
  else
    printf ("- certificate is valid\n");
  if (x & GNUTLS_CERT_NOT_TRUSTED)
    printf ("- certificate is NOT trusted\n");
  else
    printf ("- certificate is trusted\n");

  if (x & GNUTLS_CERT_CORRUPTED)
    printf ("- Found a corrupted certificate.\n");

  if (x & GNUTLS_CERT_REVOKED)
    printf ("- certificate is revoked.\n");
}

int
main ()
{

  int x;
  char *file;
  int i = 0, exp_result;

  gnutls_global_init ();

  fprintf (stderr,
	   "This test will perform some checks on X.509 certificate\n");
  fprintf (stderr, "verification functions.\n\n");

  for (;;)
    {
      exp_result = test_files[i].result;
      file = test_files[i++].test_file;

      if (file == NULL)
	break;
      x = _verify_x509_file (file, CA_FILE);

      if (x < 0)
	{
	  fprintf (stderr, "Unexpected error: %d\n", x);
	  exit (1);
	}
      printf ("Test %d, file %s: ", i, file);

      if (x != exp_result)
	{
	  printf ("failed.\n");
	  fflush (stdout);
	  fprintf (stderr, "Unexpected error in verification.\n");
	  fprintf (stderr, "Certificate was found to be: \n");
	  print_res (x);
	}
      else
	{
	  printf ("ok.");

	  printf ("\n");
	}
    }

  printf ("\n");

  gnutls_global_deinit ();

  return 0;

}

#define CERT_SEP "-----BEGIN CERT"
#define CRL_SEP "-----BEGIN X509 CRL"

/* Verifies a base64 encoded certificate list from memory 
 */
int
_verify_x509_mem (const char *cert, int cert_size,
		  const char *ca, int ca_size, const char *crl, int crl_size)
{
  int siz, i;
  const char *ptr;
  int ret;
  unsigned int output;
  gnutls_datum_t tmp;
  gnutls_x509_crt *x509_cert_list = NULL;
  gnutls_x509_crt x509_ca;
  gnutls_x509_crl *x509_crl_list = NULL;
  int x509_ncerts, x509_ncrls;

  /* Decode the CA certificate
   */
  tmp.data = (char *) ca;
  tmp.size = ca_size;

  ret = gnutls_x509_crt_init (&x509_ca);
  if (ret < 0)
    {
      fprintf (stderr, "Error parsing the CA certificate: %s\n",
	       gnutls_strerror (ret));
      exit (1);
    }

  ret = gnutls_x509_crt_import (x509_ca, &tmp, GNUTLS_X509_FMT_PEM);

  if (ret < 0)
    {
      fprintf (stderr, "Error parsing the CA certificate: %s\n",
	       gnutls_strerror (ret));
      exit (1);
    }

  /* Decode the CRL list
   */
  siz = crl_size;
  ptr = crl;

  i = 1;

  if (strstr (ptr, CRL_SEP) != NULL)	/* if CRLs exist */
    do
      {
	x509_crl_list =
	  (gnutls_x509_crl *) realloc (x509_crl_list,
				       i * sizeof (gnutls_x509_crl));
	if (x509_crl_list == NULL)
	  {
	    fprintf (stderr, "memory error\n");
	    exit (1);
	  }

	tmp.data = (char *) ptr;
	tmp.size = siz;

	ret = gnutls_x509_crl_init (&x509_crl_list[i - 1]);
	if (ret < 0)
	  {
	    fprintf (stderr, "Error parsing the CRL[%d]: %s\n", i,
		     gnutls_strerror (ret));
	    exit (1);
	  }

	ret =
	  gnutls_x509_crl_import (x509_crl_list[i - 1], &tmp,
				  GNUTLS_X509_FMT_PEM);
	if (ret < 0)
	  {
	    fprintf (stderr, "Error parsing the CRL[%d]: %s\n", i,
		     gnutls_strerror (ret));
	    exit (1);
	  }

	/* now we move ptr after the pem header */
	ptr = strstr (ptr, CRL_SEP);
	if (ptr != NULL)
	  ptr++;

	i++;
      }
    while ((ptr = strstr (ptr, CRL_SEP)) != NULL);

  x509_ncrls = i - 1;


  /* Decode the certificate chain. 
   */
  siz = cert_size;
  ptr = cert;

  i = 1;

  do
    {
      x509_cert_list =
	(gnutls_x509_crt *) realloc (x509_cert_list,
				     i * sizeof (gnutls_x509_crt));
      if (x509_cert_list == NULL)
	{
	  fprintf (stderr, "memory error\n");
	  exit (1);
	}

      tmp.data = (char *) ptr;
      tmp.size = siz;

      ret = gnutls_x509_crt_init (&x509_cert_list[i - 1]);
      if (ret < 0)
	{
	  fprintf (stderr, "Error parsing the certificate[%d]: %s\n", i,
		   gnutls_strerror (ret));
	  exit (1);
	}

      ret =
	gnutls_x509_crt_import (x509_cert_list[i - 1], &tmp,
				GNUTLS_X509_FMT_PEM);
      if (ret < 0)
	{
	  fprintf (stderr, "Error parsing the certificate[%d]: %s\n", i,
		   gnutls_strerror (ret));
	  exit (1);
	}

      /* now we move ptr after the pem header */
      ptr = strstr (ptr, CERT_SEP);
      if (ptr != NULL)
	ptr++;

      i++;
    }
  while ((ptr = strstr (ptr, CERT_SEP)) != NULL);

  x509_ncerts = i - 1;

  ret = gnutls_x509_crt_list_verify (x509_cert_list, x509_ncerts,
				     &x509_ca, 1, x509_crl_list, x509_ncrls,
				     0, &output);

  gnutls_x509_crt_deinit (x509_ca);

  for (i = 0; i < x509_ncerts; i++)
    {
      gnutls_x509_crt_deinit (x509_cert_list[i]);
    }

  for (i = 0; i < x509_ncrls; i++)
    {
      gnutls_x509_crl_deinit (x509_crl_list[i]);
    }

  free (x509_cert_list);
  free (x509_crl_list);

  if (ret < 0)
    {
      fprintf (stderr, "Error in verification: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return output;
}



/* Reads and verifies a base64 encoded certificate file 
 */
int
_verify_x509_file (const char *certfile, const char *cafile)
{
  int ca_size, cert_size;
  char ca[MAX_FILE_SIZE];
  char cert[MAX_FILE_SIZE];
  FILE *fd1;

  fd1 = fopen (certfile, "rb");
  if (fd1 == NULL)
    {
      fprintf (stderr, "error opening %s\n", certfile);
      return GNUTLS_E_FILE_ERROR;
    }

  cert_size = fread (cert, 1, sizeof (cert) - 1, fd1);
  fclose (fd1);

  cert[cert_size] = 0;


  fd1 = fopen (cafile, "rb");
  if (fd1 == NULL)
    {
      fprintf (stderr, "error opening %s\n", cafile);
      return GNUTLS_E_FILE_ERROR;
    }

  ca_size = fread (ca, 1, sizeof (ca) - 1, fd1);
  fclose (fd1);

  ca[ca_size] = 0;

  return _verify_x509_mem (cert, cert_size, ca, ca_size, cert, cert_size);
}
