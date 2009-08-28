/** t-openpgp.c -- OpenPGP regression test **/

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_mpi.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "auth_cert.h"
#include "gnutls_openpgp.h"

#include <gnutls_str.h>
#include <stdio.h>
#include <gcrypt.h>
#include <time.h>
#include <assert.h>

static const char *
get_pkalgo (int algo)
{
  switch (algo)
    {
    case GNUTLS_PK_DSA:
      return "DSA";
    case GNUTLS_PK_RSA:
      return "RSA";
    }
  return NULL;
}

static const char *
get_pktime (long timestamp)
{
  static char buf[128];
  struct tm *tb;

  tb = localtime (&timestamp);
  sprintf (buf, "%04d-%02d-%02d", tb->tm_year + 1900, tb->tm_mon + 1,
	   tb->tm_mday);
  return buf;
}

int
get_pubkey (gnutls_datum_t * pk, const gnutls_datum_t * kr, unsigned long kid)
{
  unsigned char buf[4];

  buf[0] = kid >> 24;
  buf[1] = kid >> 16;
  buf[2] = kid >> 8;
  buf[3] = kid;
  return gnutls_openpgp_get_key (pk, kr, KEY_ATTR_SHORT_KEYID, buf);
}


int
main (int argc, char **argv)
{
  gnutls_certificate_credentials ctx;
  gnutls_datum_t dat, xml, pk;
  gnutls_openpgp_name uid;
  gnutls_privkey *pkey;
  gnutls_cert *cert;
  unsigned char fpr[20], keyid[8];
  char *s, *t;
  size_t fprlen = 0;
  int rc, nbits = 0, i;

  rc = gnutls_certificate_allocate_credentials (&ctx);
  assert (rc == 0);

  s = "../doc/credentials/openpgp/cli_ring.gpg";
  rc = gnutls_certificate_set_openpgp_keyring_file (ctx, s);
  assert (rc == 0);

  s = "../doc/credentials/openpgp/pub.asc";
  t = "../doc/credentials/openpgp/sec.asc";
  rc = gnutls_certificate_set_openpgp_key_file (ctx, s, t);
  assert (rc == 0);

  dat = ctx->cert_list[0]->raw;
  assert (ctx->cert_list[0]);
  printf ("Key v%d\n", gnutls_openpgp_extract_key_version (&dat));
  rc = gnutls_openpgp_extract_key_name (&dat, 1, &uid);
  assert (rc == 0);
  printf ("userID    %s\n", uid.name);

  rc = gnutls_openpgp_extract_key_pk_algorithm (&dat, &nbits);
  printf ("pk-algorithm %s %d bits\n", get_pkalgo (rc), nbits);

  rc = gnutls_openpgp_extract_key_creation_time (&dat);
  printf ("creation time %s\n", get_pktime (rc));

  rc = gnutls_openpgp_extract_key_expiration_time (&dat);
  printf ("expiration time %lu\n", rc);

  printf ("key fingerprint: ");
  rc = gnutls_openpgp_fingerprint (&dat, fpr, &fprlen);
  assert (rc == 0);
  for (i = 0; i < fprlen / 2; i++)
    printf ("%02X%02X ", fpr[2 * i], fpr[2 * i + 1]);
  printf ("\n");

  printf ("key id: ");
  rc = gnutls_openpgp_extract_key_id (&dat, keyid);
  assert (rc == 0);
  for (i = 0; i < 8; i++)
    printf ("%02X", keyid[i]);
  printf ("\n\n");

  printf ("Check MPIs\n");
  cert = ctx->cert_list[0];
  printf ("number of certs %d\n", *ctx->cert_list_length);
  assert (*ctx->cert_list_length == 1);
  printf ("number of items %d\n", cert->params_size);
  for (i = 0; i < cert->params_size; i++)
    {
      nbits = gcry_mpi_get_nbits (cert->params[i]);
      printf ("mpi %d %d bits\n", i, nbits);
    }

  printf ("\nCheck key\n");
  rc = gnutls_openpgp_verify_key (NULL, &ctx->keyring, &dat, 1);
  printf ("certifiacte status...%d\n", rc);

  printf ("\nSeckey\n");
  pkey = ctx->pkey;
  assert (pkey);
  assert (pkey->params_size);
  nbits = gcry_mpi_get_nbits (pkey->params[0]);
  rc = pkey->pk_algorithm;
  printf ("pk-algorithm %s %d bits\n", get_pkalgo (rc), nbits);
  printf ("number of items %d\n", pkey->params_size);
  for (i = 0; i < pkey->params_size; i++)
    {
      nbits = gcry_mpi_get_nbits (pkey->params[i]);
      printf ("mpi %d %d bits\n", i, nbits);
    }

  printf ("\nGet public key\n");
  rc = get_pubkey (&pk, &ctx->keyring, 0xA7D93C3F);
  assert (rc == 0);

  printf ("key fingerprint: ");
  gnutls_openpgp_fingerprint (&pk, fpr, &fprlen);
  for (i = 0; i < fprlen / 2; i++)
    printf ("%02X%02X ", fpr[2 * i], fpr[2 * i + 1]);
  printf ("\n");
  _gnutls_free_datum (&pk);

#if 0
  rc = gnutls_openpgp_key_to_xml (&dat, &xml, 1);
  printf ("rc=%d\n", rc);
  assert (rc == 0);
  xml.data[xml.size] = '\0';
  printf ("%s\n", xml.data);
  _gnutls_free_datum (&xml);
#endif

  _gnutls_free_datum (&dat);
  gnutls_certificate_free_credentials (ctx);

  return 0;
}
