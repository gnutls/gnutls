/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson, Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

/* Functions for printing X.509 Certificate structures
 */

#include <gnutls_int.h>
#include <gnutls/openpgp.h>
#include <gnutls_errors.h>

/* I18n of error codes. */
#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)
#define N_(String) gettext_noop (String)

#define addf _gnutls_string_append_printf
#define adds _gnutls_string_append_str

static void
hexdump (gnutls_string * str, const char *data, size_t len, const char *spc)
{
  size_t j;

  if (spc)
    adds (str, spc);
  for (j = 0; j < len; j++)
    {
      if (((j + 1) % 16) == 0)
	{
	  addf (str, "%.2x\n", (unsigned char) data[j]);
	  if (spc && j != (len - 1))
	    adds (str, spc);
	}
      else if (j == (len - 1))
	addf (str, "%.2x", (unsigned char) data[j]);
      else
	addf (str, "%.2x:", (unsigned char) data[j]);
    }
  if ((j % 16) != 0)
    adds (str, "\n");
}

static void
hexprint (gnutls_string * str, const char *data, size_t len)
{
  size_t j;

  if (len == 0)
    adds (str, "00");
  else
    {
      for (j = 0; j < len; j++)
	addf (str, "%.2x", (unsigned char) data[j]);
    }
}


static void
asciiprint (gnutls_string * str, const char *data, size_t len)
{
  size_t j;

  for (j = 0; j < len; j++)
    if (isprint (data[j]))
      addf (str, "%c", (unsigned char) data[j]);
    else
      addf (str, ".");
}

static void
print_key_usage (gnutls_string * str, gnutls_openpgp_crt_t cert, unsigned int idx)
{
  unsigned int key_usage;
  int err;

  addf (str, _("\t\tKey Usage:\n"));


  if (idx == -1)
    err = gnutls_openpgp_crt_get_key_usage (cert, &key_usage);
  else
    err = gnutls_openpgp_crt_get_subkey_usage (cert, idx, &key_usage);
  if (err < 0)
    {
      addf (str, _("error: get_key_usage: %s\n"), gnutls_strerror (err));
      return;
    }

  if (key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE)
    addf (str, _("\t\t\tDigital signature.\n"));
  if (key_usage & GNUTLS_KEY_NON_REPUDIATION)
    addf (str, _("\t\t\tNon repudiation.\n"));
  if (key_usage & GNUTLS_KEY_KEY_ENCIPHERMENT)
    addf (str, _("\t\t\tKey encipherment.\n"));
  if (key_usage & GNUTLS_KEY_DATA_ENCIPHERMENT)
    addf (str, _("\t\t\tData encipherment.\n"));
  if (key_usage & GNUTLS_KEY_KEY_AGREEMENT)
    addf (str, _("\t\t\tKey agreement.\n"));
  if (key_usage & GNUTLS_KEY_KEY_CERT_SIGN)
    addf (str, _("\t\t\tCertificate signing.\n"));
  if (key_usage & GNUTLS_KEY_CRL_SIGN)
    addf (str, _("\t\t\tCRL signing.\n"));
  if (key_usage & GNUTLS_KEY_ENCIPHER_ONLY)
    addf (str, _("\t\t\tKey encipher only.\n"));
  if (key_usage & GNUTLS_KEY_DECIPHER_ONLY)
    addf (str, _("\t\t\tKey decipher only.\n"));
}

/* idx == -1 indicates main key
 * otherwise the subkey.
 */
static void
print_key_id (gnutls_string * str, gnutls_openpgp_crt_t cert, int idx)
{
    gnutls_openpgp_keyid_t id;
    int err;

    if (idx < 0)
      err = gnutls_openpgp_crt_get_id (cert, &id);
    else
      err = gnutls_openpgp_crt_get_subkey_id( cert, idx, &id);

    if (err < 0)
      addf (str, "error: get_id: %s\n", gnutls_strerror (err));
    else
      {
	addf (str, _("\tID (hex): "));
	hexprint (str, id.keyid, sizeof(id.keyid));
	addf (str, "\n");
      }
}

/* idx == -1 indicates main key
 * otherwise the subkey.
 */
static void
print_key_fingerprint (gnutls_string * str, gnutls_openpgp_crt_t cert)
{
    char fpr[128];
    size_t fpr_size = sizeof (fpr);
    int err;

    err = gnutls_openpgp_crt_get_fingerprint (cert, fpr, &fpr_size);
    if (err < 0)
      addf (str, "error: get_fingerprint: %s\n", gnutls_strerror (err));
    else
      {
	addf (str, _("\tFingerprint (hex): "));
	hexprint (str, fpr, fpr_size);
	addf (str, "\n");
      }
}

static void
print_key_revoked (gnutls_string * str, gnutls_openpgp_crt_t cert, int idx)
{
    char fpr[128];
    size_t fpr_size = sizeof (fpr);
    int err;

    if (idx < 0)
      err = gnutls_openpgp_crt_get_revoked_status (cert);
    else
      err = gnutls_openpgp_crt_get_subkey_revoked_status( cert, idx);

    if (err != 0)
      addf (str, "Revoked: True");
}

static void
print_key_times(gnutls_string * str, gnutls_openpgp_crt_t cert, int idx)
{
    time_t tim;

    addf (str, _("\tTime stamps:\n"));

    if (idx == -1)
      tim = gnutls_openpgp_crt_get_creation_time (cert);
    else
      tim = gnutls_openpgp_crt_get_subkey_creation_time (cert, idx);
      
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "error: gmtime_r (%d)\n", t);
      else if (strftime (s, max, "%a %b %e %H:%M:%S UTC %Y", &t) == 0)
	addf (str, "error: strftime (%d)\n", t);
      else
	addf (str, _("\t\tCreation: %s\n"), s);
    }

    if (idx == -1)
      tim = gnutls_openpgp_crt_get_expiration_time (cert);
    else
      tim = gnutls_openpgp_crt_get_subkey_expiration_time (cert, idx);
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "error: gmtime_r (%d)\n", t);
      else if (strftime (s, max, "%a %b %e %H:%M:%S UTC %Y", &t) == 0)
	addf (str, "error: strftime (%d)\n", t);
      else
	addf (str, _("\t\tExpiration: %s\n"), s);
    }
}

static void
print_key_info(gnutls_string * str, gnutls_openpgp_crt_t cert, int idx)
{
    int err;
    unsigned int bits;

    if (idx == -1)
      err = gnutls_openpgp_crt_get_pk_algorithm (cert, &bits);
    else
      err = gnutls_openpgp_crt_get_subkey_pk_algorithm (cert, idx, &bits);

    if (err < 0)
      addf (str, "error: get_pk_algorithm: %s\n", gnutls_strerror (err));
    else
      {
	const char *name = gnutls_pk_algorithm_get_name (err);
	if (name == NULL)
	  name = "Unknown";

	addf (str, _("\tPublic Key Algorithm: %s\n"), name);
#if 0
	switch (err)
	  {
	  case GNUTLS_PK_RSA:
	    {
	      gnutls_datum_t m, e;

	      err = gnutls_openpgp_crt_get_pk_rsa_raw (cert, &m, &e);
	      if (err < 0)
		addf (str, "error: get_pk_rsa_raw: %s\n",
		      gnutls_strerror (err));
	      else
		{
		  addf (str, _("\t\tModulus (bits %d):\n"), bits);
		  hexdump (str, m.data, m.size, "\t\t\t");
		  addf (str, _("\t\tExponent:\n"));
		  hexdump (str, e.data, e.size, "\t\t\t");
		}

	      gnutls_free (m.data);
	      gnutls_free (e.data);
	    }
	    break;

	  case GNUTLS_PK_DSA:
	    {
	      gnutls_datum_t p, q, g, y;

	      err = gnutls_openpgp_crt_get_pk_dsa_raw (cert, &p, &q, &g, &y);
	      if (err < 0)
		addf (str, "error: get_pk_dsa_raw: %s\n",
		      gnutls_strerror (err));
	      else
		{
		  addf (str, _("\t\tPublic key (bits %d):\n"), bits);
		  hexdump (str, y.data, y.size, "\t\t\t");
		  addf (str, _("\t\tP:\n"));
		  hexdump (str, p.data, p.size, "\t\t\t");
		  addf (str, _("\t\tQ:\n"));
		  hexdump (str, q.data, q.size, "\t\t\t");
		  addf (str, _("\t\tG:\n"));
		  hexdump (str, g.data, g.size, "\t\t\t");
		}
	    }
	    break;

	  default:
	    break;
	  }
#endif
      }
}


static void
print_cert (gnutls_string * str, gnutls_openpgp_crt_t cert, unsigned int format)
{
int i, subkeys;
int err;
char dn[1024];
size_t dn_size = sizeof (dn);

  /* Version. */
  {
    int version = gnutls_openpgp_crt_get_version (cert);
    if (version < 0)
      addf (str, "error: get_version: %s\n", gnutls_strerror (version));
    else
      addf (str, _("\tVersion: %d\n"), version);
  }

  /* ID. */
  print_key_id( str, cert, -1);

  print_key_fingerprint( str, cert);

  /* Names. */
  i = 0;
  do {

      err = gnutls_openpgp_crt_get_name (cert, i++, dn, &dn_size);

      if (err < 0 && err != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
	addf (str, "error: get_name: %s\n", gnutls_strerror (err));
	break;
      }

      if (err > 0)
	addf (str, _("\tName[%d]: %s\n"), i, dn);

  } while( err > 0);

  print_key_times( str, cert, -1);

  print_key_info( str, cert, -1);
  print_key_usage( str, cert, -1);
  print_key_revoked( str, cert, -1);

  subkeys = gnutls_openpgp_crt_get_subkey_count( cert);
  if (subkeys < 0)
    return;
    
  for (i=0;i<subkeys;i++) {
    addf( str, _("\n\tSubkey[%d]:\n"), i);
    
    print_key_id( str, cert, i);
    print_key_times( str, cert, i);
    print_key_info( str, cert, i);
    print_key_usage( str, cert, i);
    print_key_revoked( str, cert, i);
  }

}

/**
 * gnutls_openpgp_crt_print - Pretty print OpenPGP certificates
 * @cert: The structure to be printed
 * @format: Indicate the format to use
 * @out: Newly allocated datum with zero terminated string.
 *
 * This function will pretty print an OpenPGP certificate, suitable for
 * display to a human.
 *
 * The format should be zero for future compatibility.
 *
 * The output @out needs to be deallocate using gnutls_free().
 *
 * Returns 0 on success.
 **/
int
gnutls_openpgp_crt_print (gnutls_openpgp_crt_t cert,
		       gnutls_certificate_print_formats_t format,
		       gnutls_datum_t *out)
{
  gnutls_string str;

  _gnutls_string_init (&str, gnutls_malloc, gnutls_realloc, gnutls_free);

  _gnutls_string_append_str (&str, _("OpenPGP Certificate Information:\n"));

  print_cert (&str, cert, format);

  _gnutls_string_append_data (&str, "\0", 1);
  out->data = str.data;
  out->size = strlen (str.data);

  return 0;
}

