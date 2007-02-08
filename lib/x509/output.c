/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
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
#include <common.h>
#include <gnutls_x509.h>
#include <x509.h>
#include <gnutls_errors.h>

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

  for (j = 0; j < len; j++)
    addf (str, "%.2x", (unsigned char) data[j]);
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
print_proxy (gnutls_string * str, gnutls_x509_crt_t cert)
{
  int pathlen;
  char *policyLanguage;
  char *policy;
  size_t npolicy;
  int err;

  err = gnutls_x509_crt_get_proxy (cert, NULL,
				   &pathlen, &policyLanguage,
				   &policy, &npolicy);
  if (err < 0)
    {
      addf (str, "error: get proxy: %s\n", gnutls_strerror (err));
      return;
    }

  if (pathlen >= 0)
    addf (str, "\t\t\tPath Length Constraint: %d\n", pathlen);
  adds (str, "\t\t\tPolicy Language: ");
  if (strcmp (policyLanguage, "1.3.6.1.5.5.7.21.1") == 0)
    addf (str, "id-ppl-inheritALL\n");
  else if (strcmp (policyLanguage, "1.3.6.1.5.5.7.21.2") == 0)
    addf (str, "id-ppl-independent\n");
  else
    addf (str, "%s\n", policyLanguage);
  if (npolicy)
    addf (str, "\t\t\tPolicy Language: %.*s\n", npolicy, policy);
}

static void
print_ski (gnutls_string * str, gnutls_x509_crt_t cert)
{
  char *buffer = NULL;
  size_t size = 0;
  int err;

  err = gnutls_x509_crt_get_subject_key_id (cert, buffer, &size, NULL);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      addf (str, "error: get_subject_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  buffer = gnutls_malloc (size);
  if (!buffer)
    {
      addf (str, "error: malloc: %s\n", gnutls_strerror (err));
      return;
    }

  err = gnutls_x509_crt_get_subject_key_id (cert, buffer, &size, NULL);
  if (err < 0)
    {
      gnutls_free (buffer);
      addf (str, "error: get_subject_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  adds (str, "\t\t\t");
  hexprint (str, buffer, size);
  adds (str, "\n");

  gnutls_free (buffer);
}

static void
print_aki (gnutls_string * str, gnutls_x509_crt_t cert)
{
  char *buffer = NULL;
  size_t size = 0;
  int err;

  err = gnutls_x509_crt_get_authority_key_id (cert, buffer, &size, NULL);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      addf (str, "error: get_authority_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  buffer = gnutls_malloc (size);
  if (!buffer)
    {
      addf (str, "error: malloc: %s\n", gnutls_strerror (err));
      return;
    }

  err = gnutls_x509_crt_get_authority_key_id (cert, buffer, &size, NULL);
  if (err < 0)
    {
      gnutls_free (buffer);
      addf (str, "error: get_authority_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  adds (str, "\t\t\t");
  hexprint (str, buffer, size);
  adds (str, "\n");

  gnutls_free (buffer);
}

static void
print_key_usage (gnutls_string * str, gnutls_x509_crt_t cert)
{
  unsigned int key_usage;
  int err;

  err = gnutls_x509_crt_get_key_usage (cert, &key_usage, NULL);
  if (err < 0)
    {
      addf (str, "error: get_key_usage: %s\n", gnutls_strerror (err));
      return;
    }

  if (key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE)
    addf (str, "\t\t\tDigital signature.\n");
  if (key_usage & GNUTLS_KEY_NON_REPUDIATION)
    addf (str, "\t\t\tNon repudiation.\n");
  if (key_usage & GNUTLS_KEY_KEY_ENCIPHERMENT)
    addf (str, "\t\t\tKey encipherment.\n");
  if (key_usage & GNUTLS_KEY_DATA_ENCIPHERMENT)
    addf (str, "\t\t\tData encipherment.\n");
  if (key_usage & GNUTLS_KEY_KEY_AGREEMENT)
    addf (str, "\t\t\tKey agreement.\n");
  if (key_usage & GNUTLS_KEY_KEY_CERT_SIGN)
    addf (str, "\t\t\tCertificate signing.\n");
  if (key_usage & GNUTLS_KEY_CRL_SIGN)
    addf (str, "\t\t\tCRL signing.\n");
  if (key_usage & GNUTLS_KEY_ENCIPHER_ONLY)
    addf (str, "\t\t\tKey encipher only.\n");
  if (key_usage & GNUTLS_KEY_DECIPHER_ONLY)
    addf (str, "\t\t\tKey decipher only.\n");
}

static void
print_crldist (gnutls_string * str, gnutls_x509_crt_t cert)
{
  char *buffer;
  size_t size;
  int err;
  int indx;

  for (indx = 0;; indx++)
    {
      size = 0;
      err = gnutls_x509_crt_get_crl_dist_points (cert, indx, buffer, &size,
						 NULL, NULL);
      if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	return;
      if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
	{
	  addf (str, "error: get_crl_dist_points: %s\n",
		gnutls_strerror (err));
	  return;
	}

      buffer = gnutls_malloc (size);
      if (!buffer)
	{
	  addf (str, "error: malloc: %s\n", gnutls_strerror (err));
	  return;
	}

      err = gnutls_x509_crt_get_crl_dist_points (cert, indx, buffer, &size,
						 NULL, NULL);
      if (err < 0)
	{
	  gnutls_free (buffer);
	  addf (str, "error: get_crl_dist_points2: %s\n",
		gnutls_strerror (err));
	  return;
	}

      switch (err)
	{
	case GNUTLS_SAN_DNSNAME:
	  addf (str, "\t\t\tDNSname: %s\n", buffer);
	  break;

	case GNUTLS_SAN_RFC822NAME:
	  addf (str, "\t\t\tRFC822name: %s\n", buffer);
	  break;

	case GNUTLS_SAN_URI:
	  addf (str, "\t\t\tURI: %s\n", buffer);
	  break;

	case GNUTLS_SAN_IPADDRESS:
	  addf (str, "\t\t\tIPAddress: %s\n", buffer);
	  break;

	default:
	  addf (str, "error: unknown SAN\n");
	  break;
	}
      gnutls_free (buffer);
    }
}

static void
print_key_purpose (gnutls_string * str, gnutls_x509_crt_t cert)
{
  int indx;
  char *buffer;
  size_t size;
  int err;

  for (indx = 0;; indx++)
    {
      size = 0;
      err = gnutls_x509_crt_get_key_purpose_oid (cert, indx, buffer,
						 &size, NULL);
      if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	return;
      if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
	{
	  addf (str, "error: get_key_purpose: %s\n", gnutls_strerror (err));
	  return;
	}

      buffer = gnutls_malloc (size);
      if (!buffer)
	{
	  addf (str, "error: malloc: %s\n", gnutls_strerror (err));
	  return;
	}

      err = gnutls_x509_crt_get_key_purpose_oid (cert, indx, buffer,
						 &size, NULL);
      if (err < 0)
	{
	  gnutls_free (buffer);
	  addf (str, "error: get_key_purpose2: %s\n", gnutls_strerror (err));
	  return;
	}

      if (strcmp (buffer, GNUTLS_KP_TLS_WWW_SERVER) == 0)
	addf (str, "\t\t\tTLS WWW Server.\n");
      else if (strcmp (buffer, GNUTLS_KP_TLS_WWW_CLIENT) == 0)
	addf (str, "\t\t\tTLS WWW Client.\n");
      else if (strcmp (buffer, GNUTLS_KP_CODE_SIGNING) == 0)
	addf (str, "\t\t\tCode signing.\n");
      else if (strcmp (buffer, GNUTLS_KP_EMAIL_PROTECTION) == 0)
	addf (str, "\t\t\tEmail protection.\n");
      else if (strcmp (buffer, GNUTLS_KP_TIME_STAMPING) == 0)
	addf (str, "\t\t\tTime stamping.\n");
      else if (strcmp (buffer, GNUTLS_KP_OCSP_SIGNING) == 0)
	addf (str, "\t\t\tOCSP signing.\n");
      else if (strcmp (buffer, GNUTLS_KP_ANY) == 0)
	addf (str, "\t\t\tAny purpose.\n");
      else
	addf (str, "\t\t\t%s\n", buffer);

      gnutls_free (buffer);
    }
}

static void
print_basic (gnutls_string * str, gnutls_x509_crt_t cert)
{
  int pathlen;
  int err;

  err = gnutls_x509_crt_get_basic_constraints (cert, NULL, NULL, &pathlen);
  if (err < 0)
    {
      addf (str, "error: get basic constraints: %s\n", gnutls_strerror (err));
      return;
    }

  if (err == 0)
    addf (str, "\t\t\tCertificate Authority (CA): FALSE\n");
  else
    addf (str, "\t\t\tCertificate Authority (CA): TRUE\n");

  if (pathlen >= 0)
    addf (str, "\t\t\tPath Length Constraint: %d\n", pathlen);
}

static void
print_san (gnutls_string * str, gnutls_x509_crt_t cert, int san_idx)
{
  char *buffer = NULL;
  size_t size = 0;
  int err;

  err = gnutls_x509_crt_get_subject_alt_name (cert, san_idx, buffer, &size,
					      NULL);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      addf (str, "error: get subject alt name: %s\n", gnutls_strerror (err));
      return;
    }

  buffer = gnutls_malloc (size);
  if (!buffer)
    {
      addf (str, "error: malloc: %s\n", gnutls_strerror (err));
      return;
    }

  err = gnutls_x509_crt_get_subject_alt_name (cert, san_idx,
					      buffer, &size, NULL);
  if (err < 0)
    {
      gnutls_free (buffer);
      addf (str, "error: get subject alt name: %s\n", gnutls_strerror (err));
      return;
    }

  switch (err)
    {
    case GNUTLS_SAN_DNSNAME:
      addf (str, "\t\t\tDNSname: %s\n", buffer);
      break;

    case GNUTLS_SAN_RFC822NAME:
      addf (str, "\t\t\tRFC822name: %s\n", buffer);
      break;

    case GNUTLS_SAN_URI:
      addf (str, "\t\t\tURI: %s\n", buffer);
      break;

    case GNUTLS_SAN_IPADDRESS:
      addf (str, "\t\t\tIPAddress: %s\n", buffer);
      break;

    case GNUTLS_SAN_OTHERNAME:
      addf (str, "\t\t\totherName:\n\t\t\tDER: ");
      hexprint (str, buffer, size);
      addf (str, "\n\t\t\tASCII: ");
      asciiprint (str, buffer, size);
      addf (str, "\n");

      gnutls_free (buffer);

      size = 0;
      err = gnutls_x509_crt_get_subject_alt_othername_oid
	(cert, san_idx, buffer, &size);
      if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
	{
	  addf (str, "error: decoding otherName OID: %s\n",
		gnutls_strerror (err));
	  return;
	}

      buffer = gnutls_malloc (size);
      if (!buffer)
	{
	  addf (str, "error: malloc: %s\n", gnutls_strerror (err));
	  return;
	}

      err = gnutls_x509_crt_get_subject_alt_othername_oid
	(cert, san_idx, buffer, &size);
      if (err < 0)
	{
	  gnutls_free (buffer);
	  addf (str, "error: decoding otherName OID: %s\n",
		gnutls_strerror (err));
	  return;
	}

      addf (str, "\t\t\t\tOID: %.*s", size, buffer);
      if (err == GNUTLS_SAN_OTHERNAME_XMPP)
	addf (str, " (id-on-xmppAddr)");
      addf (str, "\n");
      break;

    default:
      addf (str, "error: unknown SAN\n");
      break;
    }

  gnutls_free (buffer);
}

static void
print_cert (gnutls_string * str, gnutls_x509_crt_t cert)
{
  /* Version. */
  {
    int version = gnutls_x509_crt_get_version (cert);
    if (version < 0)
      addf (str, "error: version: %s\n", gnutls_strerror (version));
    else
      addf (str, "\tVersion: %d\n", version);
  }

  /* Serial. */
  {
    char serial[128];
    size_t serial_size = sizeof (serial);
    int err;

    err = gnutls_x509_crt_get_serial (cert, serial, &serial_size);
    if (err < 0)
      addf (str, "error: serial: %s\n", gnutls_strerror (err));
    else if (serial_size == 0)
      addf (str, "\tSerial Number (hex): 00\n");
    else
      {
	size_t i;
	addf (str, "\tSerial Number (hex): %02x", (unsigned char) serial[0]);
	for (i = 1; i < serial_size; i++)
	  addf (str, ":%02x", (unsigned char) serial[i]);
	addf (str, "\n");
      }
  }

  /* Issuer. */
  {
    char dn[1024];
    size_t dn_size = sizeof (dn);
    int err;

    err = gnutls_x509_crt_get_issuer_dn (cert, dn, &dn_size);
    if (err < 0)
      addf (str, "error: issuer: %s\n", gnutls_strerror (err));
    else
      addf (str, "\tIssuer: %s\n", dn);
  }

  /* Validity. */
  {
    time_t tim;

    addf (str, "\tValidity:\n");

    tim = gnutls_x509_crt_get_activation_time (cert);
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "error: gmtime_r failed (%d)\n", t);
      if (strftime (s, max, "%a %b %e %H:%M:%S %Z %Y", &t) == 0)
	strcpy (s, "strftime failed");
      addf (str, "\t\tNot Before: %s\n", s);
    }

    tim = gnutls_x509_crt_get_expiration_time (cert);
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "error: gmtime_r failed (%d)\n", t);
      if (strftime (s, max, "%a %b %e %H:%M:%S %Z %Y", &t) == 0)
	strcpy (s, "strftime failed");
      addf (str, "\t\tNot After: %s\n", s);
    }
  }

  /* Subject. */
  {
    char dn[1024];
    size_t dn_size = sizeof (dn);
    int err;

    err = gnutls_x509_crt_get_dn (cert, dn, &dn_size);
    if (err < 0)
      addf (str, "error: subject: %s\n", gnutls_strerror (err));
    else
      addf (str, "\tSubject: %s\n", dn);
  }

  /* SubjectPublicKeyInfo. */
  {
    int err;
    unsigned int bits;

    err = gnutls_x509_crt_get_pk_algorithm (cert, &bits);
    if (err < 0)
      addf (str, "error: public key info: %s\n", gnutls_strerror (err));
    else
      {
	const char *name = gnutls_pk_algorithm_get_name (err);
	if (name == NULL)
	  name = "Unknown";

	addf (str, "\tSubject Public Key Algorithm: %s\n", name);
	switch (err)
	  {
	  case GNUTLS_PK_RSA:
	    {
	      gnutls_datum m, e;

	      err = gnutls_x509_crt_get_pk_rsa_raw (cert, &m, &e);
	      if (err < 0)
		addf (str,
		      "error: RSA public key: %s\n", gnutls_strerror (err));
	      else
		{
		  addf (str, "\t\tModulus (bits %d):\n", bits);
		  hexdump (str, m.data, m.size, "\t\t\t");
		  addf (str, "\t\tExponent:\n");
		  hexdump (str, e.data, e.size, "\t\t\t");
		}
	    }
	    break;

	  case GNUTLS_PK_DSA:
	    {
	      gnutls_datum p, q, g, y;

	      err = gnutls_x509_crt_get_pk_dsa_raw (cert, &p, &q, &g, &y);
	      if (err < 0)
		addf (str,
		      "error: DSA public key: %s\n", gnutls_strerror (err));
	      else
		{
		  addf (str, "\t\tPublic key (bits %d):\n", bits);
		  hexdump (str, y.data, y.size, "\t\t\t");
		  addf (str, "\t\tP:\n");
		  hexdump (str, p.data, p.size, "\t\t\t");
		  addf (str, "\t\tQ:\n");
		  hexdump (str, q.data, q.size, "\t\t\t");
		  addf (str, "\t\tG:\n");
		  hexdump (str, g.data, g.size, "\t\t\t");
		}
	    }
	    break;

	  default:
	    addf (str, "error: unknown algorithm: %d\n", err);
	    break;
	  }
      }
  }

  /* Extensions. */
  if (gnutls_x509_crt_get_version (cert) >= 3)
    {
      size_t i;
      int err = 0;

      for (i = 0;; i++)
	{
	  char oid[128] = "";
	  size_t sizeof_oid = sizeof (oid);
	  int critical;
	  size_t san_idx = 0;
	  size_t proxy_idx = 0;
	  size_t basic_idx = 0;
	  size_t keyusage_idx = 0;
	  size_t keypurpose_idx = 0;
	  size_t ski_idx = 0;
	  size_t aki_idx = 0;
	  size_t crldist_idx = 0;

	  err = gnutls_x509_crt_get_extension_info (cert, i,
						    oid, &sizeof_oid,
						    &critical);
	  if (err < 0)
	    {
	      if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		break;
	      addf (str, "error: get extension: %s\n", gnutls_strerror (err));
	      continue;
	    }

	  if (i == 0)
	    addf (str, "\tExtensions:\n");

	  if (strcmp (oid, "2.5.29.19") == 0)
	    {
	      if (basic_idx)
		{
		  addf (str, "error: more than one basic constraint\n");
		  continue;
		}

	      addf (str, "\t\tBasic Constraints (%scritical):\n",
		    critical ? "" : "not ");

	      print_basic (str, cert);

	      basic_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.14") == 0)
	    {
	      if (ski_idx)
		{
		  addf (str, "error: more than one SKI extension\n");
		  continue;
		}

	      addf (str, "\t\tSubject Key Identifier (%scritical):\n",
		    critical ? "" : "not ");

	      print_ski (str, cert);

	      ski_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.35") == 0)
	    {
	      if (aki_idx)
		{
		  addf (str, "error: more than one AKI extension\n");
		  continue;
		}

	      addf (str, "\t\tAuthority Key Identifier (%scritical):\n",
		    critical ? "" : "not ");

	      print_aki (str, cert);

	      aki_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.15") == 0)
	    {
	      if (keyusage_idx)
		{
		  addf (str, "error: more than one key usage extension\n");
		  continue;
		}

	      addf (str, "\t\tKey Usage (%scritical):\n",
		    critical ? "" : "not ");

	      print_key_usage (str, cert);

	      keyusage_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.37") == 0)
	    {
	      if (keypurpose_idx)
		{
		  addf (str, "error: more than one key purpose extension\n");
		  continue;
		}

	      addf (str, "\t\tKey Purpose (%scritical):\n",
		    critical ? "" : "not ");

	      print_key_purpose (str, cert);

	      keypurpose_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.17") == 0)
	    {
	      addf (str, "\t\tSubject Alternative Name (%scritical):\n",
		    critical ? "" : "not ");

	      print_san (str, cert, san_idx);

	      san_idx++;
	    }
	  else if (strcmp (oid, "2.5.29.31") == 0)
	    {
	      if (crldist_idx)
		{
		  addf (str, "error: more than one CRL distribution point\n");
		  continue;
		}

	      addf (str, "\t\tCRL Distribution points (%scritical):\n",
		    critical ? "" : "not ");

	      print_crldist (str, cert);

	      crldist_idx++;
	    }
	  else if (strcmp (oid, "1.3.6.1.5.5.7.1.14") == 0)
	    {
	      if (proxy_idx)
		{
		  addf (str, "error: more than one proxy extension\n");
		  continue;
		}

	      addf (str, "\t\tProxy Certificate Information (%scritical):\n",
		    critical ? "" : "not ");

	      print_proxy (str, cert);

	      proxy_idx++;
	    }
	  else
	    {
	      char *buffer;
	      size_t extlen = 0;
	      size_t j;

	      addf (str, "\t\tUnknown extension %s (%scritical):\n", oid,
		    critical ? "" : "not ");

	      err = gnutls_x509_crt_get_extension_data (cert, i,
							NULL, &extlen);
	      if (err < 0)
		{
		  addf (str, "error: get extension oid: %s\n",
			gnutls_strerror (err));
		  continue;
		}

	      buffer = gnutls_malloc (extlen);
	      if (!buffer)
		{
		  addf (str, "error: malloc: %s\n", gnutls_strerror (err));
		  continue;
		}

	      err = gnutls_x509_crt_get_extension_data (cert, i,
							buffer, &extlen);
	      if (err < 0)
		{
		  gnutls_free (buffer);
		  addf (str, "error: get extension oid: %s\n",
			gnutls_strerror (err));
		  continue;
		}

	      addf (str, "\t\t\tASCII: ");
	      for (j = 0; j < extlen; j++)
		{
		  if (isprint (buffer[j]))
		    addf (str, "%c", (unsigned char) buffer[j]);
		  else
		    addf (str, ".");
		}
	      addf (str, "\n");

	      addf (str, "\t\t\tHexdump:\n");
	      hexdump (str, buffer, extlen, "\t\t");

	      gnutls_free (buffer);
	    }
	}
    }

  /* Signature. */
  {
    int err;
    size_t size = 0;
    char *buffer;

    err = gnutls_x509_crt_get_signature_algorithm (cert);
    if (err < 0)
      addf (str, "error: signature: %s\n", gnutls_strerror (err));
    else
      {
	const char *name = gnutls_sign_algorithm_get_name (err);
	if (name == NULL)
	  name = "Unknown";
	addf (str, "\tSignature Algorithm: %s\n", name);
      }
    if (err == GNUTLS_SIGN_RSA_MD5 || err == GNUTLS_SIGN_RSA_MD2)
      {
	addf (str, "warning: Certificate signed using a "
	      "broken signature algorithm that can be forged.");
      }

    err = gnutls_x509_crt_get_signature (cert, buffer, &size);
    if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
      {
	addf (str, "error: get_signature: %s\n", gnutls_strerror (err));
	return;
      }

    buffer = gnutls_malloc (size);
    if (!buffer)
      {
	addf (str, "error: malloc: %s\n", gnutls_strerror (err));
	return;
      }

    err = gnutls_x509_crt_get_signature (cert, buffer, &size);
    if (err < 0)
      {
	gnutls_free (buffer);
	addf (str, "error: get_signature2: %s\n", gnutls_strerror (err));
	return;
      }

    addf (str, "\tSignature:\n");
    hexdump (str, buffer, size, "\t\t");
  }
}

static void
print_fingerprint (gnutls_string * str, gnutls_x509_crt_t cert,
		   gnutls_digest_algorithm_t algo)
{
  int err;
  size_t size = 0;
  char *buffer;

  err = gnutls_x509_crt_get_fingerprint (cert, algo, buffer, &size);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      addf (str, "error: get_fingerprint: %s\n", gnutls_strerror (err));
      return;
    }

  buffer = gnutls_malloc (size);
  if (!buffer)
    {
      addf (str, "error: malloc: %s\n", gnutls_strerror (err));
      return;
    }

  err = gnutls_x509_crt_get_fingerprint (cert, algo, buffer, &size);
  if (err < 0)
    {
      gnutls_free (buffer);
      addf (str, "error: get_fingerprint: %s\n", gnutls_strerror (err));
      return;
    }

  addf (str, "\t%s fingerprint:\n\t\t",
	((algo == GNUTLS_DIG_MD5) ? "MD5" :
	 ((algo == GNUTLS_DIG_SHA1) ? "SHA-1" :
	  "Unknown")));
  hexprint (str, buffer, size);
  adds (str, "\n");

  gnutls_free (buffer);
}

static void
print_keyid (gnutls_string * str, gnutls_x509_crt_t cert)
{
  int err;
  size_t size = 0;
  char *buffer;

  err = gnutls_x509_crt_get_key_id (cert, 0, buffer, &size);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      addf (str, "error: get_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  buffer = gnutls_malloc (size);
  if (!buffer)
    {
      addf (str, "error: malloc: %s\n", gnutls_strerror (err));
      return;
    }

  err = gnutls_x509_crt_get_key_id (cert, 0, buffer, &size);
  if (err < 0)
    {
      gnutls_free (buffer);
      addf (str, "error: get_key_id: %s\n", gnutls_strerror (err));
      return;
    }

  addf (str, "\tPublic Key Id:\n\t\t");
  hexprint (str, buffer, size);
  adds (str, "\n");

  gnutls_free (buffer);
}

static void
print_other (gnutls_string * str, gnutls_x509_crt_t cert)
{
  print_fingerprint (str, cert, GNUTLS_DIG_MD5);
  print_fingerprint (str, cert, GNUTLS_DIG_SHA1);
  print_keyid (str, cert);
}

static void
print_oneline (gnutls_string * str, gnutls_x509_crt_t cert)
{

  /* Subject. */
  {
    char dn[1024];
    size_t dn_size = sizeof (dn);
    int err;

    err = gnutls_x509_crt_get_dn (cert, dn, &dn_size);
    if (err < 0)
      addf (str, "unknown subject (%s), ", gnutls_strerror (err));
    else
      addf (str, "subject `%s', ", dn);
  }

  /* Issuer. */
  {
    char dn[1024];
    size_t dn_size = sizeof (dn);
    int err;

    err = gnutls_x509_crt_get_issuer_dn (cert, dn, &dn_size);
    if (err < 0)
      addf (str, "unknown issuer (%s), ", gnutls_strerror (err));
    else
      addf (str, "issuer `%s', ", dn);
  }

  {
    int bits;
    const char *name = gnutls_pk_algorithm_get_name
      (gnutls_x509_crt_get_pk_algorithm (cert, &bits));
    if (name == NULL)
      name = "Unknown";
    addf (str, "%s key %d bits, ", name, bits);
  }

  /* Validity. */
  {
    time_t tim;

    tim = gnutls_x509_crt_get_activation_time (cert);
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "unknown activation (%d), ", t);
      else if (strftime (s, max, "%Y-%m-%d %H:%M:%S UTC", &t) == 0)
	addf (str, "failed activation (%d), ", t);
      else
	addf (str, "activated `%s', ", s);
    }

    tim = gnutls_x509_crt_get_expiration_time (cert);
    {
      char s[42];
      size_t max = sizeof (s);
      struct tm t;

      if (gmtime_r (&tim, &t) == NULL)
	addf (str, "unknown expiry (%d), ", t);
      else if (strftime (s, max, "%Y-%m-%d %H:%M:%S UTC", &t) == 0)
	addf (str, "failed expiry (%d), ", t);
      else
	addf (str, "expires `%s', ", s);
    }
  }

  {
    int pathlen;
    char *policyLanguage;
    int err;

    err = gnutls_x509_crt_get_proxy (cert, NULL,
				     &pathlen, &policyLanguage,
				     NULL, NULL);
    if (err == 0)
      {
	addf (str, "proxy certificate (policy=");
	if (strcmp (policyLanguage, "1.3.6.1.5.5.7.21.1") == 0)
	  addf (str, "id-ppl-inheritALL");
	else if (strcmp (policyLanguage, "1.3.6.1.5.5.7.21.2") == 0)
	  addf (str, "id-ppl-independent");
	else
	  addf (str, "%s", policyLanguage);
	if (pathlen >= 0)
	  addf (str, ", pathlen=%d), ", pathlen);
	else
	  addf (str, "), ");
	gnutls_free (policyLanguage);
      }
  }

  {
    char buffer[20];
    size_t size = sizeof (buffer);
    int err;

    err = gnutls_x509_crt_get_fingerprint (cert, GNUTLS_DIG_SHA1,
					   buffer, &size);
    if (err < 0)
      {
	addf (str, "unknown fingerprint (%s)", gnutls_strerror (err));
      }
    else
      {
	addf (str, "SHA-1 fingerprint `");
	hexprint (str, buffer, size);
	adds (str, "'");
      }
  }

}

/**
 * gnutls_x509_crt_print - Pretty print X.509 certificates
 * @cert: The structure to be initialized
 * @format: Indicate the format to use
 * @out: Newly allocated zero terminated string with information.
 *
 * This function will pretty print a X.509 certificate, suitable for
 * displaying to a human.
 *
 * Returns 0 on success.
 **/
int
gnutls_x509_crt_print (gnutls_x509_crt_t cert,
		       gnutls_certificate_print_formats_t format,
		       char **out)
{
  gnutls_string str;

  if (format == GNUTLS_X509_CRT_FULL)
    {
      _gnutls_string_init (&str, gnutls_malloc, gnutls_realloc, gnutls_free);

      _gnutls_string_append_str (&str, "X.509 Certificate Information:\n");

      print_cert (&str, cert);

      _gnutls_string_append_str (&str, "Other Information:\n");

      print_other (&str, cert);

      _gnutls_string_append_data (&str, "\0", 1);
      *out = str.data;
    }
  else if (format == GNUTLS_X509_CRT_ONELINE)
    {
      _gnutls_string_init (&str, gnutls_malloc, gnutls_realloc, gnutls_free);

      print_oneline (&str, cert);

      _gnutls_string_append_data (&str, "\0", 1);
      *out = str.data;
    }
  else
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
}
