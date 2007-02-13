/*
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
 * Copyright (C) 2004 Simon Josefsson
 * Copyright (C) 2003 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>
#include <gnutls/gnutls.h>

#ifdef ENABLE_PKI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gnutls/x509.h>
#include <time.h>
#include "certtool-gaa.h"
#include <gnutls/pkcs12.h>
#include <unistd.h>
#include <certtool-cfg.h>

/* Gnulib portability files. */
#include <getline.h>
#include <read-file.h>

static void print_crl_info (gnutls_x509_crl crl, FILE *out, int all);
int generate_prime (int bits, int how);
void pkcs7_info (void);
void smime_to_pkcs7 (void);
void pkcs12_info (void);
void generate_pkcs12 (void);
void verify_chain (void);
void verify_crl (void);
gnutls_x509_privkey load_private_key (int mand);
gnutls_x509_crq load_request (void);
gnutls_x509_privkey load_ca_private_key (void);
gnutls_x509_crt load_ca_cert (void);
gnutls_x509_crt load_cert (int mand);
void certificate_info (void);
void crl_info (void);
void privkey_info (void);
static void print_certificate_info (gnutls_x509_crt crt, FILE *out,
				    unsigned int);
static void gaa_parser (int argc, char **argv);
void generate_self_signed (void);
void generate_request (void);
gnutls_x509_crt *load_cert_list (int mand, int *size);

static gaainfo info;
FILE *outfile;
FILE *infile;
static int in_cert_format;
static int out_cert_format;
gnutls_digest_algorithm_t dig = GNUTLS_DIG_SHA1;

#define UNKNOWN "Unknown"

/* non interactive operation if set
 */
int batch;

unsigned char buffer[64 * 1024];
const int buffer_size = sizeof (buffer);

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

int
main (int argc, char **argv)
{
  cfg_init ();
  gaa_parser (argc, argv);

  return 0;
}

const char *
raw_to_string (const unsigned char *raw, size_t raw_size)
{
  static char buf[1024];
  size_t i;
  if (raw_size == 0)
    return NULL;

  if (raw_size * 3 + 1 >= sizeof (buf))
    return NULL;

  for (i = 0; i < raw_size; i++)
    {
      sprintf (&(buf[i * 3]), "%02X%s", raw[i],
	       (i == raw_size - 1) ? "" : ":");
    }
  buf[sizeof (buf) - 1] = '\0';

  return buf;
}



static gnutls_x509_privkey
generate_private_key_int (void)
{
  gnutls_x509_privkey key;
  int ret, key_type;
  const char *msg;

  if (info.dsa)
    {
      msg = "DSA";
      key_type = GNUTLS_PK_DSA;

      if (info.bits > 1024)
	{
	  fprintf (stderr,
		   "The DSA algorithm cannot be used with primes over 1024 bits.\n");
	  exit (1);
	}
    }
  else
    {
      msg = "RSA";
      key_type = GNUTLS_PK_RSA;
    }


  if (info.privkey)
    return load_private_key (1);

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    {
      fprintf (stderr, "privkey_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  fprintf (stderr, "Generating a %d bit %s private key...\n", info.bits, msg);

  ret = gnutls_x509_privkey_generate (key, key_type, info.bits, 0);
  if (ret < 0)
    {
      fprintf (stderr, "privkey_generate: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return key;

}

static void
print_private_key (gnutls_x509_privkey key)
{
  int ret;
  size_t size;

  if (!key)
    return;

  if (!info.pkcs8)
    {
      size = sizeof (buffer);
      ret = gnutls_x509_privkey_export (key, out_cert_format, buffer, &size);
      if (ret < 0)
	{
	  fprintf (stderr, "privkey_export: %s\n", gnutls_strerror (ret));
	  exit (1);
	}
    }
  else
    {
      unsigned int flags;
      const char *pass;

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = GNUTLS_PKCS_USE_PKCS12_3DES;

      if ((pass = get_pass ()) == NULL || *pass == '\0')
	flags = GNUTLS_PKCS_PLAIN;

      size = sizeof (buffer);
      ret =
	gnutls_x509_privkey_export_pkcs8 (key, out_cert_format, pass,
					  flags, buffer, &size);
      if (ret < 0)
	{
	  fprintf (stderr, "privkey_export_pkcs8: %s\n",
		   gnutls_strerror (ret));
	  exit (1);
	}
    }

  fwrite (buffer, 1, size, outfile);
}

void
generate_private_key (void)
{
  gnutls_x509_privkey key;

  fprintf (stderr, "Generating a private key...\n");

  key = generate_private_key_int ();

  print_private_key (key);

  gnutls_x509_privkey_deinit (key);
}


gnutls_x509_crt
generate_certificate (gnutls_x509_privkey * ret_key,
		      gnutls_x509_crt ca_crt,
		      int proxy)
{
  gnutls_x509_crt crt;
  gnutls_x509_privkey key = NULL;
  size_t size;
  int ret;
  int serial, client;
  int days, result, ca_status = 0, path_len;
  const char *str;
  int vers = 3;			/* the default version in the certificate 
				 */
  unsigned int usage = 0, server;
  gnutls_x509_crq crq;		/* request */

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    {
      fprintf (stderr, "crt_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }


  crq = load_request ();

  if (crq == NULL)
    {

      key = load_private_key (1);

      if (!batch)
	fprintf (stderr,
		 "Please enter the details of the certificate's distinguished name. "
		 "Just press enter to ignore a field.\n");

      /* set the DN.
       */
      if (proxy)
	{
	  result = gnutls_x509_crt_set_proxy_dn (crt, ca_crt, 0, NULL, 0);
	  if (result < 0)
	    {
	      fprintf (stderr, "set_proxy_dn: %s\n", gnutls_strerror (result));
	      exit (1);
	    }
	  get_cn_crt_set (crt);
	}
      else
	{
	  get_country_crt_set (crt);
	  get_organization_crt_set (crt);
	  get_unit_crt_set (crt);
	  get_locality_crt_set (crt);
	  get_state_crt_set (crt);
	  get_cn_crt_set (crt);
	  get_uid_crt_set (crt);
	  get_oid_crt_set (crt);

	  if (!batch)
	    fprintf (stderr,
		     "This field should not be used in new certificates.\n");

	  get_pkcs9_email_crt_set (crt);
	}

      result = gnutls_x509_crt_set_key (crt, key);
      if (result < 0)
	{
	  fprintf (stderr, "set_key: %s\n", gnutls_strerror (result));
	  exit (1);
	}

    }
  else
    {
      result = gnutls_x509_crt_set_crq (crt, crq);
      if (result < 0)
	{
	  fprintf (stderr, "set_crq: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }


  serial = get_serial ();
  buffer[3] = serial & 0xff;
  buffer[2] = (serial >> 8) & 0xff;
  buffer[1] = (serial >> 16) & 0xff;
  buffer[0] = 0;

  result = gnutls_x509_crt_set_serial (crt, buffer, 4);
  if (result < 0)
    {
      fprintf (stderr, "serial: %s\n", gnutls_strerror (result));
      exit (1);
    }


  if (!batch)
    fprintf (stderr, "\n\nActivation/Expiration time.\n");

  gnutls_x509_crt_set_activation_time (crt, time (NULL));

  days = get_days ();

  result =
    gnutls_x509_crt_set_expiration_time (crt,
					 time (NULL) + days * 24 * 60 * 60);
  if (result < 0)
    {
      fprintf (stderr, "set_expiration: %s\n", gnutls_strerror (result));
      exit (1);
    }

  if (!batch)
    fprintf (stderr, "\n\nExtensions.\n");

  if (proxy)
    {
      const char *policylanguage;
      char *policy;
      size_t policylen;
      int proxypathlen = get_path_len ();

      if (!batch)
	{
	  printf ("1.3.6.1.5.5.7.21.1 ::= id-ppl-inheritALL\n");
	  printf ("1.3.6.1.5.5.7.21.2 ::= id-ppl-independent\n");
	}

      policylanguage = get_proxy_policy (&policy, &policylen);

      result = gnutls_x509_crt_set_proxy (crt, proxypathlen, policylanguage,
					  policy, policylen);
      if (result < 0)
	{
	  fprintf (stderr, "set_proxy: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  if (!proxy)
    ca_status = get_ca_status ();
  if (ca_status)
    path_len = get_path_len ();
  else
    path_len = -1;

  result = gnutls_x509_crt_set_basic_constraints (crt, ca_status, path_len);
  if (result < 0)
    {
      fprintf (stderr, "basic_constraints: %s\n", gnutls_strerror (result));
      exit (1);
    }

  client = get_tls_client_status ();
  if (client != 0)
    {
      result =
	gnutls_x509_crt_set_key_purpose_oid (crt,
					     GNUTLS_KP_TLS_WWW_CLIENT, 0);
      if (result < 0)
	{
	  fprintf (stderr, "key_kp: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  server = get_tls_server_status ();
  if (server != 0)
    {
      result = 0;

      if (!proxy)
	{
	  str = get_dns_name ();
	  if (str != NULL)
	    {
	      result = gnutls_x509_crt_set_subject_alternative_name
		(crt, GNUTLS_SAN_DNSNAME, str);
	    }
	  else
	    {
	      str = get_ip_addr ();
	      if (str != NULL)
		{
		  result = gnutls_x509_crt_set_subject_alternative_name
		    (crt, GNUTLS_SAN_IPADDRESS, str);
		}
	    }

	  if (result < 0)
	    {
	      fprintf (stderr, "subject_alt_name: %s\n",
		       gnutls_strerror (result));
	      exit (1);
	    }
	}

      result =
	gnutls_x509_crt_set_key_purpose_oid (crt,
					     GNUTLS_KP_TLS_WWW_SERVER, 0);
      if (result < 0)
	{
	  fprintf (stderr, "key_kp: %s\n", gnutls_strerror (result));
	  exit (1);
	}

    }
  else if (!proxy)
    {
      str = get_email ();

      if (str != NULL)
	{
	  result =
	    gnutls_x509_crt_set_subject_alternative_name (crt,
							  GNUTLS_SAN_RFC822NAME,
							  str);
	  if (result < 0)
	    {
	      fprintf (stderr, "subject_alt_name: %s\n",
		       gnutls_strerror (result));
	      exit (1);
	    }
	}
    }


  if (!ca_status || server)
    {
      int pk;


      pk = gnutls_x509_crt_get_pk_algorithm (crt, NULL);

      if (pk != GNUTLS_PK_DSA)
	{			/* DSA keys can only sign.
				 */
	  result = get_sign_status (server);
	  if (result)
	    usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;

	  result = get_encrypt_status (server);
	  if (result)
	    usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
	}
      else
	usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;
    }


  if (ca_status)
    {
      result = get_cert_sign_status ();
      if (result)
	usage |= GNUTLS_KEY_KEY_CERT_SIGN;

      result = get_crl_sign_status ();
      if (result)
	usage |= GNUTLS_KEY_CRL_SIGN;

      result = get_code_sign_status ();
      if (result)
	{
	  result =
	    gnutls_x509_crt_set_key_purpose_oid (crt,
						 GNUTLS_KP_CODE_SIGNING, 0);
	  if (result < 0)
	    {
	      fprintf (stderr, "key_kp: %s\n", gnutls_strerror (result));
	      exit (1);
	    }
	}

      result = get_ocsp_sign_status ();
      if (result)
	{
	  result =
	    gnutls_x509_crt_set_key_purpose_oid (crt,
						 GNUTLS_KP_OCSP_SIGNING, 0);
	  if (result < 0)
	    {
	      fprintf (stderr, "key_kp: %s\n", gnutls_strerror (result));
	      exit (1);
	    }
	}

      result = get_time_stamp_status ();
      if (result)
	{
	  result =
	    gnutls_x509_crt_set_key_purpose_oid (crt,
						 GNUTLS_KP_TIME_STAMPING, 0);
	  if (result < 0)
	    {
	      fprintf (stderr, "key_kp: %s\n", gnutls_strerror (result));
	      exit (1);
	    }
	}
    }

  if (usage != 0)
    {
      result = gnutls_x509_crt_set_key_usage (crt, usage);
      if (result < 0)
	{
	  fprintf (stderr, "key_usage: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  /* Version.
   */
  result = gnutls_x509_crt_set_version (crt, vers);
  if (result < 0)
    {
      fprintf (stderr, "set_version: %s\n", gnutls_strerror (result));
      exit (1);
    }

  /* Subject Key ID.
   */
  size = sizeof (buffer);
  result = gnutls_x509_crt_get_key_id (crt, 0, buffer, &size);
  if (result >= 0)
    {
      result = gnutls_x509_crt_set_subject_key_id (crt, buffer, size);
      if (result < 0)
	{
	  fprintf (stderr, "set_subject_key_id: %s\n",
		   gnutls_strerror (result));
	  exit (1);
	}
    }

  /* Authority Key ID.
   */
  if (ca_crt != NULL)
    {
      size = sizeof (buffer);
      result = gnutls_x509_crt_get_subject_key_id (ca_crt, buffer,
						   &size, NULL);
      if (result < 0)
	{
	  size = sizeof (buffer);
	  result = gnutls_x509_crt_get_key_id (ca_crt, 0, buffer, &size);
	}
      if (result >= 0)
	{
	  result = gnutls_x509_crt_set_authority_key_id (crt, buffer, size);
	  if (result < 0)
	    {
	      fprintf (stderr, "set_authority_key_id: %s\n",
		       gnutls_strerror (result));
	      exit (1);
	    }
	}
    }

  *ret_key = key;
  return crt;

}

gnutls_x509_crl
generate_crl (void)
{
  gnutls_x509_crl crl;
  gnutls_x509_crt *crts;
  int size;
  int days, result, i;
  int vers = 2;			/* the default version in the CRL
				 */

  result = gnutls_x509_crl_init (&crl);
  if (result < 0)
    {
      fprintf (stderr, "crl_init: %s\n", gnutls_strerror (result));
      exit (1);
    }

  crts = load_cert_list (1, &size);

  for (i = 0; i < size; i++)
    {

      result = gnutls_x509_crl_set_crt (crl, crts[i], time (0));
      if (result < 0)
	{
	  fprintf (stderr, "crl_set_crt: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  fprintf (stderr, "\n\nthisUpdate/nextUpdate time.\n");
  gnutls_x509_crl_set_this_update (crl, time (NULL));

  days = get_crl_next_update ();

  result =
    gnutls_x509_crl_set_next_update (crl, time (NULL) + days * 24 * 60 * 60);
  if (result < 0)
    {
      fprintf (stderr, "next_update: %s\n", gnutls_strerror (result));
      exit (1);
    }

  /* Version.
   */
  result = gnutls_x509_crl_set_version (crl, vers);
  if (result < 0)
    {
      fprintf (stderr, "set_version: %s\n", gnutls_strerror (result));
      exit (1);
    }

  return crl;
}

gnutls_x509_crt
update_certificate (void)
{
  gnutls_x509_crt crt;
  int size;
  int days, result;

  size = gnutls_x509_crt_init (&crt);
  if (size < 0)
    {
      fprintf (stderr, "crt_init: %s\n", gnutls_strerror (size));
      exit (1);
    }

  crt = load_cert (1);

  fprintf (stderr, "Activation/Expiration time.\n");
  gnutls_x509_crt_set_activation_time (crt, time (NULL));

  days = get_days ();

  result =
    gnutls_x509_crt_set_expiration_time (crt,
					 time (NULL) + days * 24 * 60 * 60);
  if (result < 0)
    {
      fprintf (stderr, "set_expiration: %s\n", gnutls_strerror (result));
      exit (1);
    }

  return crt;

}


void
generate_self_signed (void)
{
  gnutls_x509_crt crt;
  gnutls_x509_privkey key;
  size_t size;
  int result;
  const char *uri;

  fprintf (stderr, "Generating a self signed certificate...\n");

  crt = generate_certificate (&key, NULL, 0);

  if (!key)
    key = load_private_key (1);

  uri = get_crl_dist_point_url ();
  if (uri)
    {
      result = gnutls_x509_crt_set_crl_dist_points (crt, GNUTLS_SAN_URI,
						    uri,
						    0 /* all reasons */ );
      if (result < 0)
	{
	  fprintf (stderr, "crl_dist_points: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, crt, key, dig, 0);
  if (result < 0)
    {
      fprintf (stderr, "crt_sign: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "crt_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

void
generate_signed_certificate (void)
{
  gnutls_x509_crt crt;
  gnutls_x509_privkey key;
  size_t size;
  int result;
  gnutls_x509_privkey ca_key;
  gnutls_x509_crt ca_crt;

  fprintf (stderr, "Generating a signed certificate...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();

  crt = generate_certificate (&key, ca_crt, 0);

  /* Copy the CRL distribution points.
   */
  gnutls_x509_crt_cpy_crl_dist_points (crt, ca_crt);
  /* it doesn't matter if we couldn't copy the CRL dist points.
   */

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, ca_crt, ca_key, dig, 0);
  if (result < 0)
    {
      fprintf (stderr, "crt_sign: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "crt_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

void
generate_proxy_certificate (void)
{
  gnutls_x509_crt crt, eecrt;
  gnutls_x509_privkey key, eekey;
  size_t size;
  int result;

  fprintf (stderr, "Generating a proxy certificate...\n");

  eekey = load_ca_private_key ();
  eecrt = load_cert (1);

  crt = generate_certificate (&key, eecrt, 1);

  print_certificate_info (crt, stderr, 0);

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, eecrt, eekey, dig, 0);
  if (result < 0)
    {
      fprintf (stderr, "crt_sign: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "crt_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
  gnutls_x509_privkey_deinit (key);
}

void
generate_signed_crl (void)
{
  gnutls_x509_crl crl;
  size_t size;
  int result;
  gnutls_x509_privkey ca_key;
  gnutls_x509_crt ca_crt;

  fprintf (stderr, "Generating a signed CRL...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();

  crl = generate_crl ();

  print_crl_info (crl, stderr, 0);

  fprintf (stderr, "\n\nSigning CRL...\n");

  result = gnutls_x509_crl_sign (crl, ca_crt, ca_key);
  if (result < 0)
    {
      fprintf (stderr, "crl_sign: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_x509_crl_export (crl, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "crl_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crl_deinit (crl);
}

void
update_signed_certificate (void)
{
  gnutls_x509_crt crt;
  size_t size;
  int result;
  gnutls_x509_privkey ca_key;
  gnutls_x509_crt ca_crt;

  fprintf (stderr, "Generating a signed certificate...\n");

  ca_key = load_ca_private_key ();
  ca_crt = load_ca_cert ();

  crt = update_certificate ();

  fprintf (stderr, "\n\nSigning certificate...\n");

  result = gnutls_x509_crt_sign2 (crt, ca_crt, ca_key, dig, 0);
  if (result < 0)
    {
      fprintf (stderr, "crt_sign: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_x509_crt_export (crt, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "crt_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crt_deinit (crt);
}

void
gaa_parser (int argc, char **argv)
{
  int ret;

  if (gaa (argc, argv, &info) != -1)
    {
      fprintf (stderr,
	       "Error in the arguments. Use the --help or -h parameters to get more information.\n");
      exit (1);
    }

  if (info.outfile)
    {
      outfile = fopen (info.outfile, "wb");
      if (outfile == NULL)
	{
	  fprintf (stderr, "error: could not open '%s'.\n", info.outfile);
	  exit (1);
	}
    }
  else
    outfile = stdout;

  if (info.infile)
    {
      infile = fopen (info.infile, "rb");
      if (infile == NULL)
	{
	  fprintf (stderr, "error: could not open '%s'.\n", info.infile);
	  exit (1);
	}
    }
  else
    infile = stdin;

  if (info.incert_format)
    in_cert_format = GNUTLS_X509_FMT_DER;
  else
    in_cert_format = GNUTLS_X509_FMT_PEM;

  if (info.outcert_format)
    out_cert_format = GNUTLS_X509_FMT_DER;
  else
    out_cert_format = GNUTLS_X509_FMT_PEM;

  if (info.hash != NULL)
    {
      if (strcasecmp (info.hash, "md5") == 0)
	{
	  fprintf (stderr,
		   "Warning: MD5 is broken, and should not be used any more for digital signatures.\n");
	  dig = GNUTLS_DIG_MD5;
	}
      else if (strcasecmp (info.hash, "sha1") == 0)
	dig = GNUTLS_DIG_SHA1;
      else if (strcasecmp (info.hash, "sha256") == 0)
	dig = GNUTLS_DIG_SHA256;
      else if (strcasecmp (info.hash, "sha384") == 0)
	dig = GNUTLS_DIG_SHA384;
      else if (strcasecmp (info.hash, "sha512") == 0)
	dig = GNUTLS_DIG_SHA512;
      else if (strcasecmp (info.hash, "rmd160") == 0)
	dig = GNUTLS_DIG_RMD160;
      else
	fprintf (stderr,
		 "Unsupported hash algorithm '%s'. Using the default.\n",
		 info.hash);
    }

  batch = 0;
  if (info.template)
    {
      batch = 1;
      template_parse (info.template);
    }

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (info.debug);

  if ((ret = gnutls_global_init ()) < 0)
    {
      fprintf (stderr, "global_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  switch (info.action)
    {
    case 0:
      generate_self_signed ();
      break;
    case 1:
      generate_private_key ();
      break;
    case 2:
      certificate_info ();
      break;
    case 3:
      generate_request ();
      break;
    case 4:
      generate_signed_certificate ();
      break;
    case 5:
      verify_chain ();
      break;
    case 6:
      privkey_info ();
      break;
    case 7:
      update_signed_certificate ();
      break;
    case 8:
      generate_pkcs12 ();
      break;
    case 9:
      pkcs12_info ();
      break;
    case 10:
      generate_prime (info.bits, 1);
      break;
    case 16:
      generate_prime (info.bits, 0);
      break;
    case 11:
      crl_info ();
      break;
    case 12:
      pkcs7_info ();
      break;
    case 13:
      generate_signed_crl ();
      break;
    case 14:
      verify_crl ();
      break;
    case 15:
      smime_to_pkcs7 ();
      break;
    case 17:
      generate_proxy_certificate ();
      break;
    default:
      fprintf (stderr, "GnuTLS' certtool utility.\n");
      fprintf (stderr,
	       "Please use the --help to get help on this program.\n");
      exit (0);
    }
  fclose (outfile);
}


/* OIDs that are handled by the gnutls' functions.
 */
static inline int
known_oid (const char *oid)
{
  if (strcmp (oid, "2.5.29.17") == 0 ||
      strcmp (oid, "2.5.29.19") == 0 ||
      strcmp (oid, "2.5.29.31") == 0 ||
      strcmp (oid, "2.5.29.37") == 0 ||
      strcmp (oid, "2.5.29.14") == 0 ||
      strcmp (oid, "2.5.29.35") == 0 ||
      strcmp (oid, "2.5.29.15") == 0 ||
      strcmp (oid, "1.3.6.1.5.5.7.1.14") == 0)
    return 1;

  return 0;
}

#define MAX_CRTS 64
void
certificate_info (void)
{
  gnutls_x509_crt crt[MAX_CRTS];
  size_t size;
  int ret, i, count;
  gnutls_datum pem;
  unsigned int crt_num;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  pem.data = buffer;
  pem.size = size;

  crt_num = MAX_CRTS;
  ret =
    gnutls_x509_crt_list_import (crt, &crt_num, &pem, in_cert_format,
				 GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
  if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      fprintf (stderr,
	       "Too many certificates (%d), will only read the first %d.\n",
	       crt_num, MAX_CRTS);
      crt_num = MAX_CRTS;
      ret =
	gnutls_x509_crt_list_import (crt, &crt_num, &pem, in_cert_format, 0);
    }

  if (ret < 0)
    {
      fprintf (stderr, "Decoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }
  count = ret;

  if (count > 1 && out_cert_format == GNUTLS_X509_FMT_DER)
    {
      fprintf(stderr, "Cannot output multiple certificates in DER format, using PEM instead.\n");
      out_cert_format = GNUTLS_X509_FMT_PEM;
    }
    
  for (i = 0; i < count; i++)
    {
      if (out_cert_format == GNUTLS_X509_FMT_PEM)
        print_certificate_info (crt[i], outfile, 1);

      if (!info.xml)
	{
	  size = sizeof (buffer);
	  ret =
	    gnutls_x509_crt_export (crt[i], out_cert_format, buffer,
				    &size);
	  if (ret < 0)
	    {
	      fprintf (stderr, "Encoding error: %s\n", gnutls_strerror (ret));
	      exit (1);
	    }
	  fprintf (outfile, "\n%s\n", buffer);

	}
      else
	{
	  gnutls_datum xml;

	  ret = gnutls_x509_crt_to_xml (crt[i], &xml, GNUTLS_XML_SHOW_ALL);
	  if (ret < 0)
	    {
	      fprintf (stderr, "XML encoding error: %s\n",
		       gnutls_strerror (ret));
	      exit (1);
	    }

	  fprintf (outfile, "\n%s\n", xml.data);
	  gnutls_free (xml.data);
	}
    }

}

static void
print_hex_datum (gnutls_datum * dat)
{
  unsigned int j;
#define SPACE "\t"
  fprintf (outfile, "\n" SPACE);
  for (j = 0; j < dat->size; j++)
    {
      fprintf (outfile, "%.2x:", (unsigned char) dat->data[j]);
      if ((j + 1) % 15 == 0)
	fprintf (outfile, "\n" SPACE);
    }
  fprintf (outfile, "\n");
}


static void
print_certificate_info (gnutls_x509_crt crt, FILE *out, unsigned int all)
{
  gnutls_datum_t info;
  int ret;

  if (all)
    ret = gnutls_x509_crt_print (crt, GNUTLS_X509_CRT_FULL, &info);
  else
    ret = gnutls_x509_crt_print (crt, GNUTLS_X509_CRT_UNSIGNED_FULL, &info);
  if (ret == 0)
    {
      fprintf (out, "%s\n", info.data);
      gnutls_free (info.data);
    }

  if (out == stderr && batch == 0)	/* interactive */
    if (read_yesno ("Is the above information ok? (Y/N): ") == 0)
      {
	exit (1);
      }
}

static void
print_crl_info (gnutls_x509_crl crl, FILE *out, int all)
{
  int ret, rc;
  time_t tim;
  unsigned int j;
  char serial[128];
  size_t serial_size = sizeof (serial), dn_size;
  char dn[256];
  const char *cprint;
  char *tmp;

  fprintf (out, "CRL information:\n");
  fprintf (out, "Version: %d\n", gnutls_x509_crl_get_version (crl));

  /* Issuer
   */
  if (all)
    {
      dn_size = sizeof (dn);

      ret = gnutls_x509_crl_get_issuer_dn (crl, dn, &dn_size);
      if (ret >= 0)
	fprintf (out, "Issuer: %s\n", dn);

      fprintf (out, "Signature Algorithm: ");
      ret = gnutls_x509_crl_get_signature_algorithm (crl);

      cprint = gnutls_sign_algorithm_get_name (ret);
      if (cprint == NULL)
	cprint = UNKNOWN;
      fprintf (out, "%s\n", cprint);
    }

  /* Validity
   */
  fprintf (out, "Update dates:\n");

  tim = gnutls_x509_crl_get_this_update (crl);
  tmp = asctime (gmtime (&tim));
  tmp[strlen(tmp)-1] = '\0';
  fprintf (out, "\tIssued at: %s UTC\n", tmp);

  tim = gnutls_x509_crl_get_next_update (crl);
  tmp = asctime (gmtime (&tim));
  tmp[strlen(tmp)-1] = '\0';
  fprintf (out, "\tNext at: %s UTC\n", tmp);

  fprintf (out, "\n");

  /* Count the certificates.
   */

  rc = gnutls_x509_crl_get_crt_count (crl);
  fprintf (out, "Revoked certificates: %d\n", rc);

  for (j = 0; j < (unsigned int) rc; j++)
    {
      /* serial number
       */
      serial_size = sizeof (serial);
      ret =
	gnutls_x509_crl_get_crt_serial (crl, j, serial, &serial_size, &tim);

      if (ret < 0)
	{
	  fprintf (stderr, "error: %s\n", gnutls_strerror (ret));
	}
      else
	{
	  fprintf (out, "\tCertificate SN: %s\n",
		   raw_to_string (serial, serial_size));
	  tmp = asctime (gmtime (&tim));
	  tmp[strlen(tmp)-1] = '\0';
	  fprintf (out, "\tRevoked at: %s UTC\n", tmp);
	}
    }

}

void
crl_info ()
{
  gnutls_x509_crl crl;
  int ret;
  size_t size;
  gnutls_datum_t pem;

  pem.data = fread_file (infile, &size);
  pem.size = size;

  if (!pem.data)
    {
      fprintf (stderr, "Could not read file\n");
      exit (1);
    }

  ret = gnutls_x509_crl_init (&crl);
  if (ret < 0)
    {
      free (pem.data);
      fprintf (stderr, "crl_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  ret = gnutls_x509_crl_import (crl, &pem, in_cert_format);
  free (pem.data);
  if (ret < 0)
    {
      fprintf (stderr, "Decoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  print_crl_info (crl, outfile, 1);

  size = sizeof (buffer);
  ret = gnutls_x509_crl_export (crl, GNUTLS_X509_FMT_PEM, buffer, &size);
  if (ret < 0)
    {
      fprintf (stderr, "Encoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  fprintf (outfile, "\n%s\n", buffer);
}


void
privkey_info (void)
{
  gnutls_x509_privkey key;
  size_t size;
  int ret;
  gnutls_datum pem;
  const char *cprint;
  const char *pass;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  gnutls_x509_privkey_init (&key);

  pem.data = buffer;
  pem.size = size;


  if (!info.pkcs8)
    {
      ret = gnutls_x509_privkey_import (key, &pem, in_cert_format);
    }
  else
    {
      if (info.pass)
	pass = info.pass;
      else
	pass = get_pass ();
      ret =
	gnutls_x509_privkey_import_pkcs8 (key, &pem, in_cert_format, pass, 0);
    }

  if (ret < 0)
    {
      fprintf (stderr, "Decoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  /* Public key algorithm
   */
  fprintf (outfile, "Public Key Info:\n");
  ret = gnutls_x509_privkey_get_pk_algorithm (key);
  fprintf (outfile, "\tPublic Key Algorithm: ");

  cprint = gnutls_pk_algorithm_get_name (ret);
  if (cprint == NULL)
    cprint = UNKNOWN;
  fprintf (outfile, "%s\n", cprint);

  /* Print the raw public and private keys    
   */
  if (ret == GNUTLS_PK_RSA)
    {
      gnutls_datum m, e, d, p, q, u;

      ret = gnutls_x509_privkey_export_rsa_raw (key, &m, &e, &d, &p, &q, &u);
      if (ret < 0)
	{
	  fprintf (stderr, "Error in key RSA data export: %s\n",
		   gnutls_strerror (ret));
	}

      fprintf (outfile, "modulus:");
      print_hex_datum (&m);
      fprintf (outfile, "public exponent:");
      print_hex_datum (&e);
      fprintf (outfile, "private exponent:");
      print_hex_datum (&d);
      fprintf (outfile, "prime1:");
      print_hex_datum (&p);
      fprintf (outfile, "prime2:");
      print_hex_datum (&q);
      fprintf (outfile, "coefficient:");
      print_hex_datum (&u);

    }
  else if (ret == GNUTLS_PK_DSA)
    {
      gnutls_datum p, q, g, y, x;

      ret = gnutls_x509_privkey_export_dsa_raw (key, &p, &q, &g, &y, &x);
      if (ret < 0)
	{
	  fprintf (stderr, "Error in key DSA data export: %s\n",
		   gnutls_strerror (ret));
	}

      fprintf (outfile, "private key:");
      print_hex_datum (&x);
      fprintf (outfile, "public key:");
      print_hex_datum (&y);
      fprintf (outfile, "p:");
      print_hex_datum (&p);
      fprintf (outfile, "q:");
      print_hex_datum (&q);
      fprintf (outfile, "g:");
      print_hex_datum (&g);
    }

  fprintf (outfile, "\n");

  size = sizeof (buffer);
  if ((ret = gnutls_x509_privkey_get_key_id (key, 0, buffer, &size)) < 0)
    {
      fprintf (stderr, "Error in key id calculation: %s\n",
	       gnutls_strerror (ret));
    }
  else
    {
      fprintf (outfile, "Public Key ID: %s\n", raw_to_string (buffer, size));
    }

  if (info.fix_key != 0)
    {
      ret = gnutls_x509_privkey_fix (key);
      if (ret < 0)
	{
	  fprintf (stderr, "Encoding error: %s\n", gnutls_strerror (ret));
	  exit (1);
	}
    }

  size = sizeof (buffer);
  ret = gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
  if (ret < 0)
    {
      fprintf (stderr, "Encoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }
  fprintf (outfile, "\n%s\n", buffer);
}

/* mand should be non zero if it is required to read a private key.
 */
gnutls_x509_privkey
load_private_key (int mand)
{
  FILE *fd;
  gnutls_x509_privkey key;
  int ret;
  gnutls_datum dat;
  size_t size;
  const char *pass;

  if (!info.privkey && !mand)
    return NULL;

  if (!info.privkey)
    {
      fprintf (stderr, "error: a private key was not specified\n");
      exit (1);
    }

  fd = fopen (info.privkey, "r");
  if (fd == NULL)
    {
      fprintf (stderr, "error: could not load key file '%s'.\n",
	       info.privkey);
      exit (1);
    }

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    {
      fprintf (stderr, "privkey_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  dat.data = buffer;
  dat.size = size;

  if (!info.pkcs8)
    ret = gnutls_x509_privkey_import (key, &dat, in_cert_format);
  else
    {
      pass = get_pass ();
      ret = gnutls_x509_privkey_import_pkcs8 (key, &dat, in_cert_format,
					      pass, 0);
    }

  if (ret < 0)
    {
      fprintf (stderr, "privkey_import: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return key;
}

gnutls_x509_crq
load_request ()
{
  FILE *fd;
  gnutls_x509_crq crq;
  int ret;
  gnutls_datum dat;
  size_t size;

  if (!info.request)
    return NULL;

  fd = fopen (info.request, "r");
  if (fd == NULL)
    {
      fprintf (stderr, "File %s does not exist.\n", info.request);
      exit (1);
    }

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ret = gnutls_x509_crq_init (&crq);
  if (ret < 0)
    {
      fprintf (stderr, "crq_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  dat.data = buffer;
  dat.size = size;

  ret = gnutls_x509_crq_import (crq, &dat, in_cert_format);

  if (ret < 0)
    {
      fprintf (stderr, "crq_import: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return crq;
}

gnutls_x509_privkey
load_ca_private_key ()
{
  FILE *fd;
  gnutls_x509_privkey key;
  int ret;
  const char *pass;
  gnutls_datum dat;
  size_t size;

  fprintf (stderr, "Loading CA's private key...\n");

  if (info.ca_privkey == NULL)
    {
      fprintf (stderr, "You must specify a private key of the CA.\n");
      exit (1);
    }

  fd = fopen (info.ca_privkey, "r");
  if (fd == NULL)
    {
      fprintf (stderr, "File %s does not exist.\n", info.ca_privkey);
      exit (1);
    }

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    {
      fprintf (stderr, "privkey_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  dat.data = buffer;
  dat.size = size;

  if (!info.pkcs8)
    ret = gnutls_x509_privkey_import (key, &dat, in_cert_format);
  else
    {
      pass = get_pass ();
      ret = gnutls_x509_privkey_import_pkcs8 (key, &dat, in_cert_format,
					      pass, 0);
    }

  if (ret < 0)
    {
      fprintf (stderr, "privkey_import: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return key;
}

/* Loads the CA's certificate
 */
gnutls_x509_crt
load_ca_cert ()
{
  FILE *fd;
  gnutls_x509_crt crt;
  int ret;
  gnutls_datum dat;
  size_t size;

  fprintf (stderr, "Loading CA's certificate...\n");

  if (info.ca == NULL)
    {
      fprintf (stderr, "You must specify a certificate of the CA.\n");
      exit (1);
    }

  fd = fopen (info.ca, "r");
  if (fd == NULL)
    {
      fprintf (stderr, "File %s does not exist.\n", info.ca);
      exit (1);
    }

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    {
      fprintf (stderr, "crt_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  dat.data = buffer;
  dat.size = size;

  ret = gnutls_x509_crt_import (crt, &dat, in_cert_format);
  if (ret < 0)
    {
      fprintf (stderr, "crt_import: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  return crt;
}

/* Loads the certificate
 * If mand is non zero then a certificate is mandatory. Otherwise
 * null will be returned if the certificate loading fails.
 */
gnutls_x509_crt
load_cert (int mand)
{
  gnutls_x509_crt *crt;
  int size;

  crt = load_cert_list (mand, &size);

  return crt ? crt[0] : NULL;
}

#define MAX_CERTS 256

/* Loads a certificate list
 */
gnutls_x509_crt *
load_cert_list (int mand, int *crt_size)
{
  FILE *fd;
  static gnutls_x509_crt crt[MAX_CERTS];
  char *ptr;
  int ret, i;
  gnutls_datum dat;
  size_t size;
  int ptr_size;

  *crt_size = 0;
  fprintf (stderr, "Loading certificate list...\n");

  if (info.cert == NULL)
    {
      fprintf (stderr, "You must specify a certificate.\n");
      if (mand)
	exit (1);
      else
	return NULL;
    }

  fd = fopen (info.cert, "r");
  if (fd == NULL)
    {
      fprintf (stderr, "File %s does not exist.\n", info.cert);
      exit (1);
    }

  size = fread (buffer, 1, sizeof (buffer) - 1, fd);
  buffer[size] = 0;

  fclose (fd);

  ptr = buffer;
  ptr_size = size;

  for (i = 0; i < MAX_CERTS; i++)
    {
      ret = gnutls_x509_crt_init (&crt[i]);
      if (ret < 0)
	{
	  fprintf (stderr, "crt_init: %s\n", gnutls_strerror (ret));
	  exit (1);
	}

      dat.data = ptr;
      dat.size = ptr_size;

      ret = gnutls_x509_crt_import (crt[i], &dat, in_cert_format);
      if (ret < 0 && *crt_size > 0)
	break;
      if (ret < 0)
	{
	  fprintf (stderr, "crt_import: %s\n", gnutls_strerror (ret));
	  exit (1);
	}

      ptr = strstr (ptr, "---END");
      if (ptr == NULL)
	break;
      ptr++;

      ptr_size = size;
      ptr_size -=
	(unsigned int) ((unsigned char *) ptr - (unsigned char *) buffer);

      if (ptr_size < 0)
	break;

      (*crt_size)++;
    }
  fprintf (stderr, "Loaded %d certificates.\n", *crt_size);

  return crt;
}


/* Generate a PKCS #10 certificate request.
 */
void
generate_request (void)
{
  gnutls_x509_crq crq;
  gnutls_x509_privkey key;
  int ret;
  const char *pass;
  size_t size;

  fprintf (stderr, "Generating a PKCS #10 certificate request...\n");

  ret = gnutls_x509_crq_init (&crq);
  if (ret < 0)
    {
      fprintf (stderr, "crq_init: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  /* Load the private key.
   */
  key = generate_private_key_int ();

  /* Set the DN.
   */
  get_country_crq_set (crq);
  get_organization_crq_set (crq);
  get_unit_crq_set (crq);
  get_locality_crq_set (crq);
  get_state_crq_set (crq);
  get_cn_crq_set (crq);
  get_uid_crq_set (crq);
  get_oid_crq_set (crq);

  ret = gnutls_x509_crq_set_version (crq, 1);
  if (ret < 0)
    {
      fprintf (stderr, "set_version: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  pass = get_challenge_pass ();

  if (pass != NULL)
    {
      ret = gnutls_x509_crq_set_challenge_password (crq, pass);
      if (ret < 0)
	{
	  fprintf (stderr, "set_pass: %s\n", gnutls_strerror (ret));
	  exit (1);
	}
    }

  ret = gnutls_x509_crq_set_key (crq, key);
  if (ret < 0)
    {
      fprintf (stderr, "set_key: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  ret = gnutls_x509_crq_sign (crq, key);
  if (ret < 0)
    {
      fprintf (stderr, "sign: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  size = sizeof (buffer);
  ret = gnutls_x509_crq_export (crq, out_cert_format, buffer, &size);
  if (ret < 0)
    {
      fprintf (stderr, "export: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

  gnutls_x509_crq_deinit (crq);
  gnutls_x509_privkey_deinit (key);

}

static void print_verification_res (gnutls_x509_crt crt,
				    gnutls_x509_crt issuer,
				    gnutls_x509_crl * crl_list,
				    int crl_list_size);

#define CERT_SEP "-----BEGIN CERT"
#define CRL_SEP "-----BEGIN X509 CRL"
int
_verify_x509_mem (const void *cert, int cert_size)
{
  int siz, i;
  const char *ptr;
  int ret;
  char name[256];
  char issuer_name[256];
  size_t name_size;
  size_t issuer_name_size;
  gnutls_datum tmp;
  gnutls_x509_crt *x509_cert_list = NULL;
  gnutls_x509_crl *x509_crl_list = NULL;
  int x509_ncerts, x509_ncrls;


  /* Decode the CA certificate
   */

  /* Decode the CRL list
   */
  siz = cert_size;
  ptr = cert;

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


      if (i - 1 != 0)
	{
	  /* verify the previous certificate using this one 
	   * as CA.
	   */

	  name_size = sizeof (name);
	  ret =
	    gnutls_x509_crt_get_dn (x509_cert_list[i - 2], name, &name_size);
	  if (ret < 0)
	    {
	      fprintf (stderr, "get_dn: %s\n", gnutls_strerror (ret));
	      exit (1);
	    }

	  fprintf (outfile, "Certificate[%d]: %s\n", i - 2, name);

	  /* print issuer 
	   */
	  issuer_name_size = sizeof (issuer_name);
	  ret =
	    gnutls_x509_crt_get_issuer_dn (x509_cert_list[i - 2],
					   issuer_name, &issuer_name_size);
	  if (ret < 0)
	    {
	      fprintf (stderr, "get_issuer_dn: %s\n", gnutls_strerror (ret));
	      exit (1);
	    }

	  fprintf (outfile, "\tIssued by: %s\n", issuer_name);

	  /* Get the Issuer's name
	   */
	  name_size = sizeof (name);
	  ret =
	    gnutls_x509_crt_get_dn (x509_cert_list[i - 1], name, &name_size);
	  if (ret < 0)
	    {
	      fprintf (stderr, "get_dn: %s\n", gnutls_strerror (ret));
	      exit (1);
	    }

	  fprintf (outfile, "\tVerifying against certificate[%d].\n", i - 1);

	  if (strcmp (issuer_name, name) != 0)
	    {
	      fprintf (stderr, "Error: Issuer's name: %s\n", name);
	      fprintf (stderr,
		       "Error: Issuer's name does not match the next certificate.\n");
	      exit (1);
	    }

	  fprintf (outfile, "\tVerification output: ");
	  print_verification_res (x509_cert_list[i - 2],
				  x509_cert_list[i - 1], x509_crl_list,
				  x509_ncrls);
	  fprintf (outfile, ".\n\n");

	}


      /* now we move ptr after the pem header 
       */
      ptr = strstr (ptr, CERT_SEP);
      if (ptr != NULL)
	ptr++;

      i++;
    }
  while ((ptr = strstr (ptr, CERT_SEP)) != NULL);

  x509_ncerts = i - 1;

  /* The last certificate in the list will be used as
   * a CA (should be self signed).
   */
  name_size = sizeof (name);
  ret =
    gnutls_x509_crt_get_dn (x509_cert_list[x509_ncerts - 1], name,
			    &name_size);
  if (ret < 0)
    {
      fprintf (stderr, "get_dn: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  fprintf (outfile, "Certificate[%d]: %s\n", x509_ncerts - 1, name);

  /* print issuer 
   */
  issuer_name_size = sizeof (issuer_name);
  ret =
    gnutls_x509_crt_get_issuer_dn (x509_cert_list[x509_ncerts - 1],
				   issuer_name, &issuer_name_size);
  if (ret < 0)
    {
      fprintf (stderr, "get_issuer_dn: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  fprintf (outfile, "\tIssued by: %s\n", name);

  if (strcmp (issuer_name, name) != 0)
    {
      fprintf (stderr, "Error: The last certificate is not self signed.\n");
      exit (1);
    }

  fprintf (outfile, "\tVerification output: ");
  print_verification_res (x509_cert_list[x509_ncerts - 1],
			  x509_cert_list[x509_ncerts - 1], x509_crl_list,
			  x509_ncrls);

  fprintf (outfile, ".\n\n");

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

  return 0;
}

static void
print_verification_res (gnutls_x509_crt crt,
			gnutls_x509_crt issuer,
			gnutls_x509_crl * crl_list, int crl_list_size)
{
  unsigned int output;
  int comma = 0;
  int ret;
  time_t now = time (0);

  ret = gnutls_x509_crt_verify (crt, &issuer, 1, 0, &output);
  if (ret < 0)
    {
      fprintf (stderr, "Error in verification: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  if (output & GNUTLS_CERT_INVALID)
    {
      fprintf (outfile, "Not verified");
      comma = 1;
    }
  else
    {
      fprintf (outfile, "Verified");
      comma = 1;
    }

  if (output & GNUTLS_CERT_SIGNER_NOT_CA)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Issuer is not a CA");
      comma = 1;
    }

  if (output & GNUTLS_CERT_INSECURE_ALGORITHM)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Insecure algorithm");
      comma = 1;
    }

  /* Check expiration dates.
   */

  if (gnutls_x509_crt_get_activation_time (crt) > now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Not activated");
    }

  if (gnutls_x509_crt_get_expiration_time (crt) < now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Expired");
    }

  ret = gnutls_x509_crt_check_revocation (crt, crl_list, crl_list_size);
  if (ret < 0)
    {
      fprintf (stderr, "Error in verification: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  if (ret == 1)
    {				/* revoked */
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Revoked");
    }
}

void
verify_chain (void)
{
  size_t size;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  _verify_x509_mem (buffer, size);

}

void
verify_crl (void)
{
  size_t size, dn_size;
  char dn[128];
  unsigned int output;
  int comma = 0;
  int ret;
  gnutls_datum pem;
  gnutls_x509_crl crl;
  time_t now = time (0);
  gnutls_x509_crt issuer;

  issuer = load_ca_cert ();

  fprintf (outfile, "\nCA certificate:\n");
  dn_size = sizeof (dn);
  ret = gnutls_x509_crt_get_dn (issuer, dn, &dn_size);
  if (ret >= 0)
    fprintf (outfile, "\tSubject: %s\n\n", dn);

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  pem.data = buffer;
  pem.size = size;

  gnutls_x509_crl_init (&crl);

  ret = gnutls_x509_crl_import (crl, &pem, in_cert_format);
  if (ret < 0)
    {
      fprintf (stderr, "CRL decoding error: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  print_crl_info (crl, outfile, 1);


  fprintf (outfile, "Verification output: ");
  ret = gnutls_x509_crl_verify (crl, &issuer, 1, 0, &output);
  if (ret < 0)
    {
      fprintf (stderr, "Error in verification: %s\n", gnutls_strerror (ret));
      exit (1);
    }

  if (output & GNUTLS_CERT_INVALID)
    {
      fprintf (outfile, "Not verified");
      comma = 1;
    }
  else
    {
      fprintf (outfile, "Verified");
      comma = 1;
    }

  if (output & GNUTLS_CERT_SIGNER_NOT_CA)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Issuer is not a CA");
      comma = 1;
    }

  if (output & GNUTLS_CERT_INSECURE_ALGORITHM)
    {
      if (comma)
	fprintf (outfile, ", ");
      fprintf (outfile, "Insecure algorithm");
      comma = 1;
    }

  /* Check expiration dates.
   */

  if (gnutls_x509_crl_get_this_update (crl) > now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "Issued in the future!");
    }

  if (gnutls_x509_crl_get_next_update (crl) < now)
    {
      if (comma)
	fprintf (outfile, ", ");
      comma = 1;
      fprintf (outfile, "CRL is not up to date");
    }

  fprintf (outfile, "\n");

}

#include <gnutls/pkcs12.h>
#include <unistd.h>

void
generate_pkcs12 (void)
{
  gnutls_pkcs12 pkcs12;
  gnutls_x509_crt *crts;
  gnutls_x509_privkey key;
  int result;
  size_t size;
  gnutls_datum data;
  const char *password;
  const char *name;
  unsigned int flags;
  gnutls_datum key_id;
  unsigned char _key_id[20];
  int index;
  int ncrts;
  int i;

  fprintf (stderr, "Generating a PKCS #12 structure...\n");

  key = load_private_key (0);
  crts = load_cert_list (0, &ncrts);

  name = get_pkcs12_key_name ();

  if (info.pass)
    password = info.pass;
  else
    password = get_pass ();

  result = gnutls_pkcs12_init (&pkcs12);
  if (result < 0)
    {
      fprintf (stderr, "pkcs12_init: %s\n", gnutls_strerror (result));
      exit (1);
    }

  for (i = 0; i < ncrts; i++)
    {
      gnutls_pkcs12_bag bag;

      result = gnutls_pkcs12_bag_init (&bag);
      if (result < 0)
	{
	  fprintf (stderr, "bag_init: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      result = gnutls_pkcs12_bag_set_crt (bag, crts[i]);
      if (result < 0)
	{
	  fprintf (stderr, "set_crt[%d]: %s\n", i, gnutls_strerror (result));
	  exit (1);
	}

      index = result;

      result = gnutls_pkcs12_bag_set_friendly_name (bag, index, name);
      if (result < 0)
	{
	  fprintf (stderr, "bag_set_friendly_name: %s\n",
		   gnutls_strerror (result));
	  exit (1);
	}

      size = sizeof (_key_id);
      result = gnutls_x509_crt_get_key_id (crts[i], 0, _key_id, &size);
      if (result < 0)
	{
	  fprintf (stderr, "key_id[%d]: %s\n", i, gnutls_strerror (result));
	  exit (1);
	}

      key_id.data = _key_id;
      key_id.size = size;

      result = gnutls_pkcs12_bag_set_key_id (bag, index, &key_id);
      if (result < 0)
	{
	  fprintf (stderr, "bag_set_key_id: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = GNUTLS_PKCS8_USE_PKCS12_3DES;

      result = gnutls_pkcs12_bag_encrypt (bag, password, flags);
      if (result < 0)
	{
	  fprintf (stderr, "bag_encrypt: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      result = gnutls_pkcs12_set_bag (pkcs12, bag);
      if (result < 0)
	{
	  fprintf (stderr, "set_bag: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  if (key)
    {
      gnutls_pkcs12_bag kbag;

      result = gnutls_pkcs12_bag_init (&kbag);
      if (result < 0)
	{
	  fprintf (stderr, "bag_init: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      if (info.export)
	flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
      else
	flags = GNUTLS_PKCS_USE_PKCS12_3DES;

      size = sizeof (buffer);
      result =
	gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER,
					  password, flags, buffer, &size);
      if (result < 0)
	{
	  fprintf (stderr, "key_export: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      data.data = buffer;
      data.size = size;
      result =
	gnutls_pkcs12_bag_set_data (kbag,
				    GNUTLS_BAG_PKCS8_ENCRYPTED_KEY, &data);
      if (result < 0)
	{
	  fprintf (stderr, "bag_set_data: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      index = result;

      result = gnutls_pkcs12_bag_set_friendly_name (kbag, index, name);
      if (result < 0)
	{
	  fprintf (stderr, "bag_set_friendly_name: %s\n",
		   gnutls_strerror (result));
	  exit (1);
	}

      size = sizeof (_key_id);
      result = gnutls_x509_privkey_get_key_id (key, 0, _key_id, &size);
      if (result < 0)
	{
	  fprintf (stderr, "key_id: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      key_id.data = _key_id;
      key_id.size = size;

      result = gnutls_pkcs12_bag_set_key_id (kbag, index, &key_id);
      if (result < 0)
	{
	  fprintf (stderr, "bag_set_key_id: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      result = gnutls_pkcs12_set_bag (pkcs12, kbag);
      if (result < 0)
	{
	  fprintf (stderr, "set_bag: %s\n", gnutls_strerror (result));
	  exit (1);
	}
    }

  result = gnutls_pkcs12_generate_mac (pkcs12, password);
  if (result < 0)
    {
      fprintf (stderr, "generate_mac: %s\n", gnutls_strerror (result));
      exit (1);
    }

  size = sizeof (buffer);
  result = gnutls_pkcs12_export (pkcs12, out_cert_format, buffer, &size);
  if (result < 0)
    {
      fprintf (stderr, "pkcs12_export: %s\n", gnutls_strerror (result));
      exit (1);
    }

  fwrite (buffer, 1, size, outfile);

}

const char *
BAGTYPE (gnutls_pkcs12_bag_type x)
{
  switch (x)
    {
    case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
      return "PKCS #8 Encrypted key";
    case GNUTLS_BAG_EMPTY:
      return "Empty";
    case GNUTLS_BAG_PKCS8_KEY:
      return "PKCS #8 Key";
    case GNUTLS_BAG_CERTIFICATE:
      return "Certificate";
    case GNUTLS_BAG_ENCRYPTED:
      return "Encrypted";
    case GNUTLS_BAG_CRL:
      return "CRL";
    default:
      return "Unknown";
    }
}

void
print_bag_data (gnutls_pkcs12_bag bag)
{
  int result;
  int count, i, type;
  gnutls_datum cdata, id;
  const char *str, *name;
  gnutls_datum out;

  count = gnutls_pkcs12_bag_get_count (bag);
  if (count < 0)
    {
      fprintf (stderr, "get_count: %s\n", gnutls_strerror (count));
      exit (1);
    }



  fprintf (outfile, "\tElements: %d\n", count);

  for (i = 0; i < count; i++)
    {
      type = gnutls_pkcs12_bag_get_type (bag, i);
      if (type < 0)
	{
	  fprintf (stderr, "get_type: %s\n", gnutls_strerror (type));
	  exit (1);
	}

      fprintf (stderr, "\tType: %s\n", BAGTYPE (type));

      name = NULL;
      result = gnutls_pkcs12_bag_get_friendly_name (bag, i, (char **) &name);
      if (result < 0)
	{
	  fprintf (stderr, "get_friendly_name: %s\n", gnutls_strerror (type));
	  exit (1);
	}
      if (name)
	fprintf (outfile, "\tFriendly name: %s\n", name);

      id.data = NULL;
      id.size = 0;
      result = gnutls_pkcs12_bag_get_key_id (bag, i, &id);
      if (result < 0)
	{
	  fprintf (stderr, "get_key_id: %s\n", gnutls_strerror (type));
	  exit (1);
	}
      fprintf (outfile, "\tKey ID: %s\n", raw_to_string (id.data, id.size));

      result = gnutls_pkcs12_bag_get_data (bag, i, &cdata);
      if (result < 0)
	{
	  fprintf (stderr, "get_data: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      switch (type)
	{
	case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
	  str = "ENCRYPTED PRIVATE KEY";
	  break;
	case GNUTLS_BAG_PKCS8_KEY:
	  str = "PRIVATE KEY";
	  break;
	case GNUTLS_BAG_CERTIFICATE:
	  str = "CERTIFICATE";
	  break;
	case GNUTLS_BAG_CRL:
	  str = "CRL";
	  break;
	case GNUTLS_BAG_ENCRYPTED:
	case GNUTLS_BAG_EMPTY:
	default:
	  str = NULL;
	}

      if (str != NULL)
	{
	  gnutls_pem_base64_encode_alloc (str, &cdata, &out);
	  fprintf (outfile, "%s\n", out.data);

	  gnutls_free (out.data);
	}

    }
}

void
pkcs12_info (void)
{
  gnutls_pkcs12 pkcs12;
  gnutls_pkcs12_bag bag;
  int result, ret;
  size_t size;
  gnutls_datum data;
  const char *password;
  int index;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  data.data = buffer;
  data.size = size;

  if (info.pass)
    password = info.pass;
  else
    password = get_pass ();

  result = gnutls_pkcs12_init (&pkcs12);
  if (result < 0)
    {
      fprintf (stderr, "p12_init: %s\n", gnutls_strerror (result));
      exit (1);
    }

  result = gnutls_pkcs12_import (pkcs12, &data, in_cert_format, 0);
  if (result < 0)
    {
      fprintf (stderr, "p12_import: %s\n", gnutls_strerror (result));
      exit (1);
    }

  result = gnutls_pkcs12_verify_mac (pkcs12, password);
  if (result < 0)
    {
      fprintf (stderr, "verify_mac: %s\n", gnutls_strerror (result));
      exit (1);
    }



  index = 0;

  do
    {
      result = gnutls_pkcs12_bag_init (&bag);
      if (result < 0)
	{
	  fprintf (stderr, "bag_init: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      ret = gnutls_pkcs12_get_bag (pkcs12, index, bag);
      if (ret < 0)
	{
	  break;
	}

      result = gnutls_pkcs12_bag_get_count (bag);
      if (result < 0)
	{
	  fprintf (stderr, "bag_init: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      fprintf (outfile, "BAG #%d\n", index);

      result = gnutls_pkcs12_bag_get_type (bag, 0);
      if (result < 0)
	{
	  fprintf (stderr, "bag_init: %s\n", gnutls_strerror (result));
	  exit (1);
	}


      if (result == GNUTLS_BAG_ENCRYPTED)
	{
	  fprintf (stderr, "\tType: %s\n", BAGTYPE (result));
	  fprintf (stderr, "\n\tDecrypting...\n");

	  result = gnutls_pkcs12_bag_decrypt (bag, password);

	  if (result < 0)
	    {
	      fprintf (stderr, "bag_decrypt: %s\n", gnutls_strerror (result));
	      exit (1);
	    }

	  result = gnutls_pkcs12_bag_get_count (bag);
	  if (result < 0)
	    {
	      fprintf (stderr, "get_count: %s\n", gnutls_strerror (result));
	      exit (1);
	    }

	}

      print_bag_data (bag);

      gnutls_pkcs12_bag_deinit (bag);

      index++;
    }
  while (ret == 0);


}

void
pkcs7_info (void)
{
  gnutls_pkcs7 pkcs7;
  int result;
  size_t size;
  gnutls_datum data, b64;
  int index, count;

  size = fread (buffer, 1, sizeof (buffer) - 1, infile);
  buffer[size] = 0;

  data.data = buffer;
  data.size = size;

  result = gnutls_pkcs7_init (&pkcs7);
  if (result < 0)
    {
      fprintf (stderr, "p7_init: %s\n", gnutls_strerror (result));
      exit (1);
    }

  result = gnutls_pkcs7_import (pkcs7, &data, in_cert_format);
  if (result < 0)
    {
      fprintf (stderr, "p7_import: %s\n", gnutls_strerror (result));
      exit (1);
    }

  /* Read and print the certificates.
   */
  result = gnutls_pkcs7_get_crt_count (pkcs7);
  if (result < 0)
    {
      fprintf (stderr, "p7_count: %s\n", gnutls_strerror (result));
      exit (1);
    }

  count = result;

  if (count > 0)
    fprintf (outfile, "Certificates: %u\n", count);

  for (index = 0; index < count; index++)
    {
      size = sizeof (buffer);
      result = gnutls_pkcs7_get_crt_raw (pkcs7, index, buffer, &size);
      if (result < 0)
	{
	  break;
	}

      data.data = buffer;
      data.size = size;

      result = gnutls_pem_base64_encode_alloc ("CERTIFICATE", &data, &b64);
      if (result < 0)
	{
	  fprintf (stderr, "error encoding: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      fputs (b64.data, outfile);
      fputs ("\n", outfile);
      gnutls_free (b64.data);
    }

  /* Read the CRLs now.
   */
  result = gnutls_pkcs7_get_crl_count (pkcs7);
  if (result < 0)
    {
      fprintf (stderr, "p7_count: %s\n", gnutls_strerror (result));
      exit (1);
    }

  count = result;

  if (count > 0)
    fprintf (outfile, "\nCRLs: %u\n", count);

  for (index = 0; index < count; index++)
    {
      size = sizeof (buffer);
      result = gnutls_pkcs7_get_crl_raw (pkcs7, index, buffer, &size);
      if (result < 0)
	{
	  break;
	}

      data.data = buffer;
      data.size = size;

      result = gnutls_pem_base64_encode_alloc ("X509 CRL", &data, &b64);
      if (result < 0)
	{
	  fprintf (stderr, "error encoding: %s\n", gnutls_strerror (result));
	  exit (1);
	}

      fputs (b64.data, outfile);
      fputs ("\n", outfile);
      gnutls_free (b64.data);
    }


}

void
smime_to_pkcs7 (void)
{
  size_t linesize = 0;
  char *lineptr = NULL;
  ssize_t len;

  /* Find body.  FIXME: Handle non-b64 Content-Transfer-Encoding.
     Reject non-S/MIME tagged Content-Type's? */
  do
    {
      len = getline (&lineptr, &linesize, infile);
      if (len == -1)
	{
	  fprintf (stderr, "Cannot find RFC 2822 header/body separator\n");
	  exit (1);
	}
    }
  while (strcmp (lineptr, "\r\n") != 0 && strcmp (lineptr, "\n") != 0);

  do
    {
      len = getline (&lineptr, &linesize, infile);
      if (len == -1)
	{
	  fprintf (stderr, "Message has RFC 2822 header but no body\n");
	  exit (1);
	}
    }
  while (strcmp (lineptr, "\r\n") == 0 && strcmp (lineptr, "\n") == 0);

  printf ("-----BEGIN PKCS7-----\n");

  do
    {
      while (len > 0
	     && (lineptr[len - 1] == '\r' || lineptr[len - 1] == '\n'))
	lineptr[--len] = '\0';
      if (strcmp (lineptr, "") != 0)
	printf ("%s\n", lineptr);
      len = getline (&lineptr, &linesize, infile);
    }
  while (len != -1);

  printf ("-----END PKCS7-----\n");

  free (lineptr);
}

#else /* ENABLE_PKI */

#include <stdio.h>

int
main (int argc, char **argv)
{
  printf ("\nX.509 PKI not supported. This program is a dummy.\n\n");
  return 1;
};

#endif

void
certtool_version (void)
{
  const char *v = gnutls_check_version (NULL);

  printf ("certtool (GnuTLS) %s\n", LIBGNUTLS_VERSION);
  if (strcmp (v, LIBGNUTLS_VERSION) != 0)
    printf ("libgnutls %s\n", v);
}

void
print_license (void)
{
  fputs ("\nCopyright (C) 2004 Free Software Foundation\n"
	 "This program is free software; you can redistribute it and/or modify \n"
	 "it under the terms of the GNU General Public License as published by \n"
	 "the Free Software Foundation; either version 2 of the License, or \n"
	 "(at your option) any later version. \n" "\n"
	 "This program is distributed in the hope that it will be useful, \n"
	 "but WITHOUT ANY WARRANTY; without even the implied warranty of \n"
	 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the \n"
	 "GNU General Public License for more details. \n" "\n"
	 "You should have received a copy of the GNU General Public License \n"
	 "along with this program; if not, write to the Free Software \n"
	 "Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n",
	 stdout);
}
