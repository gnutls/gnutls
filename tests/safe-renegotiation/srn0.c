/*
 * Copyright (C) 2008, 2010 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Code based on ../mini-x509-rehandshake.c.
 *
 * This tests that the safe renegotiation extension is negotiated
 * properly by default on initial connections and on rehandshaked
 * connections.  Consequently, it also verifies that rehandshaked
 * connections work with the extension enabled.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

static char *to_server;
static size_t to_server_len;

static char *to_client;
static size_t to_client_len;

static ssize_t
client_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  if (to_client_len < len)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  memcpy (data, to_client, len);

  memmove (to_client, to_client + len, to_client_len - len);
  to_client_len -= len;

  return len;
}

static ssize_t
client_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  size_t newlen = to_server_len + len;
  char *tmp;

  tmp = realloc (to_server, newlen);
  if (!tmp)
    abort ();
  to_server = tmp;

  memcpy (to_server + to_server_len, data, len);
  to_server_len = newlen;

  return len;
}

static ssize_t
server_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  if (to_server_len < len)
    {
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  memcpy (data, to_server, len);

  memmove (to_server, to_server + len, to_server_len - len);
  to_server_len -= len;

  return len;
}

static ssize_t
server_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  size_t newlen = to_client_len + len;
  char *tmp;

  tmp = realloc (to_client, newlen);
  if (!tmp)
    abort ();
  to_client = tmp;

  memcpy (to_client + to_client_len, data, len);
  to_client_len = newlen;

  return len;
}

static unsigned char server_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICVjCCAcGgAwIBAgIERiYdMTALBgkqhkiG9w0BAQUwGTEXMBUGA1UEAxMOR251\n"
  "VExTIHRlc3QgQ0EwHhcNMDcwNDE4MTMyOTIxWhcNMDgwNDE3MTMyOTIxWjA3MRsw\n"
  "GQYDVQQKExJHbnVUTFMgdGVzdCBzZXJ2ZXIxGDAWBgNVBAMTD3Rlc3QuZ251dGxz\n"
  "Lm9yZzCBnDALBgkqhkiG9w0BAQEDgYwAMIGIAoGA17pcr6MM8C6pJ1aqU46o63+B\n"
  "dUxrmL5K6rce+EvDasTaDQC46kwTHzYWk95y78akXrJutsoKiFV1kJbtple8DDt2\n"
  "DZcevensf9Op7PuFZKBroEjOd35znDET/z3IrqVgbtm2jFqab7a+n2q9p/CgMyf1\n"
  "tx2S5Zacc1LWn9bIjrECAwEAAaOBkzCBkDAMBgNVHRMBAf8EAjAAMBoGA1UdEQQT\n"
  "MBGCD3Rlc3QuZ251dGxzLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8B\n"
  "Af8EBQMDB6AAMB0GA1UdDgQWBBTrx0Vu5fglyoyNgw106YbU3VW0dTAfBgNVHSME\n"
  "GDAWgBTpPBz7rZJu5gakViyi4cBTJ8jylTALBgkqhkiG9w0BAQUDgYEAaFEPTt+7\n"
  "bzvBuOf7+QmeQcn29kT6Bsyh1RHJXf8KTk5QRfwp6ogbp94JQWcNQ/S7YDFHglD1\n"
  "AwUNBRXwd3riUsMnsxgeSDxYBfJYbDLeohNBsqaPDJb7XailWbMQKfAbFQ8cnOxg\n"
  "rOKLUQRWJ0K3HyXRMhbqjdLIaQiCvQLuizo=\n" "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
  sizeof (server_cert_pem)
};

static unsigned char server_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIICXAIBAAKBgQDXulyvowzwLqknVqpTjqjrf4F1TGuYvkrqtx74S8NqxNoNALjq\n"
  "TBMfNhaT3nLvxqResm62ygqIVXWQlu2mV7wMO3YNlx696ex/06ns+4VkoGugSM53\n"
  "fnOcMRP/PciupWBu2baMWppvtr6far2n8KAzJ/W3HZLllpxzUtaf1siOsQIDAQAB\n"
  "AoGAYAFyKkAYC/PYF8e7+X+tsVCHXppp8AoP8TEZuUqOZz/AArVlle/ROrypg5kl\n"
  "8YunrvUdzH9R/KZ7saNZlAPLjZyFG9beL/am6Ai7q7Ma5HMqjGU8kTEGwD7K+lbG\n"
  "iomokKMOl+kkbY/2sI5Czmbm+/PqLXOjtVc5RAsdbgvtmvkCQQDdV5QuU8jap8Hs\n"
  "Eodv/tLJ2z4+SKCV2k/7FXSKWe0vlrq0cl2qZfoTUYRnKRBcWxc9o92DxK44wgPi\n"
  "oMQS+O7fAkEA+YG+K9e60sj1K4NYbMPAbYILbZxORDecvP8lcphvwkOVUqbmxOGh\n"
  "XRmTZUuhBrJhJKKf6u7gf3KWlPl6ShKEbwJASC118cF6nurTjuLf7YKARDjNTEws\n"
  "qZEeQbdWYINAmCMj0RH2P0mvybrsXSOD5UoDAyO7aWuqkHGcCLv6FGG+qwJAOVqq\n"
  "tXdUucl6GjOKKw5geIvRRrQMhb/m5scb+5iw8A4LEEHPgGiBaF5NtJZLALgWfo5n\n"
  "hmC8+G8F0F78znQtPwJBANexu+Tg5KfOnzSILJMo3oXiXhf5PqXIDmbN0BKyCKAQ\n"
  "LfkcEcUbVfmDaHpvzwY9VEaoMOKVLitETXdNSxVpvWM=\n"
  "-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { server_key_pem,
  sizeof (server_key_pem)
};

int
main (int argc, char *argv[])
{
  int debug_level = argc - 1;
  int exit_code = EXIT_SUCCESS;
  /* Server stuff. */
  gnutls_certificate_credentials_t serverx509cred;
  gnutls_session_t server;
  int sret = GNUTLS_E_AGAIN;
  /* Client stuff. */
  gnutls_certificate_credentials_t clientx509cred;
  gnutls_session_t client;
  int cret = GNUTLS_E_AGAIN;

  /* General init. */
  gnutls_global_init ();
  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (debug_level);

  /* Init server */
  gnutls_certificate_allocate_credentials (&serverx509cred);
  gnutls_certificate_set_x509_key_mem (serverx509cred,
				       &server_cert, &server_key,
				       GNUTLS_X509_FMT_PEM);
  gnutls_init (&server, GNUTLS_SERVER);
  gnutls_credentials_set (server, GNUTLS_CRD_CERTIFICATE, serverx509cred);
  gnutls_priority_set_direct (server, "NORMAL", NULL);
  gnutls_transport_set_push_function (server, server_push);
  gnutls_transport_set_pull_function (server, server_pull);

  /* Init client */
  gnutls_certificate_allocate_credentials (&clientx509cred);
  gnutls_init (&client, GNUTLS_CLIENT);
  gnutls_credentials_set (client, GNUTLS_CRD_CERTIFICATE, clientx509cred);
  gnutls_priority_set_direct (client, "NORMAL", NULL);
  gnutls_transport_set_push_function (client, client_push);
  gnutls_transport_set_pull_function (client, client_pull);

  /* Check that initially no session use the extension. */
  if (gnutls_safe_renegotiation_status (server)
      || gnutls_safe_renegotiation_status (client))
    {
      puts ("Client or server using extension before handshake?");
      abort ();
    }

  do
    {
      static int max_iter = 0;
      if (max_iter++ > 10)
	abort ();

      if (cret == GNUTLS_E_AGAIN)
	{
	  cret = gnutls_handshake (client);
	  if (debug_level > 0)
	    {
	      tls_log_func (0, "gnutls_handshake (client)...\n");
	      tls_log_func (0, gnutls_strerror (cret));
	      tls_log_func (0, "\n");
	    }
	}

      if (sret == GNUTLS_E_AGAIN)
	{
	  sret = gnutls_handshake (server);
	  if (debug_level > 0)
	    {
	      tls_log_func (0, "gnutls_handshake (server)...\n");
	      tls_log_func (0, gnutls_strerror (sret));
	      tls_log_func (0, "\n");
	    }
	}
    }
  while (
	  /* Not done: */
	  !(cret == GNUTLS_E_SUCCESS && sret == GNUTLS_E_SUCCESS)
	  /* No error: */
	  && (cret == GNUTLS_E_AGAIN || sret == GNUTLS_E_AGAIN));

  if (cret != GNUTLS_E_SUCCESS && sret != GNUTLS_E_SUCCESS)
    exit_code = EXIT_FAILURE;

  if (!gnutls_safe_renegotiation_status (client) ||
      !gnutls_safe_renegotiation_status (server))
    {
      tls_log_func (0, "Session not using safe renegotiation!\n");
      exit_code = EXIT_FAILURE;
    }

  sret = gnutls_rehandshake (server);
  if (debug_level > 0)
    {
      tls_log_func (0, "gnutls_rehandshake (server)...\n");
      tls_log_func (0, gnutls_strerror (sret));
      tls_log_func (0, "\n");
    }

  {
    ssize_t n;
    char b[1];
    n = gnutls_record_recv (client, b, 1);
    if (n != GNUTLS_E_REHANDSHAKE)
      abort ();
  }

  cret = GNUTLS_E_AGAIN;
  sret = GNUTLS_E_AGAIN;

  do
    {
      static int max_iter = 0;
      if (max_iter++ > 10)
	abort ();

      if (cret == GNUTLS_E_AGAIN)
	{
	  cret = gnutls_handshake (client);
	  if (debug_level > 0)
	    {
	      tls_log_func (0, "second gnutls_handshake (client)...\n");
	      tls_log_func (0, gnutls_strerror (cret));
	      tls_log_func (0, "\n");
	    }
	}

      if (sret == GNUTLS_E_AGAIN)
	{
	  sret = gnutls_handshake (server);
	  if (debug_level > 0)
	    {
	      tls_log_func (0, "second gnutls_handshake (server)...\n");
	      tls_log_func (0, gnutls_strerror (sret));
	      tls_log_func (0, "\n");
	    }
	}
    }
  while (
	  /* Not done: */
	  !(cret == GNUTLS_E_SUCCESS && sret == GNUTLS_E_SUCCESS)
	  /* No error: */
	  && (cret == GNUTLS_E_AGAIN || sret == GNUTLS_E_AGAIN));

  if (cret != GNUTLS_E_SUCCESS && sret != GNUTLS_E_SUCCESS)
    exit_code = 1;

  if (!gnutls_safe_renegotiation_status (client) ||
      !gnutls_safe_renegotiation_status (server))
    {
      tls_log_func (0,
		    "Rehandshaked session not using safe renegotiation!\n");
      exit_code = EXIT_FAILURE;
    }

  gnutls_bye (client, GNUTLS_SHUT_RDWR);
  gnutls_bye (server, GNUTLS_SHUT_RDWR);

  gnutls_deinit (client);
  gnutls_deinit (server);

  free (to_server);
  free (to_client);

  gnutls_certificate_free_credentials (serverx509cred);

  gnutls_global_deinit ();

  if (debug_level > 0)
    {
      if (exit_code == 0)
	puts ("Self-test successful");
      else
	puts ("Self-test failed");
    }

  return exit_code;
}
