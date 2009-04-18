/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Parts copied from GnuTLS example programs. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "ex-session-info.c"
#include "ex-x509-info.c"

#include "utils.h"

pid_t child;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "%s |<%d>| %s", child ? "server" : "client", level, str);
}

/* A very basic TLS client, with anonymous authentication.
 */

/* sha1 hash of "hello" string */
const gnutls_datum_t hash_data = {
  (void*)"\xaa\xf4\xc6\x1d\xdc\xc5\xe8\xa2\xda\xbe\xde\x0f\x3b\x48\x2c\xd9\xae\xa9\x43\x4d",
  20
};

const gnutls_datum_t raw_data = {
  (void*)"hello",
  5
};

static char cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICHjCCAYmgAwIBAgIERiYdNzALBgkqhkiG9w0BAQUwGTEXMBUGA1UEAxMOR251\n"
  "VExTIHRlc3QgQ0EwHhcNMDcwNDE4MTMyOTI3WhcNMDgwNDE3MTMyOTI3WjAdMRsw\n"
  "GQYDVQQDExJHbnVUTFMgdGVzdCBjbGllbnQwgZwwCwYJKoZIhvcNAQEBA4GMADCB\n"
  "iAKBgLtmQ/Xyxde2jMzF3/WIO7HJS2oOoa0gUEAIgKFPXKPQ+GzP5jz37AR2ExeL\n"
  "ZIkiW8DdU3w77XwEu4C5KL6Om8aOoKUSy/VXHqLnu7czSZ/ju0quak1o/8kR4jKN\n"
  "zj2AC41179gAgY8oBAOgIo1hBAf6tjd9IQdJ0glhaZiQo1ipAgMBAAGjdjB0MAwG\n"
  "A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDwYDVR0PAQH/BAUDAweg\n"
  "ADAdBgNVHQ4EFgQUTLkKm/odNON+3svSBxX+odrLaJEwHwYDVR0jBBgwFoAU6Twc\n"
  "+62SbuYGpFYsouHAUyfI8pUwCwYJKoZIhvcNAQEFA4GBALujmBJVZnvaTXr9cFRJ\n"
  "jpfc/3X7sLUsMvumcDE01ls/cG5mIatmiyEU9qI3jbgUf82z23ON/acwJf875D3/\n"
  "U7jyOsBJ44SEQITbin2yUeJMIm1tievvdNXBDfW95AM507ShzP12sfiJkJfjjdhy\n"
  "dc8Siq5JojruiMizAf0pA7in\n" "-----END CERTIFICATE-----\n";
const gnutls_datum_t cert = { cert_pem, sizeof (cert_pem) };

char key_pem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQC7ZkP18sXXtozMxd/1iDuxyUtqDqGtIFBACIChT1yj0Phsz+Y8\n"
    "9+wEdhMXi2SJIlvA3VN8O+18BLuAuSi+jpvGjqClEsv1Vx6i57u3M0mf47tKrmpN\n"
    "aP/JEeIyjc49gAuNde/YAIGPKAQDoCKNYQQH+rY3fSEHSdIJYWmYkKNYqQIDAQAB\n"
    "AoGADpmARG5CQxS+AesNkGmpauepiCz1JBF/JwnyiX6vEzUh0Ypd39SZztwrDxvF\n"
    "PJjQaKVljml1zkJpIDVsqvHdyVdse8M+Qn6hw4x2p5rogdvhhIL1mdWo7jWeVJTF\n"
    "RKB7zLdMPs3ySdtcIQaF9nUAQ2KJEvldkO3m/bRJFEp54k0CQQDYy+RlTmwRD6hy\n"
    "7UtMjR0H3CSZJeQ8svMCxHLmOluG9H1UKk55ZBYfRTsXniqUkJBZ5wuV1L+pR9EK\n"
    "ca89a+1VAkEA3UmBelwEv2u9cAU1QjKjmwju1JgXbrjEohK+3B5y0ESEXPAwNQT9\n"
    "TrDM1m9AyxYTWLxX93dI5QwNFJtmbtjeBQJARSCWXhsoaDRG8QZrCSjBxfzTCqZD\n"
    "ZXtl807ymCipgJm60LiAt0JLr4LiucAsMZz6+j+quQbSakbFCACB8SLV1QJBAKZQ\n"
    "YKf+EPNtnmta/rRKKvySsi3GQZZN+Dt3q0r094XgeTsAqrqujVNfPhTMeP4qEVBX\n"
    "/iVX2cmMTSh3w3z8MaECQEp0XJWDVKOwcTW6Ajp9SowtmiZ3YDYo1LF9igb4iaLv\n"
    "sWZGfbnU3ryjvkb6YuFjgtzbZDZHWQCo8/cOtOBmPdk=\n"
    "-----END RSA PRIVATE KEY-----\n";
const gnutls_datum_t key_dat = { key_pem, sizeof (key_pem) };

void
doit (void)
{
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t crt;
  gnutls_digest_algorithm_t hash_algo;
  unsigned char _signature[128];
  size_t _signature_size = sizeof(_signature);
  gnutls_datum signature;
  int ret;

  gnutls_global_init ();

  gnutls_global_set_log_function (tls_log_func);
//  if (debug)
    gnutls_global_set_log_level (4711);

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    fail("gnutls_x509_privkey_init\n");

  ret = gnutls_x509_privkey_import (key, &key_dat, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail("gnutls_x509_privkey_import\n");

  ret = gnutls_x509_privkey_sign_data (key, GNUTLS_DIG_SHA1, 0, &raw_data, _signature, &_signature_size);
  if (ret < 0)
    fail("gnutls_x509_privkey_sign_hash\n");

  ret = gnutls_x509_crt_init (&crt);
  if (ret < 0)
    fail("gnutls_x509_crt_init\n");

  ret = gnutls_x509_crt_import (crt, &cert, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail("gnutls_x509_crt_import\n");

  signature.data = _signature;
  signature.size = _signature_size;

  ret = gnutls_x509_crt_get_verify_algorithm(crt, &signature, &hash_algo);
  if (ret < 0 || hash_algo != GNUTLS_DIG_SHA1)
    fail("gnutls_x509_crt_get_verify_algorithm\n");
  
  ret = gnutls_x509_crt_verify_hash (crt, 0, &hash_data, &signature);
  if (ret < 0)
    fail("gnutls_x509_privkey_verify_hash\n");

  gnutls_x509_privkey_deinit (key);
  gnutls_x509_crt_deinit (crt);
  return;
}


