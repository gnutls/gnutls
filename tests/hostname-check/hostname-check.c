/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

char pem[] =
  "X.509 Certificate Information:\n"
  "        Version: 3\n"
  "        Serial Number (hex): 00\n"
  "        Issuer: O=GnuTLS hostname check test CA\n"
  "        Validity:\n"
  "                Not Before: Fri Feb 16 12:59:09 UTC 2007\n"
  "                Not After: Fri Mar 30 12:59:13 UTC 2007\n"
  "        Subject: O=GnuTLS hostname check test CA\n"
  "        Subject Public Key Algorithm: RSA\n"
  "                Modulus (bits 1024):\n"
  "                        be:ec:98:7a:1d:6f:7e:6b:25:9e:e8:20:78:42:a0:64\n"
  "                        05:66:43:99:6d:49:d5:18:ec:7d:b9:58:64:b2:80:a3\n"
  "                        14:61:9d:0a:4f:be:2f:f0:2e:fc:d2:ab:5c:36:df:53\n"
  "                        ec:43:c7:fc:de:91:bc:1e:01:a6:b7:6c:b2:07:10:2e\n"
  "                        cb:61:47:75:ca:03:ce:23:6e:38:f1:34:27:1a:1a:cd\n"
  "                        f7:96:f3:b3:f0:0d:67:7f:ca:77:84:3f:9c:29:f4:62\n"
  "                        91:f6:12:5b:62:5a:cc:ba:ed:08:2e:32:44:26:ac:fd\n"
  "                        23:ce:53:1b:bb:f2:87:fe:dc:78:93:7c:59:bf:a1:75\n"
  "                Exponent:\n"
  "                        01:00:01\n"
  "        Extensions:\n"
  "                Basic Constraints (critical):\n"
  "                        Certificate Authority (CA): TRUE\n"
  "                Subject Key Identifier (not critical):\n"
  "                        e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "        Signature Algorithm: RSA-SHA\n"
  "        Signature:\n"
  "                7b:e8:11:6c:15:3f:f9:01:a0:f1:28:0c:62:50:58:f8\n"
  "                92:44:fb:bf:ab:20:8a:3b:81:ca:e5:68:60:71:df:2b\n"
  "                e8:50:58:82:32:ef:fb:6e:4a:72:2c:c9:37:4f:88:1d\n"
  "                d7:1b:68:5b:db:83:1b:1a:f3:b4:8e:e0:88:03:e2:43\n"
  "                91:be:d8:b1:ca:f2:62:ec:a1:fd:1a:c8:41:8c:fe:53\n"
  "                1b:be:03:c9:a1:3d:f4:ae:57:fc:44:a6:34:bb:2c:2e\n"
  "                a7:56:14:1f:89:e9:3a:ec:1f:a3:da:d7:a1:94:3b:72\n"
  "                1d:12:71:b9:65:a1:85:a2:4c:3a:d1:2c:e9:e9:ea:1c\n"
  "Other Information:\n"
  "        MD5 fingerprint:\n"
  "                fd845ded8c28ba5e78d6c1844ceafd24\n"
  "        SHA-1 fingerprint:\n"
  "                0bae431dda3cae76012b82276e4cd92ad7961798\n"
  "        Public Key Id:\n"
  "                e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB8TCCAVygAwIBAgIBADALBgkqhkiG9w0BAQUwKDEmMCQGA1UEChMdR251VExT\n"
  "IGhvc3RuYW1lIGNoZWNrIHRlc3QgQ0EwHhcNMDcwMjE2MTI1OTA5WhcNMDcwMzMw\n"
  "MTI1OTEzWjAoMSYwJAYDVQQKEx1HbnVUTFMgaG9zdG5hbWUgY2hlY2sgdGVzdCBD\n"
  "QTCBnDALBgkqhkiG9w0BAQEDgYwAMIGIAoGAvuyYeh1vfmslnuggeEKgZAVmQ5lt\n"
  "SdUY7H25WGSygKMUYZ0KT74v8C780qtcNt9T7EPH/N6RvB4BprdssgcQLsthR3XK\n"
  "A84jbjjxNCcaGs33lvOz8A1nf8p3hD+cKfRikfYSW2JazLrtCC4yRCas/SPOUxu7\n"
  "8of+3HiTfFm/oXUCAwEAAaMyMDAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU\n"
  "6Twc+62SbuYGpFYsouHAUyfI8pUwCwYJKoZIhvcNAQEFA4GBAHvoEWwVP/kBoPEo\n"
  "DGJQWPiSRPu/qyCKO4HK5Whgcd8r6FBYgjLv+25KcizJN0+IHdcbaFvbgxsa87SO\n"
  "4IgD4kORvtixyvJi7KH9GshBjP5TG74DyaE99K5X/ESmNLssLqdWFB+J6TrsH6Pa\n"
  "16GUO3IdEnG5ZaGFokw60Szp6eoc\n"
  "-----END CERTIFICATE-----\n";

void
doit (void)
{
  gnutls_x509_crt_t cert;
  gnutls_datum_t data;
  int ret;

  data.data = pem;
  data.size = strlen (pem);

  ret = gnutls_global_init ();
  if (ret < 0)
    fail ("gnutls_global_init: %d\n", ret);

  ret = gnutls_x509_crt_init (&cert);
  if (ret < 0)
    fail ("gnutls_x509_crt_init: %d\n", ret);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname match failure (%d)\n", ret);
  else
    success ("gnutls_x509_crt_check_hostname: %d\n", ret);

  gnutls_x509_crt_deinit (cert);

  gnutls_global_deinit ();
}
