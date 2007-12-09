/*
 * Copyright (C) 2007 Free Software Foundation
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

/* Certificate with no SAN nor CN. */
char pem1[] =
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

/* Certificate with CN but no SAN. */
char pem2[] =
  "X.509 Certificate Information:\n"
  "        Version: 3\n"
  "        Serial Number (hex): 00\n"
  "        Issuer: CN=www.example.org\n"
  "        Validity:\n"
  "                Not Before: Fri Feb 16 13:30:30 UTC 2007\n"
  "                Not After: Fri Mar 30 13:30:32 UTC 2007\n"
  "        Subject: CN=www.example.org\n"
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
  "                b0:4e:ac:fb:89:12:36:27:f3:72:b8:1a:57:dc:bf:f3\n"
  "                a9:27:de:15:75:94:4f:65:cc:3a:59:12:4b:91:0e:28\n"
  "                b9:8d:d3:6e:ac:5d:a8:3e:b9:35:81:0c:8f:c7:95:72\n"
  "                d9:51:61:06:00:c6:aa:68:54:c8:52:3f:b6:1f:21:92\n"
  "                c8:fd:15:50:15:ac:d4:18:29:a1:ff:c9:25:5a:ce:5e\n"
  "                11:7f:82:b2:94:8c:44:3c:3f:de:d7:3b:ff:1c:da:9c\n"
  "                81:fa:63:e1:a7:67:ee:aa:fa:d0:c9:2f:66:1b:5e:af\n"
  "                46:8c:f9:53:55:e7:80:7e:74:95:98:d4:2d:5f:94:ab\n"
  "Other Information:\n"
  "        MD5 fingerprint:\n"
  "                30cda7de4f0360892547974f45111ac1\n"
  "        SHA-1 fingerprint:\n"
  "                39e3f8fec6a8d842390b6536998a957c1a6b7322\n"
  "        Public Key Id:\n"
  "                e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB1TCCAUCgAwIBAgIBADALBgkqhkiG9w0BAQUwGjEYMBYGA1UEAxMPd3d3LmV4\n"
  "YW1wbGUub3JnMB4XDTA3MDIxNjEzMzAzMFoXDTA3MDMzMDEzMzAzMlowGjEYMBYG\n"
  "A1UEAxMPd3d3LmV4YW1wbGUub3JnMIGcMAsGCSqGSIb3DQEBAQOBjAAwgYgCgYC+\n"
  "7Jh6HW9+ayWe6CB4QqBkBWZDmW1J1RjsfblYZLKAoxRhnQpPvi/wLvzSq1w231Ps\n"
  "Q8f83pG8HgGmt2yyBxAuy2FHdcoDziNuOPE0JxoazfeW87PwDWd/yneEP5wp9GKR\n"
  "9hJbYlrMuu0ILjJEJqz9I85TG7vyh/7ceJN8Wb+hdQIDAQABozIwMDAPBgNVHRMB\n"
  "Af8EBTADAQH/MB0GA1UdDgQWBBTpPBz7rZJu5gakViyi4cBTJ8jylTALBgkqhkiG\n"
  "9w0BAQUDgYEAsE6s+4kSNifzcrgaV9y/86kn3hV1lE9lzDpZEkuRDii5jdNurF2o\n"
  "Prk1gQyPx5Vy2VFhBgDGqmhUyFI/th8hksj9FVAVrNQYKaH/ySVazl4Rf4KylIxE\n"
  "PD/e1zv/HNqcgfpj4adn7qr60MkvZhter0aM+VNV54B+dJWY1C1flKs=\n"
  "-----END CERTIFICATE-----\n";

/* Certificate with SAN but no CN. */
char pem3[] =
  "X.509 Certificate Information:"
  "        Version: 3\n"
  "        Serial Number (hex): 00\n"
  "        Issuer: O=GnuTLS hostname check test CA\n"
  "        Validity:\n"
  "                Not Before: Fri Feb 16 13:36:27 UTC 2007\n"
  "                Not After: Fri Mar 30 13:36:29 UTC 2007\n"
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
  "                Subject Alternative Name (not critical):\n"
  "                        DNSname: www.example.org\n"
  "                Key Purpose (not critical):\n"
  "                        TLS WWW Server.\n"
  "                Subject Key Identifier (not critical):\n"
  "                        e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "        Signature Algorithm: RSA-SHA\n"
  "        Signature:\n"
  "                a1:30:bc:01:b3:0f:98:7f:8e:76:7d:23:87:34:15:7f\n"
  "                a6:ae:a1:fb:87:75:e3:e8:1a:e5:5e:03:5d:bf:44:75\n"
  "                46:4f:d2:a1:28:50:84:49:6d:3b:e0:bc:4e:de:79:85\n"
  "                fa:e1:07:b7:6e:0c:14:04:4a:82:b9:f3:22:6a:bc:99\n"
  "                14:20:3b:49:1f:e4:97:d9:ea:eb:73:9a:83:a6:cc:b8\n"
  "                55:fb:52:8e:5f:86:7c:9d:fa:af:03:76:ae:97:e0:64\n"
  "                50:59:73:22:99:55:cf:da:59:31:0a:e8:6d:a0:53:bc\n"
  "                39:63:2e:ac:92:4a:e9:8b:1e:d0:03:df:33:bb:4e:88\n"
  "Other Information:\n"
  "        MD5 fingerprint:\n"
  "                df3f57d00c8149bd826b177d6ea4f369\n"
  "        SHA-1 fingerprint:\n"
  "                e95e56e2acac305f72ea6f698c11624663a595bd\n"
  "        Public Key Id:\n"
  "                e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIICIjCCAY2gAwIBAgIBADALBgkqhkiG9w0BAQUwKDEmMCQGA1UEChMdR251VExT\n"
  "IGhvc3RuYW1lIGNoZWNrIHRlc3QgQ0EwHhcNMDcwMjE2MTMzNjI3WhcNMDcwMzMw\n"
  "MTMzNjI5WjAoMSYwJAYDVQQKEx1HbnVUTFMgaG9zdG5hbWUgY2hlY2sgdGVzdCBD\n"
  "QTCBnDALBgkqhkiG9w0BAQEDgYwAMIGIAoGAvuyYeh1vfmslnuggeEKgZAVmQ5lt\n"
  "SdUY7H25WGSygKMUYZ0KT74v8C780qtcNt9T7EPH/N6RvB4BprdssgcQLsthR3XK\n"
  "A84jbjjxNCcaGs33lvOz8A1nf8p3hD+cKfRikfYSW2JazLrtCC4yRCas/SPOUxu7\n"
  "8of+3HiTfFm/oXUCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzAR\n"
  "gg93d3cuZXhhbXBsZS5vcmcwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYE\n"
  "FOk8HPutkm7mBqRWLKLhwFMnyPKVMAsGCSqGSIb3DQEBBQOBgQChMLwBsw+Yf452\n"
  "fSOHNBV/pq6h+4d14+ga5V4DXb9EdUZP0qEoUIRJbTvgvE7eeYX64Qe3bgwUBEqC\n"
  "ufMiaryZFCA7SR/kl9nq63Oag6bMuFX7Uo5fhnyd+q8Ddq6X4GRQWXMimVXP2lkx\n"
  "CuhtoFO8OWMurJJK6Yse0APfM7tOiA==\n"
  "-----END CERTIFICATE-----\n";

/* Certificate with wildcard SAN but no CN. */
char pem4[] =
  "X.509 Certificate Information:\n"
  "        Version: 3\n"
  "        Serial Number (hex): 00\n"
  "        Issuer:\n"
  "        Validity:\n"
  "                Not Before: Fri Feb 16 13:40:10 UTC 2007\n"
  "                Not After: Fri Mar 30 13:40:12 UTC 2007\n"
  "        Subject:\n"
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
  "                Subject Alternative Name (not critical):\n"
  "                        DNSname: *.example.org\n"
  "                Key Purpose (not critical):\n"
  "                        TLS WWW Server.\n"
  "                Subject Key Identifier (not critical):\n"
  "                        e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "        Signature Algorithm: RSA-SHA\n"
  "        Signature:\n"
  "                b1:62:e5:e3:0b:a5:99:58:b0:1c:5c:f5:d1:3f:7c:bb\n"
  "                67:e1:43:c5:d7:a2:5c:db:f2:5a:f3:03:fc:76:e4:4d\n"
  "                c1:a0:89:36:24:82:a4:a1:ad:f5:83:e3:96:75:f4:c4\n"
  "                f3:eb:ff:3a:9b:da:d2:2c:58:d4:10:37:50:33:d1:39\n"
  "                53:71:9e:48:2d:b2:5b:27:ce:1e:d9:d5:36:59:ac:17\n"
  "                3a:83:cc:59:6b:8f:6a:24:b8:9f:f0:e6:14:03:23:5a\n"
  "                87:e7:33:10:32:11:58:a2:bb:f1:e5:5a:88:87:bb:80\n"
  "                1b:b6:bb:12:18:cb:15:d5:3a:fc:99:e4:42:5a:ba:45\n"
  "Other Information:\n"
  "        MD5 fingerprint:\n"
  "                a411da7b0fa064d214116d5f94e06c24\n"
  "        SHA-1 fingerprint:\n"
  "                3596e796c73ed096d762ab3d440a9ab55a386b3b\n"
  "        Public Key Id:\n"
  "                e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB0DCCATugAwIBAgIBADALBgkqhkiG9w0BAQUwADAeFw0wNzAyMTYxMzQwMTBa\n"
  "Fw0wNzAzMzAxMzQwMTJaMAAwgZwwCwYJKoZIhvcNAQEBA4GMADCBiAKBgL7smHod\n"
  "b35rJZ7oIHhCoGQFZkOZbUnVGOx9uVhksoCjFGGdCk++L/Au/NKrXDbfU+xDx/ze\n"
  "kbweAaa3bLIHEC7LYUd1ygPOI2448TQnGhrN95bzs/ANZ3/Kd4Q/nCn0YpH2Elti\n"
  "Wsy67QguMkQmrP0jzlMbu/KH/tx4k3xZv6F1AgMBAAGjYTBfMA8GA1UdEwEB/wQF\n"
  "MAMBAf8wGAYDVR0RBBEwD4INKi5leGFtcGxlLm9yZzATBgNVHSUEDDAKBggrBgEF\n"
  "BQcDATAdBgNVHQ4EFgQU6Twc+62SbuYGpFYsouHAUyfI8pUwCwYJKoZIhvcNAQEF\n"
  "A4GBALFi5eMLpZlYsBxc9dE/fLtn4UPF16Jc2/Ja8wP8duRNwaCJNiSCpKGt9YPj\n"
  "lnX0xPPr/zqb2tIsWNQQN1Az0TlTcZ5ILbJbJ84e2dU2WawXOoPMWWuPaiS4n/Dm\n"
  "FAMjWofnMxAyEViiu/HlWoiHu4AbtrsSGMsV1Tr8meRCWrpF\n"
  "-----END CERTIFICATE-----\n";

/* Certificate with ipaddress CN but no SAN. */
char pem5[] =
  "X.509 Certificate Information:"
  "        Version: 3\n"
  "        Serial Number (hex): 00\n"
  "        Issuer: CN=www.example.org\n"
  "        Validity:\n"
  "                Not Before: Fri Feb 16 13:44:29 UTC 2007\n"
  "                Not After: Fri Mar 30 13:44:30 UTC 2007\n"
  "        Subject: CN=www.example.org\n"
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
  "                Subject Alternative Name (not critical):\n"
  "                        IPAddress: 1.2.3.4\n"
  "                Key Purpose (not critical):\n"
  "                        TLS WWW Server.\n"
  "                Subject Key Identifier (not critical):\n"
  "                        e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "        Signature Algorithm: RSA-SHA\n"
  "        Signature:\n"
  "                66:b1:32:9f:6e:06:d7:da:28:bf:3a:d7:56:d5:b6:fe\n"
  "                78:40:f0:48:92:3a:19:8a:1c:37:ad:59:6f:bc:af:f2\n"
  "                f0:89:81:33:33:01:a8:e4:1a:c1:31:a7:3c:6d:4a:9f\n"
  "                a5:86:6d:22:6e:5b:8b:69:65:83:28:b5:b8:68:72:c5\n"
  "                2b:af:99:89:dd:48:ad:fc:f6:90:55:c3:a5:41:f3:d7\n"
  "                bc:a2:57:56:25:f1:d1:12:fb:08:70:58:d5:45:57:86\n"
  "                1b:aa:f2:d4:63:62:c6:fd:b3:04:64:60:9c:77:c3:4b\n"
  "                d1:e4:c7:77:00:17:79:d2:2b:1f:14:ad:e9:34:c8:da\n"
  "Other Information:\n"
  "        MD5 fingerprint:\n"
  "                cdffe1ac9bf42a4f04a15298f9d18bf6\n"
  "        SHA-1 fingerprint:\n"
  "                4fa47b29e928499142c88c598ea175b9453957f7\n"
  "        Public Key Id:\n"
  "                e93c1cfbad926ee606a4562ca2e1c05327c8f295\n"
  "\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB/jCCAWmgAwIBAgIBADALBgkqhkiG9w0BAQUwGjEYMBYGA1UEAxMPd3d3LmV4\n"
  "YW1wbGUub3JnMB4XDTA3MDIxNjEzNDQyOVoXDTA3MDMzMDEzNDQzMFowGjEYMBYG\n"
  "A1UEAxMPd3d3LmV4YW1wbGUub3JnMIGcMAsGCSqGSIb3DQEBAQOBjAAwgYgCgYC+\n"
  "7Jh6HW9+ayWe6CB4QqBkBWZDmW1J1RjsfblYZLKAoxRhnQpPvi/wLvzSq1w231Ps\n"
  "Q8f83pG8HgGmt2yyBxAuy2FHdcoDziNuOPE0JxoazfeW87PwDWd/yneEP5wp9GKR\n"
  "9hJbYlrMuu0ILjJEJqz9I85TG7vyh/7ceJN8Wb+hdQIDAQABo1swWTAPBgNVHRMB\n"
  "Af8EBTADAQH/MBIGA1UdEQQLMAmHBzEuMi4zLjQwEwYDVR0lBAwwCgYIKwYBBQUH\n"
  "AwEwHQYDVR0OBBYEFOk8HPutkm7mBqRWLKLhwFMnyPKVMAsGCSqGSIb3DQEBBQOB\n"
  "gQBmsTKfbgbX2ii/OtdW1bb+eEDwSJI6GYocN61Zb7yv8vCJgTMzAajkGsExpzxt\n"
  "Sp+lhm0ibluLaWWDKLW4aHLFK6+Zid1Irfz2kFXDpUHz17yiV1Yl8dES+whwWNVF\n"
  "V4YbqvLUY2LG/bMEZGCcd8NL0eTHdwAXedIrHxSt6TTI2g==\n"
  "-----END CERTIFICATE-----\n";

void
doit (void)
{
  gnutls_x509_crt_t cert;
  gnutls_datum_t data;
  int ret;

  ret = gnutls_global_init ();
  if (ret < 0)
    fail ("gnutls_global_init: %d\n", ret);

  ret = gnutls_x509_crt_init (&cert);
  if (ret < 0)
    fail ("gnutls_x509_crt_init: %d\n", ret);

  success ("Testing pem1...\n");
  data.data = pem1;
  data.size = strlen (pem1);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  success ("Testing pem2...\n");
  data.data = pem2;
  data.size = strlen (pem2);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "www.example.org");
  if (ret)
    success ("Hostname correctly matches (%d)\n", ret);
  else
    fail ("Hostname incorrectly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "*.example.org");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  success ("Testing pem3...\n");
  data.data = pem3;
  data.size = strlen (pem3);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "www.example.org");
  if (ret)
    success ("Hostname correctly matches (%d)\n", ret);
  else
    fail ("Hostname incorrectly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "*.example.org");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  success ("Testing pem4...\n");
  data.data = pem4;
  data.size = strlen (pem4);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "www.example.org");
  if (ret)
    success ("Hostname correctly matches (%d)\n", ret);
  else
    fail ("Hostname incorrectly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo.example.org");
  if (ret)
    success ("Hostname correctly matches (%d)\n", ret);
  else
    fail ("Hostname incorrectly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo.example.com");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  success ("Testing pem5...\n");
  data.data = pem5;
  data.size = strlen (pem5);

  ret = gnutls_x509_crt_import (cert, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("gnutls_x509_crt_import: %d\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "foo");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "1.2.3.4");
  if (ret)
    success ("Hostname correctly matches (%d)\n", ret);
  else
    fail ("Hostname incorrectly does not match (%d)\n", ret);

  ret = gnutls_x509_crt_check_hostname (cert, "www.example.org");
  if (ret)
    fail ("Hostname incorrectly matches (%d)\n", ret);
  else
    success ("Hostname correctly does not match (%d)\n", ret);

  gnutls_x509_crt_deinit (cert);

  gnutls_global_deinit ();
}
