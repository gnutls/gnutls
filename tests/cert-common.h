/*
 * Copyright (C) 2015-2017 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
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
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUTLS_TESTS_CERT_COMMON_H
#define GNUTLS_TESTS_CERT_COMMON_H

#include <gnutls/gnutls.h>

/* This file contains a lot of common parameters used by legacy and new
 * tests. The recommended to use for new tests are:
 *
 * CA: ca3_cert, ca3_key
 * TLS client: cli_ca3_cert, cli_ca3_key
 * TLS client (RSA PSS): cli_ca3_rsa_pss_cert, cli_ca3_rsa_pss_key
 * TLS client (GOST R 34.10-2001): cligost01_ca3_cert, cligost01_ca3_key
 * TLS client (GOST R 34.10-2012-256): cligost12_256_ca3_cert, cligost12_256_ca3_key
 * TLS client (GOST R 34.10-2012-512): cligost12_512_ca3_cert, cligost12_512_ca3_key
 * IPv4 server (SAN: IPAddr: 127.0.0.1): server_ca3_ipaddr_cert, server_ca3_key
 * IPv4 server (RSA-PSS, SAN: localhost IPAddr: 127.0.0.1): server_ca3_rsa_pss_cert, server_ca3_rsa_pss_key
 * IPv4 server (RSA-PSS key, SAN: localhost IPAddr: 127.0.0.1): server_ca3_rsa_pss2_cert, server_ca3_rsa_pss2_key
 * IPv4 server (Ed25519, SAN: localhost IPAddr: 127.0.0.1): server_ca3_eddsa_cert, server_ca3_eddsa_key
 * IPv4 server (Ed448, SAN: localhost IPAddr: 127.0.0.1): server_ca3_ed448_cert, server_ca3_ed448_key
 * IPv4 server (GOST R 34.10-2001, SAN: localhost): server_ca3_gost01_cert, server_ca3_gost01_key
 * IPv4 server (GOST R 34.10-2012-256, SAN: localhost): server_ca3_gost12-256_cert, server_ca3_gost12-256_key
 * IPv4 server (GOST R 34.10-2012-512, SAN: localhost): server_ca3_gost12-512_cert, server_ca3_gost12-512_key
 * IPv6 server: server_ca3_tlsfeat_cert, server_ca3_key
 * IPv6 server: server_ca3_localhost6_cert, server_ca3_key
 * IPv4 server: server_ca3_localhost_cert, server_ca3_key
 * IPv4 server: server_ca3_localhost_ecc_cert, server_ca3_ecc_key
 * IPv4 server: server_ca3_localhost_utf8_cert, server_ca3_key - UTF8 names
 * IPv4 server: server_ca3_localhost_inv_utf8_cert, server_ca3_key - invalid UTF8 names
 * IPv4 server: insecure key: server_ca3_localhost_insecure_key, server_ca3_localhost_insecure_cert
 * IPv4 server: RSA-decrypt key: server_ca3_localhost_rsa_decrypt_cert, server_ca3_key
 * IPv4 server: RSA-sign-only key: server_ca3_localhost_rsa_sign_cert, server_ca3_key
 */

static char ecc_key[] =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MHgCAQEEIQD9KwCA8zZfETJl440wMztH9c74E+VMws/96AVqyslBsaAKBggqhkjO\n"
	"PQMBB6FEA0IABDwVbx1IPmRZEyxtBBo4DTBc5D9Vy9kXFUZycZLB+MYzPQQuyMEP\n"
	"wFAEe5/JSLVA+m+TgllhXnJXy4MGvcyClME=\n"
	"-----END EC PRIVATE KEY-----\n";

static char ecc_cert[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC4DCCAoagAwIBAgIBBzAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G\n"
	"A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y\n"
	"aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0\n"
	"ZSBhdXRob3JpdHkwIhgPMjAxMjA5MDEwOTIyMzZaGA8yMDE5MTAwNTA5MjIzNlow\n"
	"gbgxCzAJBgNVBAYTAkdSMRIwEAYDVQQKEwlLb2tvIGluYy4xFzAVBgNVBAsTDnNs\n"
	"ZWVwaW5nIGRlcHQuMQ8wDQYDVQQIEwZBdHRpa2kxFTATBgNVBAMTDENpbmR5IExh\n"
	"dXBlcjEXMBUGCgmSJomT8ixkAQETB2NsYXVwZXIxDDAKBgNVBAwTA0RyLjEPMA0G\n"
	"A1UEQRMGamFja2FsMRwwGgYJKoZIhvcNAQkBFg1ub25lQG5vbmUub3JnMFkwEwYH\n"
	"KoZIzj0CAQYIKoZIzj0DAQcDQgAEPBVvHUg+ZFkTLG0EGjgNMFzkP1XL2RcVRnJx\n"
	"ksH4xjM9BC7IwQ/AUAR7n8lItUD6b5OCWWFeclfLgwa9zIKUwaOBtjCBszAMBgNV\n"
	"HRMBAf8EAjAAMD0GA1UdEQQ2MDSCDHd3dy5ub25lLm9yZ4ITd3d3Lm1vcmV0aGFu\n"
	"b25lLm9yZ4IJbG9jYWxob3N0hwTAqAEBMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8G\n"
	"A1UdDwEB/wQFAwMHgAAwHQYDVR0OBBYEFKz6R2fGG0F5Elf3rAXBUOKO0A5bMB8G\n"
	"A1UdIwQYMBaAFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqGSM49BAMCA0gAMEUC\n"
	"ICgq4CTInkRQ1DaFoI8wmu2KP8445NWRXKouag2WJSFzAiEAx4KxaoZJNVfBBSc4\n"
	"bA9XTz/2OnpgAZutUohNNb/tmRE=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ecc_cert = { (unsigned char *)ecc_cert,
					 sizeof(ecc_cert) - 1 };

const gnutls_datum_t server_ecc_key = { (unsigned char *)ecc_key,
					sizeof(ecc_key) - 1 };

/* A cert-key pair */
static char pem1_cert[] =
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
	"dc8Siq5JojruiMizAf0pA7in\n"
	"-----END CERTIFICATE-----\n";

static char pem1_key[] =
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

const gnutls_datum_t cert_dat = { (unsigned char *)pem1_cert,
				  sizeof(pem1_cert) - 1 };

const gnutls_datum_t key_dat = { (unsigned char *)pem1_key,
				 sizeof(pem1_key) - 1 };

/* A server cert/key pair with CA */
static unsigned char server_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDIzCCAgugAwIBAgIMUz8PCR2sdRK56V6OMA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTEwIhgPMjAxNDA0MDQxOTU5MDVaGA85OTk5MTIzMTIzNTk1OVow\n"
	"EzERMA8GA1UEAxMIc2VydmVyLTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
	"AoIBAQDZ3dCzh9gOTOiOb2dtrPu91fYYgC/ey0ACYjQxaru7FZwnuXPhQK9KHsIV\n"
	"YRIyo49wjKZddkHet2sbpFAAeETZh8UUWLRb/mupyaSJMycaYCNjLZCUJTztvXxJ\n"
	"CCNfbtgvKC+Vu1mu94KBPatslgvnsamH7AiL5wmwRRqdH/Z93XaEvuRG6Zk0Sh9q\n"
	"ZMdCboGfjtmGEJ1V+z5CR+IyH4sckzd8WJW6wBSEwgliGaXnc75xKtFWBZV2njNr\n"
	"8V1TOYOdLEbiF4wduVExL5TKq2ywNkRpUfK2I1BcWS5D9Te/QT7aSdE08rL6ztmZ\n"
	"IhILSrMOfoLnJ4lzXspz3XLlEuhnAgMBAAGjdzB1MAwGA1UdEwEB/wQCMAAwFAYD\n"
	"VR0RBA0wC4IJbG9jYWxob3N0MA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFJXR\n"
	"raRS5MVhEqaRE42A3S2BIj7UMB8GA1UdIwQYMBaAFP6S7AyMRO2RfkANgo8YsCl8\n"
	"JfJkMA0GCSqGSIb3DQEBCwUAA4IBAQCQ62+skMVZYrGbpab8RI9IG6xH8kEndvFj\n"
	"J7wBBZCOlcjOj+HQ7a2buF5zGKRwAOSznKcmvZ7l5DPdsd0t5/VT9LKSbQ6+CfGr\n"
	"Xs5qPaDJnRhZkOILCvXJ9qyO+79WNMsg9pWnxkTK7aWR5OYE+1Qw1jG681HMkWTm\n"
	"nt7et9bdiNNpvA+L55569XKbdtJLs3hn5gEQFgS7EaEj59aC4vzSTFcidowCoa43\n"
	"7JmfSfC9YaAIFH2vriyU0QNf2y7cG5Hpkge+U7uMzQrsT77Q3SDB9WkyPAFNSB4Q\n"
	"B/r+OtZXOnQhLlMV7h4XGlWruFEaOBVjFHSdMGUh+DtaLvd1bVXI\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDATCCAemgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCIYDzIwMTQwNDA0MTk1OTA1WhgPOTk5OTEyMzEyMzU5NTlaMA8xDTALBgNVBAMT\n"
	"BENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDvhyQfsUm3T0xK\n"
	"jiBXO3H6Y27b7lmCRYZQCmXCl2sUsGDL7V9biavTt3+sorWtH542/cTGDh5n8591\n"
	"7rVxAB/VASmN55O3fjZyFGrjusjhXBla0Yxe5rZ/7/Pjrq84T7gc/IXiX9Sums/c\n"
	"o9AeoykfhsjV2ubhh4h+8uPsHDTcAFTxq3mQaoldwnW2nmjDFzaKLtQdnyFf41o6\n"
	"nsJCK/J9PtpdCID5Zb+eQfu5Yhk1iUHe8a9TOstCHtgBq61YzufDHUQk3zsT+VZM\n"
	"20lDvSBnHdWLjxoea587JbkvtH8xRR8ThwABSb98qPnhJ8+A7mpO89QO1wxZM85A\n"
	"xEweQlMHAgMBAAGjZDBiMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcE\n"
	"ADAdBgNVHQ4EFgQU/pLsDIxE7ZF+QA2CjxiwKXwl8mQwHwYDVR0jBBgwFoAUGD0R\n"
	"Yr2H7kfjQUcBMxSTCDQnhu0wDQYJKoZIhvcNAQELBQADggEBANEXLUV+Z1PGTn7M\n"
	"3rPT/m/EamcrZJ3vFWrnfN91ws5llyRUKNhx6222HECh3xRSxH9YJONsbv2zY6sd\n"
	"ztY7lvckL4xOgWAjoCVTx3hqbZjDxpLRsvraw1PlqBHlRQVWLKlEQ55+tId2zgMX\n"
	"Z+wxM7FlU/6yWVPODIxrqYQd2KqaEp4aLIklw6Hi4HD6DnQJikjsJ6Noe0qyX1Tx\n"
	"uZ8mgP/G47Fe2d2H29kJ1iJ6hp1XOqyWrVIh/jONcnTvWS8aMqS3MU0EJH2Pb1Qa\n"
	"KGIvbd/3H9LykFTP/b7Imdv2fZxXIK8jC+jbF1w6rdBCVNA0p30X/jonoC3vynEK\n"
	"5cK0cgs=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
				     sizeof(server_cert_pem) - 1 };

static unsigned char server_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEpQIBAAKCAQEA2d3Qs4fYDkzojm9nbaz7vdX2GIAv3stAAmI0MWq7uxWcJ7lz\n"
	"4UCvSh7CFWESMqOPcIymXXZB3rdrG6RQAHhE2YfFFFi0W/5rqcmkiTMnGmAjYy2Q\n"
	"lCU87b18SQgjX27YLygvlbtZrveCgT2rbJYL57Gph+wIi+cJsEUanR/2fd12hL7k\n"
	"RumZNEofamTHQm6Bn47ZhhCdVfs+QkfiMh+LHJM3fFiVusAUhMIJYhml53O+cSrR\n"
	"VgWVdp4za/FdUzmDnSxG4heMHblRMS+UyqtssDZEaVHytiNQXFkuQ/U3v0E+2knR\n"
	"NPKy+s7ZmSISC0qzDn6C5yeJc17Kc91y5RLoZwIDAQABAoIBAQCRXAu5HPOsZufq\n"
	"0K2DYZz9BdqSckR+M8HbVUZZiksDAeIUJwoHyi6qF2eK+B86JiK4Bz+gsBw2ys3t\n"
	"vW2bQqM9N/boIl8D2fZfbCgZWkXGtUonC+mgzk+el4Rq/cEMFVqr6/YDwuKNeJpc\n"
	"PJc5dcsvpTvlcjgpj9bJAvJEz2SYiIUpvtG4WNMGGapVZZPDvWn4/isY+75T5oDf\n"
	"1X5jG0lN9uoUjcuGuThN7gxjwlRkcvEOPHjXc6rxfrWIDdiz/91V46PwpqVDpRrg\n"
	"ig6U7+ckS0Oy2v32x0DaDhwAfDJ2RNc9az6Z+11lmY3LPkjG/p8Klcmgvt4/lwkD\n"
	"OYRC5QGRAoGBAPFdud6nmVt9h1DL0o4R6snm6P3K81Ds765VWVmpzJkK3+bwe4PQ\n"
	"GQQ0I0zN4hXkDMwHETS+EVWllqkK/d4dsE3volYtyTti8zthIATlgSEJ81x/ChAQ\n"
	"vvXxgx+zPUnb1mUwy+X+6urTHe4bxN2ypg6ROIUmT+Hx1ITG40LRRiPTAoGBAOcT\n"
	"WR8DTrj42xbxAUpz9vxJ15ZMwuIpk3ShE6+CWqvaXHF22Ju4WFwRNlW2zVLH6UMt\n"
	"nNfOzyDoryoiu0+0mg0wSmgdJbtCSHoI2GeiAnjGn5i8flQlPQ8bdwwmU6g6I/EU\n"
	"QRbGK/2XLmlrGN52gVy9UX0NsAA5fEOsAJiFj1CdAoGBAN9i3nbq6O2bNVSa/8mL\n"
	"XaD1vGe/oQgh8gaIaYSpuXlfbjCAG+C4BZ81XgJkfj3CbfGbDNqimsqI0fKsAJ/F\n"
	"HHpVMgrOn3L+Np2bW5YMj0Fzwy+1SCvsQ8C+gJwjOLMV6syGp/+6udMSB55rRv3k\n"
	"rPnIf+YDumUke4tTw9wAcgkPAoGASHMkiji7QfuklbjSsslRMyDj21gN8mMevH6U\n"
	"cX7pduBsA5dDqu9NpPAwnQdHsSDE3i868d8BykuqQAfLut3hPylY6vPYlLHfj4Oe\n"
	"dj+xjrSX7YeMBE34qvfth32s1R4FjtzO25keyc/Q2XSew4FcZftlxVO5Txi3AXC4\n"
	"bxnRKXECgYEAva+og7/rK+ZjboJVNxhFrwHp9bXhz4tzrUaWNvJD2vKJ5ZcThHcX\n"
	"zCig8W7eXHLPLDhi9aWZ3kUZ1RLhrFc/6dujtVtU9z2w1tmn1I+4Zi6D6L4DzKdg\n"
	"nMRLFoXufs/qoaJTqa8sQvKa+ceJAF04+gGtw617cuaZdZ3SYRLR2dk=\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { server_key_pem,
				    sizeof(server_key_pem) - 1 };

static unsigned char ca_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC4DCCAcigAwIBAgIBADANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCIYDzIwMTQwNDA0MTk1OTA1WhgPOTk5OTEyMzEyMzU5NTlaMA8xDTALBgNVBAMT\n"
	"BENBLTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD46JAPKrTsNTHl\n"
	"zD06eIYBF/8Z+TR0wukp9Cdh8Sw77dODLjy/QrVKiDgDZZdyUc8Agsdr86i95O0p\n"
	"w19Np3a0wja0VC9uwppZrpuHsrWukwxIBXoViyBc20Y6Ce8j0scCbR10SP565qXC\n"
	"i8vr86S4xmQMRZMtwohP/GWQzt45jqkHPYHjdKzwo2b2XI7joDq0dvbr3MSONkGs\n"
	"z7A/1Bl3iH5keDTWjqpJRWqXE79IhGOhELy+gG4VLJDGHWCr2mq24b9Kirp+TTxl\n"
	"lUwJRbchqUqerlFdt1NgDoGaJyd73Sh0qcZzmEiOI2hGvBtG86tdQ6veC9dl05et\n"
	"pM+6RMABAgMBAAGjQzBBMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcE\n"
	"ADAdBgNVHQ4EFgQUGD0RYr2H7kfjQUcBMxSTCDQnhu0wDQYJKoZIhvcNAQELBQAD\n"
	"ggEBALnHMubZ6WJ/XOFyDuo0imwg2onrPas3MuKT4+y0aHY943BgAOEc3jKitRjc\n"
	"qhb0IUD+NS7itRwNtCgI3v5Ym5nnQoVk+aOD/D724TjJ9XaPQJzOnuGaZX99VN2F\n"
	"sgwAtDXedlDQ+I6KLzLd6VW+UyWTG4qiRjOGDnG2kM1wAEOM27TzHV/YWleGjhtA\n"
	"bRHxkioOni5goNlTzazxF4v9VD2uinWrIFyZmF6vQuMm6rKFgq6higAU8uesFo7+\n"
	"3qpeRjNrPC4fNJUBvv+PC0WnP0PLnD/rY/ZcTYjLb/vJp1fiMJ5fU7jJklBhX2TE\n"
	"tstcP7FUV5HA/s9BxgAh0Z2wyyY=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t ca_cert = { ca_cert_pem, sizeof(ca_cert_pem) - 1 };

/* A server cert/key pair with CA */
static unsigned char server2_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEITCCAomgAwIBAgIMVmajOA3Gh2967f62MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTAwIBcNMTUxMjA4MDkzMDMyWhgPOTk5OTEyMzEyMzU5NTlaMBMx\n"
	"ETAPBgNVBAMTCHNlcnZlci0xMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC\n"
	"AYEApk9rgAWlVEGy9t5Nn9RsvupM3JATJe2ONeGgMjAT++rgjsENwjqNNmEFLZjx\n"
	"8VfRjnHoVEIWvMJqeaAeBwP7GiKiDiLkHEK4ZwjJZ7aqy0KIRktDLWvJrZdoJryt\n"
	"yMikKVhPHQ9qwh6JRA3qx1FiEcW7ahU2U4/r/fydiUC0wec2UhBd4AJyXzYvFO7o\n"
	"SKPkQfzlGBNT55z/Wp9zfOO1w2x/++I+1AoKFFJ1dRI3hyrL/DfOUMoeVkJ6knyZ\n"
	"N3TQo+ZjbSkLZlpnAoxGSN8uNcX9q91AuM2zQOg1xPD0ZJvLP3j9BOtYQ7rvkX0U\n"
	"3efJXXO+Gq4oCKiPU4ZY6u43BquipzEaeZiSWPS6Xj2Ipn+KO0v77NBxhNP3lpfQ\n"
	"YDwZbw1AjnViE+WUS8r2DyM47daTGafqUCXM08kSTCrSWSte96P0jHFnyjtPGrwC\n"
	"0KQw1ug4nJxFi9FHZyU+IhczvFthocPuKOAq44//zsKKuPKsJIhA4QXfdVVvm4m+\n"
	"RoTZAgMBAAGjdzB1MAwGA1UdEwEB/wQCMAAwFAYDVR0RBA0wC4IJbG9jYWxob3N0\n"
	"MA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFCWcdf+x5Ge4ec8WGfoWYcNlaEQF\n"
	"MB8GA1UdIwQYMBaAFEt2/L3oAu29JvNzjKv/Xavvp0ufMA0GCSqGSIb3DQEBCwUA\n"
	"A4IBgQC/vXr2ecuGhAHJaBxWqay3IxyBgoQUxOMkXcXLMILxXGtIKheVZOJnilvU\n"
	"K9/fBy7N3ygUemvblNBfDJG+fA5jTmUQC8UEgeStp0iena3iAJxsGikCIAJKGzBk\n"
	"LHiPls2z9uLQXO+ZRlK1E+XfB0/3Mu4dPAPM50TLL8jYLfYzZZchgfhCX51dmic/\n"
	"EW4LL+K6LzIHoLV32YEFL9ea4y46Ub0dAX+WEwZYKu5Fu/hk+n34lBYBW1uWzPhK\n"
	"JjXVbQQUE4nirzjWr6ch5rDXz1JhhNuuex29EqA3reWtQWnHySU43/uoFxN1jD0r\n"
	"bMjyE5li2WU796vKyB0hYBKcOauWJPDdrKFvVs45GH6r84hjAacMq4RKm4P9esuQ\n"
	"0GXVaUCLGHP1ss+glFB/k5DJO1nb6hZPOCKsdaO/VbXl5kmcxgvzAoedDTiUJiC5\n"
	"URF3vuETfLwew2gE38NrTEPT54S5rYLsp/F6+5nIIhqG0BtaOwIx1VbBlrMnbsx+\n"
	"pFLp6h0=\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIID8zCCAlugAwIBAgIBADANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCAXDTE1MTIwODA5MzAzMVoYDzk5OTkxMjMxMjM1OTU5WjAPMQ0wCwYDVQQDEwRD\n"
	"QS0wMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Q82wj5Dk/me634j\n"
	"DnFBbAJ5FGNNeXnBgprRo2tQv8oJYMN/osSVd/03XiWBQnXk7v2aSkfXMqgEAzfv\n"
	"0fzWZYyhKSwTvDG48LfnIuF7UrnvnC3xdAOjcQ+E3zUdYYonSn3gRBwIjOK4wFbG\n"
	"Q4oelFnPOjWGeasLh++yBNfCa506jgFd9Y1rU5o0r/EIYSQi2aj71E+x3EdkS0Tx\n"
	"iKpIGHseuP2ARmmZPLy4YglFBvPiDRi0jdgdWd6UbNk7XJ+xnKa9gVtk3TX7vy5E\n"
	"7R1686F66bIe9T1N2Wyf3huJkgwUB2UPpG9rNiOvRLGFxkONeATwiJyzJG9DmtGw\n"
	"GbKsyMDU9Rq9Z694tBCnlWlPrQKsZEsnivPIn/2VaANArT1QtsS+EdaXzuIWmIM0\n"
	"cdQXf1U1VhzACFpHnFZ6XsOe40qwzj+6RQprHcWnIGP992qiQ6zPF8QPkycTrbhi\n"
	"TG7hX59sTTBJva5DNjZnx4H/hOiQub04CMD501JiLQ1ALXGfAgMBAAGjWDBWMA8G\n"
	"A1UdEwEB/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYDVR0PAQH/BAUD\n"
	"AwcGADAdBgNVHQ4EFgQUS3b8vegC7b0m83OMq/9dq++nS58wDQYJKoZIhvcNAQEL\n"
	"BQADggGBALJv0DUD3Ujb0a9zcgKQIjljFMoA0v5A6+ZoLeHmRTU5udNV9G2AsdSx\n"
	"PEH/D7v/GyoR0jApgA0TiAqRuvlc3NsdHBx9tFvgrAFyC7bbJRrf9lP9QlTqkmb7\n"
	"a85OYmdiDhtQSyKdtSZpAfP7jVGJqQz5UWbV3CjYfubU+HLIZXEb6m8YCKBFb7l9\n"
	"GNrcKK+gFyrQr6KmojzMkJd5PxVBUsYleaf/0QxC7nRbTH/qomJvooI2nLBLA7U3\n"
	"VGLL3Og6rpjIWu2dwkvepcnesdrnPq4hJQ+uSfDkthP/qCs/3Nj9bvL73DIAYUc2\n"
	"6FUmOK40BRhBhcAIYj+9JDtHncykj0RBjH6eq+goDTSd4gTXmfbzb8p1jjLal8xZ\n"
	"PcNzShMpUqkmWe3Otzd98zkOzqiHeO03tBgfA5u+4gInSdQp5eUpE3Uivp9IcNaC\n"
	"TMSfIA6roY+p7j1ISlmzXUZuEz9dkJumV0TMmOv6nd+ZufwaDOIuDPad5bG2JFji\n"
	"KvV1dLfOfg==\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server2_cert = { server2_cert_pem,
				      sizeof(server2_cert_pem) - 1 };

static unsigned char server2_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server2_key = { server2_key_pem,
				     sizeof(server2_key_pem) - 1 };

static unsigned char ca2_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIID8zCCAlugAwIBAgIBADANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCAXDTE1MTIwODA5MzAzMVoYDzk5OTkxMjMxMjM1OTU5WjAPMQ0wCwYDVQQDEwRD\n"
	"QS0wMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Q82wj5Dk/me634j\n"
	"DnFBbAJ5FGNNeXnBgprRo2tQv8oJYMN/osSVd/03XiWBQnXk7v2aSkfXMqgEAzfv\n"
	"0fzWZYyhKSwTvDG48LfnIuF7UrnvnC3xdAOjcQ+E3zUdYYonSn3gRBwIjOK4wFbG\n"
	"Q4oelFnPOjWGeasLh++yBNfCa506jgFd9Y1rU5o0r/EIYSQi2aj71E+x3EdkS0Tx\n"
	"iKpIGHseuP2ARmmZPLy4YglFBvPiDRi0jdgdWd6UbNk7XJ+xnKa9gVtk3TX7vy5E\n"
	"7R1686F66bIe9T1N2Wyf3huJkgwUB2UPpG9rNiOvRLGFxkONeATwiJyzJG9DmtGw\n"
	"GbKsyMDU9Rq9Z694tBCnlWlPrQKsZEsnivPIn/2VaANArT1QtsS+EdaXzuIWmIM0\n"
	"cdQXf1U1VhzACFpHnFZ6XsOe40qwzj+6RQprHcWnIGP992qiQ6zPF8QPkycTrbhi\n"
	"TG7hX59sTTBJva5DNjZnx4H/hOiQub04CMD501JiLQ1ALXGfAgMBAAGjWDBWMA8G\n"
	"A1UdEwEB/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYDVR0PAQH/BAUD\n"
	"AwcGADAdBgNVHQ4EFgQUS3b8vegC7b0m83OMq/9dq++nS58wDQYJKoZIhvcNAQEL\n"
	"BQADggGBALJv0DUD3Ujb0a9zcgKQIjljFMoA0v5A6+ZoLeHmRTU5udNV9G2AsdSx\n"
	"PEH/D7v/GyoR0jApgA0TiAqRuvlc3NsdHBx9tFvgrAFyC7bbJRrf9lP9QlTqkmb7\n"
	"a85OYmdiDhtQSyKdtSZpAfP7jVGJqQz5UWbV3CjYfubU+HLIZXEb6m8YCKBFb7l9\n"
	"GNrcKK+gFyrQr6KmojzMkJd5PxVBUsYleaf/0QxC7nRbTH/qomJvooI2nLBLA7U3\n"
	"VGLL3Og6rpjIWu2dwkvepcnesdrnPq4hJQ+uSfDkthP/qCs/3Nj9bvL73DIAYUc2\n"
	"6FUmOK40BRhBhcAIYj+9JDtHncykj0RBjH6eq+goDTSd4gTXmfbzb8p1jjLal8xZ\n"
	"PcNzShMpUqkmWe3Otzd98zkOzqiHeO03tBgfA5u+4gInSdQp5eUpE3Uivp9IcNaC\n"
	"TMSfIA6roY+p7j1ISlmzXUZuEz9dkJumV0TMmOv6nd+ZufwaDOIuDPad5bG2JFji\n"
	"KvV1dLfOfg==\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t ca2_cert = { ca2_cert_pem, sizeof(ca2_cert_pem) - 1 };

static unsigned char cli_cert_pem[] =
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
	"dc8Siq5JojruiMizAf0pA7in\n"
	"-----END CERTIFICATE-----\n";
const gnutls_datum_t cli_cert = { cli_cert_pem, sizeof(cli_cert_pem) - 1 };

static unsigned char cli_key_pem[] =
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
const gnutls_datum_t cli_key = { cli_key_pem, sizeof(cli_key_pem) - 1 };

static char dsa_key_pem[] =
	"-----BEGIN DSA PRIVATE KEY-----\n"
	"MIIBugIBAAKBgQC5hPVagb4aDcWKc48Mmy+btg5Lw3Qaf2StnfMoxaBHvJtXVvGX\n"
	"1X43A+nyTPTji38wo10vu6GiN8LqNY8fsV+mol8B8SM2K+RPLy3dndU6pjmvelF8\n"
	"0iWOl3TPHsV7S3ZDgQcfBhS4blgS4ZDiN2/SG+xoxVji5jDgal4sY3jsBwIVAJ9W\n"
	"jEhkL/6NqnptltsEXRbvCKVxAoGAYgZ+5Fx2CLdGGl3Xl9QqIfsfMcnS9Po52CfR\n"
	"m/wnXacKpxr8U8EvQ8I3yIV/PUyrXYEy+x1eHlQRFiDGgFrZjJtD8N1roPTD8oqc\n"
	"OdIcew/v+iiTj9KhIuvc4IqLrSgOz+8Jhek2vYt6UNV79yUNbGARxO9wkM/WG+u7\n"
	"jsY+OpcCgYAPiodX8tHC3KzfS4sPi7op9+ED5FX6spgH1v0SsYC89bq0UNR/oA5D\n"
	"55/JeBFf5eQMLGtqpDXcvVTlYDaaMdGKWW5rHLq9LrrrfIfv2sjdoeukg+aLrfr6\n"
	"jlvXN8gyPpbCPvRD2n2RAg+3vPjvj/dBAF6W3w8IltzqsukGgq/SLwIUS5/r/2ya\n"
	"AoNBXjeBjgCGMei2m8E=\n"
	"-----END DSA PRIVATE KEY-----\n";

const gnutls_datum_t dsa_key = { (unsigned char *)dsa_key_pem,
				 sizeof(dsa_key_pem) - 1 };

static char ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIID+jCCAmKgAwIBAgIIVzGgXgSsTYwwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA1MTAwODQ4MzBaGA85OTk5MTIzMTIzNTk1OVowDzENMAsG\n"
	"A1UEAxMEQ0EtMzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALbdxniG\n"
	"+2wP/ONeZfvR7AJakVo5deFKIHVTiiBWwhg+HSjd4nfDa+vyTt/wIdldP1PriD1R\n"
	"igc8z68+RxPpGfAc197pKlKpO08I0L1RDKnjBWr4fGdCzE6uZ/ZsKVifoIZpdC8M\n"
	"2IYpAIMajEtnH53XZ1hTEviXTsneuiCTtap73OeSkL71SrIMkgBmAX17gfX3SxFj\n"
	"QUzOs6QMMOa3+8GW7RI+E/SyS1QkOO860dj9XYgOnTL20ibGcWF2XmTiQASI+KmH\n"
	"vYJCNJF/8pvmyJRyBHGZO830aBY0+DcS2bLKcyMiWfOJw7WnpaO7zSEC5WFgo4jd\n"
	"qroUBQdjQNCSSdrt1yYrAl1Sj2PMxYFX4H545Pr2sMpwC9AnPk9+uucT1Inj9615\n"
	"qbuXgFwhkgpK5pnPjzKaHp7ESlJj4/dIPTmhlt5BV+CLh7tSLzVLrddGU+os8Jin\n"
	"T42radJ5V51Hn0C1CHIaFAuBCd5XRHXtrKb7WcnwCOxlcvux9h5/847F4wIDAQAB\n"
	"o1gwVjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMJMA8GA1Ud\n"
	"DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqG\n"
	"SIb3DQEBCwUAA4IBgQBhBi8dXQMtXH2oqcuHuEj9JkxraAsaJvc1WAoxbiqVcJKc\n"
	"VSC0gvoCY3q+NQvuePzw5dzd5JBfkoIsP5U6ATWAUPPqCP+/jRnFqDQlH626mhDG\n"
	"VS8W7Ee8z1KWqnKWGv5nkrZ6r3y9bVaNUmY7rytzuct1bI9YkX1kM66vgnU2xeMI\n"
	"jDe36/wTtBRVFPSPpE3KL9hxCg3KgPSeSmmIhmQxJ1M6xe00314/GX3lTDt55UdM\n"
	"gmldl2LHV+0i1NPCgnuOEFVOiz2nHAnw2LNmvHEDDpPauz2Meeh9aaDeefIh2u/w\n"
	"g39WRPhU1mYvmxvYZqA/jwSctiEhuKEBBZSOHxeTjplH1THlIziVnYyVW4sPMiGU\n"
	"ajXhTi47H219hx87+bldruOtirbDIslL9RGWqWAkMeGP+hUl1R2zvDukaqIKqIN8\n"
	"1/A/EeMoI6/IHb1BpgY2rGs/I/QTb3VTKqQUYv09Hi+itPCdKqamSm8dZMKKaPA0\n"
	"fD9yskUMFPBhfj8BvXg=\n"
	"-----END CERTIFICATE-----\n";

static char ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t ca3_key = { (unsigned char *)ca3_key_pem,
				 sizeof(ca3_key_pem) - 1 };

const gnutls_datum_t ca3_cert = { (unsigned char *)ca3_cert_pem,
				  sizeof(ca3_cert_pem) - 1 };

static char subca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
	"EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
	"NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
	"uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
	"kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
	"AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
	"JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
	"ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
	"ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
	"jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
	"A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
	"PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
	"QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
	"R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
	"cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
	"+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
	"EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
	"haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
	"frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
	"-----END CERTIFICATE-----\n";

static char subca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t subca3_key = { (unsigned char *)subca3_key_pem,
				    sizeof(subca3_key_pem) - 1 };

const gnutls_datum_t subca3_cert = { (unsigned char *)subca3_cert_pem,
				     sizeof(subca3_cert_pem) - 1 };

static char cli_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIERjCCAq6gAwIBAgIMV6MdMjZaLvmhsFpSMA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1NjM5WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MBYxFDASBgNVBAMTC1Rlc3QgY2xpZW50MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\n"
	"MIIBigKCAYEA4QAezvLHuNtTlTQSn1vNaYBrZ5+CzS8/tB2L5G+wWy3Yqqqh1kB+\n"
	"gcWN9Ftqv21B1WgRWtjrn4rTJgxl+ogLiLgLIZ6iG/Ye1POFKxxVYYxPXI7spAYa\n"
	"CW6/+QjS/18M6NCAHsvhJEMkOY6clIqEqCpLTyaWzJULBBwtpA84pkcLTiNpmfIJ\n"
	"Wos9OsYH0hSK2xE/5qu+DkkaKrfS2Cyp61wdhURrX1fdlkBUBt9XH8S5A2bWuQEY\n"
	"82GgXxl8HpehkB2RLgpkZQzxopzhoqG2P8IZFQmtOySzRPWtdpy0RJbvmLfZqaEw\n"
	"sq3g1jZFXhqUjc5y3vbHta2Xg5/zx0X/FB69j2KZsgUmklYVFG9te7UtSVDgz3U6\n"
	"9ed16AULxNqAF2LGhuIEI5+4PikXb+QxaOx/hw1BtEqMzLMbNphILSPBRI+NpTZ2\n"
	"PCSedGsQzxsgns/iaLB7q1AIrKLUQlVpy+JNfauYqzvlMNXwMaoNQZDf9oOoFkdT\n"
	"P5P8t/gGk2rlAgMBAAGjgZUwgZIwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr\n"
	"BgEFBQcDAjAcBgNVHREEFTATgRFoZWxsb0BleGFtcGxlLm9yZzAPBgNVHQ8BAf8E\n"
	"BQMDB4AAMB0GA1UdDgQWBBRdXorh31ji3Vx07Tm7u9jZMbKBajAfBgNVHSMEGDAW\n"
	"gBQtMwQbJ3+UBHzH4zVP6SWklOG3oTANBgkqhkiG9w0BAQsFAAOCAYEAPjXZC89d\n"
	"2lkc33p5qBTneqXAAZeseBZlSF9Rd798NofXTw0oi235UWCdmPOS4l0z8PBh0ICA\n"
	"MY7iUrv5MJeEcvGOq1NFZObsEP+gcpDi3s1otSif9n3ZSR9gDqG1kAlvwOxDW1As\n"
	"KuGgwE2vRZN3T20USkcSXvtJ3QD+tIroD9z/Auh2H6LsqOMwSwBo9Alzj7DWLk8G\n"
	"mdpQtQU+l/+3pa5MY4MBQM3T3PpK4TdjMVKzKc8lMUeFH/VJSbyQ2kgL7OqavMsH\n"
	"jGrm0JCWi2M188EobKVqt2nhQQA7SIogYe4cqx8Q2/7v6RDXZ11QifFKupQ2vXLb\n"
	"DZxa4j7YQz4F2m7+PbYbSAs1y4/oiJ32O3BjQC7Oa3OaGFpkipUtrozaa1TM4tab\n"
	"kZSyKmSvKG2RxDphl71OZ28tgWjjzJbyG3dbnI3HF1L7YVwHUGFUPhUGuiS7H/b4\n"
	"6Zd8Y0P6Cxn/4rUEZZPDpCVt92cjQsWXL45JXpmqwDlaRdSXXoIB2l2D\n"
	"-----END CERTIFICATE-----\n";

static char cli_ca3_cert_chain_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIERjCCAq6gAwIBAgIMV6MdMjZaLvmhsFpSMA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1NjM5WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MBYxFDASBgNVBAMTC1Rlc3QgY2xpZW50MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\n"
	"MIIBigKCAYEA4QAezvLHuNtTlTQSn1vNaYBrZ5+CzS8/tB2L5G+wWy3Yqqqh1kB+\n"
	"gcWN9Ftqv21B1WgRWtjrn4rTJgxl+ogLiLgLIZ6iG/Ye1POFKxxVYYxPXI7spAYa\n"
	"CW6/+QjS/18M6NCAHsvhJEMkOY6clIqEqCpLTyaWzJULBBwtpA84pkcLTiNpmfIJ\n"
	"Wos9OsYH0hSK2xE/5qu+DkkaKrfS2Cyp61wdhURrX1fdlkBUBt9XH8S5A2bWuQEY\n"
	"82GgXxl8HpehkB2RLgpkZQzxopzhoqG2P8IZFQmtOySzRPWtdpy0RJbvmLfZqaEw\n"
	"sq3g1jZFXhqUjc5y3vbHta2Xg5/zx0X/FB69j2KZsgUmklYVFG9te7UtSVDgz3U6\n"
	"9ed16AULxNqAF2LGhuIEI5+4PikXb+QxaOx/hw1BtEqMzLMbNphILSPBRI+NpTZ2\n"
	"PCSedGsQzxsgns/iaLB7q1AIrKLUQlVpy+JNfauYqzvlMNXwMaoNQZDf9oOoFkdT\n"
	"P5P8t/gGk2rlAgMBAAGjgZUwgZIwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr\n"
	"BgEFBQcDAjAcBgNVHREEFTATgRFoZWxsb0BleGFtcGxlLm9yZzAPBgNVHQ8BAf8E\n"
	"BQMDB4AAMB0GA1UdDgQWBBRdXorh31ji3Vx07Tm7u9jZMbKBajAfBgNVHSMEGDAW\n"
	"gBQtMwQbJ3+UBHzH4zVP6SWklOG3oTANBgkqhkiG9w0BAQsFAAOCAYEAPjXZC89d\n"
	"2lkc33p5qBTneqXAAZeseBZlSF9Rd798NofXTw0oi235UWCdmPOS4l0z8PBh0ICA\n"
	"MY7iUrv5MJeEcvGOq1NFZObsEP+gcpDi3s1otSif9n3ZSR9gDqG1kAlvwOxDW1As\n"
	"KuGgwE2vRZN3T20USkcSXvtJ3QD+tIroD9z/Auh2H6LsqOMwSwBo9Alzj7DWLk8G\n"
	"mdpQtQU+l/+3pa5MY4MBQM3T3PpK4TdjMVKzKc8lMUeFH/VJSbyQ2kgL7OqavMsH\n"
	"jGrm0JCWi2M188EobKVqt2nhQQA7SIogYe4cqx8Q2/7v6RDXZ11QifFKupQ2vXLb\n"
	"DZxa4j7YQz4F2m7+PbYbSAs1y4/oiJ32O3BjQC7Oa3OaGFpkipUtrozaa1TM4tab\n"
	"kZSyKmSvKG2RxDphl71OZ28tgWjjzJbyG3dbnI3HF1L7YVwHUGFUPhUGuiS7H/b4\n"
	"6Zd8Y0P6Cxn/4rUEZZPDpCVt92cjQsWXL45JXpmqwDlaRdSXXoIB2l2D\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
	"EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
	"NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
	"uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
	"kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
	"AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
	"JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
	"ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
	"ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
	"jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
	"A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
	"PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
	"QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
	"R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
	"cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
	"+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
	"EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
	"haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
	"frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
	"-----END CERTIFICATE-----\n";

static char cli_ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t cli_ca3_key = { (unsigned char *)cli_ca3_key_pem,
				     sizeof(cli_ca3_key_pem) - 1 };

const gnutls_datum_t cli_ca3_cert = { (unsigned char *)cli_ca3_cert_pem,
				      sizeof(cli_ca3_cert_pem) - 1 };

const gnutls_datum_t cli_ca3_cert_chain = {
	(unsigned char *)cli_ca3_cert_chain_pem,
	sizeof(cli_ca3_cert_chain_pem) - 1
};

static char clidsa_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEMzCCApugAwIBAgIIV+OL0jeIUYkwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA5MjIwNzQ0MjBaGA85OTk5MTIzMTIzNTk1OVowFTETMBEG\n"
	"A1UEAxMKRFNBIGNsaWVudDCCAbcwggErBgcqhkjOOAQBMIIBHgKBgQD6BQw6J3GB\n"
	"Lv8xjTjq6flgCLUYf9wNQO1osjl8F3mP3P0ggZd101pwDG34Kdffby+PTB5rpe8Z\n"
	"SUx83ozzCiCcxf+kM4B0B0JP7mlqLrdTyPbWTap8sCMtabKnuR7UWdhsB8WU2Ct9\n"
	"/IcCEG2dYcmzzWXE6/Pdo45iCd7lv+fl/wIVAM8gQzNh7394wHpNStxbGq9Xe+7z\n"
	"AoGAJuUzfmL64dwFgQDmow8BjA5jI4mPiXc9+HDlUG0xXT65tUqHyg5fTSVm8p+q\n"
	"WaklZeWTvuDc7KYofGZolG3LxhBKvIXHiUrD5hJ/cE/qcx89oczD7mChHG8k4a+Y\n"
	"sr9/gXMFp8/TUsiTXrPLvEedBiAL9isDGC+ibRswfFYqGKYDgYUAAoGBAOFzLEe4\n"
	"9nHYysKSgx6o7LadjsWAcLLHvI4EcmRZf7cHW/S/FCHgpnMn7GvnD4xiaysDFA8A\n"
	"XEh9QJutRiLcpp14bVkPd0E+1z3v3LDhwVaJ1DofWEMnAsGoRVkAuEBkND6aNoKI\n"
	"AuUMvFlnpU8SD5SZrUQkP22jyMj+mxsJntK9o3YwdDAMBgNVHRMBAf8EAjAAMBMG\n"
	"A1UdJQQMMAoGCCsGAQUFBwMCMA8GA1UdDwEB/wQFAwMHgAAwHQYDVR0OBBYEFCnQ\n"
	"ScP7Ao3G+SjKY0a5DEmNF5X+MB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv\n"
	"8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQArAfKJgKd6Sz7BW0m46T4DxXWsrlYVc76M\n"
	"metxnSBDZdWzRbP6dGXGkKH1J2Oftv3kVrRL8amDz7DLRE6pBAUDx+5Es/dheTNA\n"
	"juIVZuKzSYoRPtuiO1gHvRPvyV/2HUpnLl+w2qW/Df4ZWlHz6ujuYFzhdWueon+t\n"
	"7/JtabcuBxK6gFyNs+A0fHjszpWtZxUXuik1t4y9IcEV6Ig+vWk+GNwVAs5lQenv\n"
	"7IhIg1EWxBNiRF3yKINAiyFkM4FcFEPqlbijX9xDorCK2Xn4HLIN2oUQJFYDqVOV\n"
	"KGg0rMmeJ8rRZI0ELK89SdPyALe4HQzKnQtzxy45oq+Vv7A8B0lorTMPIq3WKxo4\n"
	"mXJdEF2aYxeUsMYBDZOOslBc8UMaUAF8ncrk6eNqJoDZCxElfgDXx4CfM8Lh0V2c\n"
	"MDBXeiNUf1HWcCkvnMPGLXZXez/5abnhNIFqDsmRxuhUqlTbarq3CxjAWMjQRb9c\n"
	"SWUGHPlOkmEGRv5JB6djjpRFRwtHLNc=\n"
	"-----END CERTIFICATE-----\n";

static char clidsa_ca3_key_pem[] =
	"-----BEGIN DSA PRIVATE KEY-----\n"
	"MIIBuwIBAAKBgQD6BQw6J3GBLv8xjTjq6flgCLUYf9wNQO1osjl8F3mP3P0ggZd1\n"
	"01pwDG34Kdffby+PTB5rpe8ZSUx83ozzCiCcxf+kM4B0B0JP7mlqLrdTyPbWTap8\n"
	"sCMtabKnuR7UWdhsB8WU2Ct9/IcCEG2dYcmzzWXE6/Pdo45iCd7lv+fl/wIVAM8g\n"
	"QzNh7394wHpNStxbGq9Xe+7zAoGAJuUzfmL64dwFgQDmow8BjA5jI4mPiXc9+HDl\n"
	"UG0xXT65tUqHyg5fTSVm8p+qWaklZeWTvuDc7KYofGZolG3LxhBKvIXHiUrD5hJ/\n"
	"cE/qcx89oczD7mChHG8k4a+Ysr9/gXMFp8/TUsiTXrPLvEedBiAL9isDGC+ibRsw\n"
	"fFYqGKYCgYEA4XMsR7j2cdjKwpKDHqjstp2OxYBwsse8jgRyZFl/twdb9L8UIeCm\n"
	"cyfsa+cPjGJrKwMUDwBcSH1Am61GItymnXhtWQ93QT7XPe/csOHBVonUOh9YQycC\n"
	"wahFWQC4QGQ0Ppo2gogC5Qy8WWelTxIPlJmtRCQ/baPIyP6bGwme0r0CFDUW6VNf\n"
	"FgAdB5hhtag7oTw45a72\n"
	"-----END DSA PRIVATE KEY-----\n";

const gnutls_datum_t clidsa_ca3_key = { (unsigned char *)clidsa_ca3_key_pem,
					sizeof(clidsa_ca3_key_pem) - 1 };

const gnutls_datum_t clidsa_ca3_cert = { (unsigned char *)clidsa_ca3_cert_pem,
					 sizeof(clidsa_ca3_cert_pem) - 1 };

static char cligost01_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC4zCCAUugAwIBAgIIWcZXXAz6FbgwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA5MjMxMjQ1MTdaGA85OTk5MTIzMTIzNTk1OVowGzEZMBcG\n"
	"A1UEAxMQR09TVC0yMDAxIGNsaWVudDBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcq\n"
	"hQMCAh4BA0MABEBuvOEDe9xPJY9jsnFckLyQ6B5XeDi4Wo2E4c05im/3iI+rlWGI\n"
	"rTc6hMmWca0BVDL0lObZ0ZHb4Vhy0XREgvtro3YwdDAMBgNVHRMBAf8EAjAAMBMG\n"
	"A1UdJQQMMAoGCCsGAQUFBwMCMA8GA1UdDwEB/wQFAwMHsAAwHQYDVR0OBBYEFCck\n"
	"yCTDt+A6zS8SnMRrgbyjeQmoMB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv\n"
	"8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQACkq/DQhHMEZPL0NwPFpnf2+RDviEuRE+C\n"
	"xaOMTbHgxIUSy6xQAaHXK5hNr9xk87OFPPXmNKPl1nVBXrDF0aj+YUVBT2QeJIpA\n"
	"APfyjnPtdZpRl3MXrJbQ/VBCdShvmKhspiOkGO6K8ETDeqE57qtPsUaGApfNK7oL\n"
	"WgevmnkaQqNTVJglOoB5o5IDNv0JuFEkKSEvCgS25OV+gl0rRHmWDaIdQtDJLQjV\n"
	"24b99/woYj0Ql8WfvMUUUYqTX03zmV56k5DgoNusTxKG+r71WQwbeb3XiVjof6I7\n"
	"ll3ANTdyf/KrysLx/tk1pNgfangArpAZzbCRejTQVYdVfCf3KDdwXvKlTHy9Jv+p\n"
	"ZUSf7kMnBqcUHpbceiyHFCXNAKIdrMDkTJAeee7ktpeYMfdO9oBki+6a8RJjNHIr\n"
	"wHe0DcExV7UsokG6jMl8kH7gb7EW0UphL3ncWyY8C4jbtf/q1kci6SZDcapXBpGp\n"
	"adJdx9bycdOUm1cGiboUMMPiCA5bO+Q=\n"
	"-----END CERTIFICATE-----\n";

static char cligost01_ca3_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MEUCAQAwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgEEIgQgVPdBJeLrp/Zh\n"
	"2tiV6qz9N6HraKTFTKz4alNuGhK2iLM=\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t cligost01_ca3_key = {
	(unsigned char *)cligost01_ca3_key_pem,
	sizeof(cligost01_ca3_key_pem) - 1
};

const gnutls_datum_t cligost01_ca3_cert = {
	(unsigned char *)cligost01_ca3_cert_pem,
	sizeof(cligost01_ca3_cert_pem) - 1
};

static char cligost12_256_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC6jCCAVKgAwIBAgIIWcalgS6c0DMwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA5MjMxODE4NDJaGA85OTk5MTIzMTIzNTk1OVowHzEdMBsG\n"
	"A1UEAxMUR09TVCAyMDEyLzI1NiBjbGllbnQwZjAfBggqhQMHAQEBATATBgcqhQMC\n"
	"AiQABggqhQMHAQECAgNDAARArjme5Fb62BC4uPT8vQVim3xTjYY/RVvvUtAfYluY\n"
	"o+8Zjz8A8VTFejK0Zok5f1dssbzrrHtRODJZsCuAjypIXqN2MHQwDAYDVR0TAQH/\n"
	"BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB7AAMB0GA1Ud\n"
	"DgQWBBTzHDVZRnSgaq4M3B7NdLResyKgajAfBgNVHSMEGDAWgBT5qIYZY7akFBNg\n"
	"dg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAtAGi0lQdBC9Mp/TdqYFuMIDr\n"
	"o/xGbie6Eq33BiqXo6B5DOiPZcE1Mi+y4htefvrEBkN4OLy4PbUHlfEC/ATs3X9S\n"
	"cUHucm6gkyzUxTLPYPfTmXD24MRFDAJQKMvX8Pklbi7HyFZVYIQaJfEohaQZmuYR\n"
	"S7Z03MW0Cbz6j7LGQl1Pyix78BLKeyLyAzQz63+hCuO46xp7TaGDKGI79Dd6Od0p\n"
	"oY/B/MxfuP3RXhHrpjgp+Ev08dYoCH3Snps+TYWSyhkN0VhGRJgE5Tnhdly8XMW3\n"
	"WKZqGYmWG+rBtiTgA6FZrw0qYwAsmN3yCo5pE+Ukd0Q5L0tugc0a9HK53AftG/zV\n"
	"qf0DI+E4dEnUkVhdEQbW+rujGpAR0sgjgar5Zvwuu92BaV+AFucj7hVP1fqDySmp\n"
	"E52EzrFcnCYrZb19aDJKgWevG5Vh6OEcu8Vx/zVFOoTx9ZCXniVLm7PaXyKXdhLv\n"
	"Vhg3mi7koFAPGlTiKldJ/LKKPW0yti3I8L/p2F5+\n"
	"-----END CERTIFICATE-----\n";

static char cligost12_256_ca3_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MEgCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgnA1XIfe2\n"
	"V3D0UVFQTRCHolA9v+r5cDt2tlr1gTZbDC8=\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t cligost12_256_ca3_key = {
	(unsigned char *)cligost12_256_ca3_key_pem,
	sizeof(cligost12_256_ca3_key_pem) - 1
};

const gnutls_datum_t cligost12_256_ca3_cert = {
	(unsigned char *)cligost12_256_ca3_cert_pem,
	sizeof(cligost12_256_ca3_cert_pem) - 1
};

static char cligost12_512_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDLzCCAZegAwIBAgIIWcalYA16syEwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA5MjMxODE4MDhaGA85OTk5MTIzMTIzNTk1OVowHzEdMBsG\n"
	"A1UEAxMUR09TVCAyMDEyLzUxMiBjbGllbnQwgaowIQYIKoUDBwEBAQIwFQYJKoUD\n"
	"BwECAQIBBggqhQMHAQECAwOBhAAEgYCyAdmv9viBTnemLvULAZ9RyaEf37ZAydKj\n"
	"E3qLbZ5tTxgLAYhIIGApVPVb5SZxge3u2qY/ekkHjz9Asn5cPQ69wCvce87+2u1f\n"
	"XcATUzYvR3UIL25C5BbNjDjGnufhjYAwT6uZ5xQ7j8/Wfr0MZU04O2CSUquKqfrB\n"
	"DA81M2HvUqN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjAP\n"
	"BgNVHQ8BAf8EBQMDB7AAMB0GA1UdDgQWBBRYXgWHcQazcPFyxKrgRdfd2IPBozAf\n"
	"BgNVHSMEGDAWgBT5qIYZY7akFBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOC\n"
	"AYEAUOpvomUtaFQm5O8bEQk/d3ghZLzwfMKRngSq0XbXDi8t+TV+kFvkzJ/hrAOP\n"
	"/HPCQdnEvdV2HyZzDb9b8cVegRHPPooKSV8+HCTNVXNKZPRSlE42S5kFIAnAxbs5\n"
	"vzGfipp6jQe9dqlCYseikxnE31o3AX7QAlNBaXELu0JnEY5BoJeKoja8XS40b1k9\n"
	"kKRwAGkdh1OcAy6pW8AH4m61RMDWFzmPGgcb0JiDNp+9HQDSkG904niU8AlvmoQD\n"
	"Q2AVd9mam4NIjmA0hkVuSh+7Tn2XnoGoGxN/+u72qaSUA6ybkbtkIKpMeJ8vciI1\n"
	"6GRhBYpI0OuRiAIbDA9WhfCCKwj9ZaIsSSHC7qADRz3bR/89Et1mM40v5jbYNDkV\n"
	"1cvlca3+pK3DxNP7y/q3QoUz8++z9VXzsdVHc4wNUyg4E8mjMcdLlRsZbST0WjX+\n"
	"IhxAkfOexMu3nJ3EVbjgvox6eIxjiTWr2DP6x666UztrnFSBhhypwKHb8jW7PYJ2\n"
	"lWlI\n"
	"-----END CERTIFICATE-----\n";

static char cligost12_512_ca3_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MGoCAQAwIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBEA9uga7\n"
	"LIPp1heDZYj5EozNtbrmsKYMXrFasBIVAFFVQVFd6/+YjttV6Vmx16OFWrM+/ydX\n"
	"rB0aUqYPU8w5DUyk\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t cligost12_512_ca3_key = {
	(unsigned char *)cligost12_512_ca3_key_pem,
	sizeof(cligost12_512_ca3_key_pem) - 1
};

const gnutls_datum_t cligost12_512_ca3_cert = {
	(unsigned char *)cligost12_512_ca3_cert_pem,
	sizeof(cligost12_512_ca3_cert_pem) - 1
};

static char server_ca3_ecc_key_pem[] =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MHgCAQEEIQDn1XFX7QxTKXl2ekfSrEARsq+06ySEeeOB+N0igwcNLqAKBggqhkjO\n"
	"PQMBB6FEA0IABG1J5VZy+PMTNJSuog4R3KmhbmIejOZZgPNtxkJcIubJIIO68kkd\n"
	"GK04pl/ReivZAwibv+85lpT4sm/9RBVhLZM=\n"
	"-----END EC PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_ecc_key = {
	(unsigned char *)server_ca3_ecc_key_pem,
	sizeof(server_ca3_ecc_key_pem) - 1
};

static char server_ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_key = { (unsigned char *)server_ca3_key_pem,
					sizeof(server_ca3_key_pem) - 1 };

static char server_ca3_rsa_pss_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEowIBAAKCAQEAvxOfMAZbqIuVqkPt5s5fyNeuYD09r80oDEN54MS7/tMy+2yk\n"
	"rwsX3a1zGLqn47Q59E0QAlheFP5ZXcQgFXVdQwWCn00YtYyGn5uGrzT80PlIAnaG\n"
	"yVpjLGci7mU13IpHlLKqQbBaCdiDU1qV/fyy03t0KVdlyzTi3RJoKDU3XTG/eJmy\n"
	"bPHuBGzBjtXn4IJkbbe9FL090YJbgu0EqgcVhaon9JOs5cVNGsHZ4zdRo1d9/5zK\n"
	"tqaAVCPYECL/OYwTBS0O8kTrkoHwXo08bR0sUhb7enfI827mOOiIyokkzUu1YVyP\n"
	"6GMnggmoUa8LaSeO3bsWU9rx1ngWBUQ5hBG5JQIDAQABAoIBAAkoYpfFpjz0u66W\n"
	"ZN+MApE4rRXVuZAkcAfub/fy1ePHsYjVUytEh9dLCdokkAlcyO5JhzvlilTNP/E7\n"
	"hiIhJuAgcns6EbYZzxX1OUZKbteBKw9bKOibmWc2Zjkwxp0UT4vz6C8PybDxHJIx\n"
	"JEExDE0QfKfClZFgroLT8AQFUOr5cy8dY2edh17+rMMeBvJ5Yit3L6hlHjO+5eJA\n"
	"E0WzxPrZWIFfAJl484HbZL/kBT8UXqYDTR7MB+qOq8mdKQSLcHwyjvItgvgklEPu\n"
	"0Rl626K+R6841FmrXjUEBVtfkS8Osw/+CJDYw6YZwB7W8oLRRhcB7PjMWU5RHAIW\n"
	"nZKFWn0CgYEA0qsP7FUemy7kG7cA8qMErt7oWV/DYIMpKaCJC+17vk37OmJbUpbo\n"
	"UkfEIY9iT8hcPjP1jAnQf2d0A37zn9B7DTYPhbjbRtNrOSkdrE/u5FeWd4tr9uc7\n"
	"JdYhRc6dkPKbVbFFyo7bdHwU0ZLtfhJYKpTYJ3oNvjsiLqBjIHaj2v8CgYEA6DFV\n"
	"FKlQL9OnzTnQtu5oDvqHFiaHD1wdPTN9MeNWEFdcf/kd3eVvcRmpenGZaud7jn72\n"
	"nhtXXyzc9GlVoKL6R+/1GVexwu477dr2Ci5MwPYGtyh2tJWjgHTad0bT0Jq4Bneu\n"
	"ZuXZ0EszfxTmHkUkPlzvUrbPjoJxgb57P0Qfn9sCgYEAnYrTg5c8Jizw5VD74nfK\n"
	"nsOP2pZk054CgGDPXB4i9fP3Nngrdx3navDEWZySlrttUA8nR6xnQX+qIJslsZQF\n"
	"EaImBYhyYwrkGoEG8b9tFVHy8j9PY/sUHn19sGiNKMJlK7ZATPR8ZSYNo5RPCoLJ\n"
	"cD6TTyJVeLdcHqZOuw4+Bx0CgYAvP5qokauXj+JdiJ5IG0thgOlsQHrLTVtF0Oxw\n"
	"8mnY+W4BPJgvRzjeMvKhz+wALQqffIaCtd2ZqG9t7OFXxtJXQSUG+ylZGVFonV3j\n"
	"xHgp6+aB7uH47VpQEXdDPk5r7I/2APSkS7F/CU55Va9eCYPOjOrGUhz6SuD+HdzG\n"
	"iv5EcQKBgDyt221UUieb1sWhCHaKaQ3z8/aJlzs+ge6kSLqoVjcfr5uOKM1O5O72\n"
	"bfy00r7B8ky77qXNTtzv2xt9Km/hRptqnCHsgly5OXW8pMcFnf7Kdh3Q+c5UzVlc\n"
	"ODwZlaKK2fjp9xr2dNpYjRqyEb1gkC9FJMaxab9OAf+AoQifxncv\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_rsa_pss_key = {
	(unsigned char *)server_ca3_rsa_pss_key_pem,
	sizeof(server_ca3_rsa_pss_key_pem) - 1
};

static char server_ca3_rsa_pss_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEAjCCAjqgAwIBAgIMWSa+iBMb7BVvI0GIMD0GCSqGSIb3DQEBCjAwoA0wCwYJ\n"
	"YIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIDAgEgMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMTkwNDE1MDkyMjIwWhcNNDkxMjMxMDkyMjIwWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAVIwPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAY\n"
	"BgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogMCASADggEPADCCAQoCggEBAL8TnzAG\n"
	"W6iLlapD7ebOX8jXrmA9Pa/NKAxDeeDEu/7TMvtspK8LF92tcxi6p+O0OfRNEAJY\n"
	"XhT+WV3EIBV1XUMFgp9NGLWMhp+bhq80/ND5SAJ2hslaYyxnIu5lNdyKR5SyqkGw\n"
	"WgnYg1Nalf38stN7dClXZcs04t0SaCg1N10xv3iZsmzx7gRswY7V5+CCZG23vRS9\n"
	"PdGCW4LtBKoHFYWqJ/STrOXFTRrB2eM3UaNXff+cyramgFQj2BAi/zmMEwUtDvJE\n"
	"65KB8F6NPG0dLFIW+3p3yPNu5jjoiMqJJM1LtWFcj+hjJ4IJqFGvC2knjt27FlPa\n"
	"8dZ4FgVEOYQRuSUCAwEAAaNQME4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUjFqe\n"
	"vO9heHT9V24WV1ovs7pvUvMwHwYDVR0jBBgwFoAU+aiGGWO2pBQTYHYPAZo1Nu/x\n"
	"tK8wPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgw\n"
	"CwYJYIZIAWUDBAIBogMCASADggGBAAgVZdGqSwhaa8c/KuqsnELoK5QlzdSUNZ0O\n"
	"J31nVQyOmIJtqR14nMndU0y1iowAoj0osZFYjxjN6e2AqUF7R22uhtxmG6rr0YEi\n"
	"XS+rNpbs7+gY/3hK30vo376QL85+U4v4HuTCd+yX8bY9VPqwZBMYO5rcDyXG82xC\n"
	"ZKXT/Tr7XD80iMFjyR2cvRAjoZQeXbWzNE4AEm0jNz2F5Qnl6uSgtpDkHYKgr9xq\n"
	"yUhm/WNKG86pzBxfcFju4prqBLiwUZh068b6znBAS0wMflrF/lznu01QqDhK6mz3\n"
	"cSn5LlzoKjuouAWdZRieqokr1mNiWggmX5n2qKM9FJtDQctsvntCf/freAfy+Xmu\n"
	"Tm055R9UzX76mL89eXY92U++HR8Y5IO5lqY1f13rzWK5rJB9qjz/Mamj9xR6Egoa\n"
	"hh1ysRItcTCFJI5xKb/i3hHv94U12EH1IfFHofptr1pyCtAeOhJytWPndCiB2m1q\n"
	"M2k3tl6cHvlUz7DpgnxNniuQ/dQ4MA==\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_rsa_pss_cert = {
	(unsigned char *)server_ca3_rsa_pss_cert_pem,
	sizeof(server_ca3_rsa_pss_cert_pem) - 1
};

static char server_ca3_rsa_pss2_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIE7AIBADA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3\n"
	"DQEBCDALBglghkgBZQMEAgGiAwIBIASCBKYwggSiAgEAAoIBAQCte+3f4Sgy89/R\n"
	"LNfx/NazlTgHxL6IXJuL44tutdhxA91vCJt0+ZSShWibsuyF+H09it3G0+3LvE2W\n"
	"vkU58ha7ljvCWckPf2+YpsFynNQc0Lw6BThRMQdJpJvI54OdxfhoPjhDnTui/EEj\n"
	"/n9MbLo5rAX5ZDIpWa3Vgpl37Q8czjFINCgQ/f8qsD4WabBSbuSnrYDvuASGez4O\n"
	"YDAFvM51+4U4GxN7ZKbrDTQcAySU0Fjy+I5eW/BIXd9TeHb6XYJudMQY7rozTijm\n"
	"6qbZieahke+FUCgm8BnRXghfcVSswUZEJQkCvF+SdUl3iAYlY/UBzVFsGDSFbID2\n"
	"XRtEvrnvAgMBAAECggEATj8COCL+lZSnU1oNgAiQ8eiQn/heE3TpdzvHLMT5/WdH\n"
	"3YedTjIvj7J6TxdxVK+SFUrn4oC91VF2EVJ6OLt3A16sT2ldpQ7OT6SOxdn0VZbT\n"
	"/rtR/lTFu7JxzTiWhXfAJYxCpkRpnIZ3/vsPgXHcwJxVCXnmof3fyNghzhRu54de\n"
	"V5GUwJ6TT3MMYLYKf5ii8Yt9WqeekQF7Hy/kIwz+4CbgR3fDdRXFnRwdNmA4RG3w\n"
	"TbwvqR9ApyAictYz4HpZWgYL+cXsH6Fm+/ChZiV9/zvdVVOo+dOAcxx2cWahm/NL\n"
	"tksGD7hI5kqD9moi2wiAsGHPa+/rkLxIBm0xvF1veQKBgQDVFKujtQyfzJw5DUPL\n"
	"kTCLp+370ZBTK01daKZrpfgw6QrylYljcIq8n1izauElYm5cZ9krMGzvL5ceg49p\n"
	"obl1tdCOQJQACrJmLZSuvVfw8TSwHPyOGtRWxhF4miX+ym3yMFqRyN2nXx1iAo5I\n"
	"Cz+aGmTfT1zSZkLnfQSjYWZFgwKBgQDQbX2wPavLI+1yWARStqrwVWO1mU0Nixbo\n"
	"jHrRlzrKYqtV+0ea6550LtDG5A/zf9MP6439NNHPqs4rnY910odd+xmLdQj2gocB\n"
	"IS4nPBE4o1k3L9m+bSw9nyDdJWRkASq4uem6QvyVsQpWUoxzmg5/fwRUlOU8X3pP\n"
	"ZLSSpz06JQKBgF4b6AbAwtedFe54tlWlRWyY+Zn7n6Or/1pfCwmGXwyzEJu9gdWC\n"
	"cjQGqLVtYg0R4S48y4SwuZwWR8c5UdDUlcWwTHFXgkZWcx5/ySg4BiwrTBrwYncc\n"
	"0GWWy0aZxmg23cJWqtmyfnsani6YdGDLXwbf22dpdNSUR75X0AGc1f+jAoGADha4\n"
	"nkcs66hcDpSghi7O0zwSZ14bdUTnoYSNcMl2MeQFjORVbMVsipH3jtovsdf8HmFf\n"
	"0bPWUuFK2mvmHKLEf7fPfDvHBVLBaXQiuIg46ckw6KgVYefjS68L+6bhaFkj2CTJ\n"
	"BcwtYrj65+bgk5fgTwH4+vatoC0cCW3XPuqLGvkCgYAj2NGQAEQ4HkmF55otDocZ\n"
	"SkAJFfibyrkKEK+PsQ7dRR/HEc93hvkI0PHpsLx8A3FZ370FAPtiKmnmfabHxEsK\n"
	"TWA2DTacq//MzXQrjsx0CpvGId1dOyVZIrwIFM17KmW5HHE37fY4PFZTZVXHAKf6\n"
	"nQyUF7m3FUJjavm46KJIhw==\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_rsa_pss2_key = {
	(unsigned char *)server_ca3_rsa_pss2_key_pem,
	sizeof(server_ca3_rsa_pss2_key_pem) - 1
};

static char server_ca3_rsa_pss2_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIID0TCCAjmgAwIBAgIIWXYEJjkAauMwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA3MjQxNDI4NTVaGA85OTk5MTIzMTIzNTk1OVowADCCAVIw\n"
	"PQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJ\n"
	"YIZIAWUDBAIBogMCASADggEPADCCAQoCggEBAK177d/hKDLz39Es1/H81rOVOAfE\n"
	"vohcm4vji2612HED3W8Im3T5lJKFaJuy7IX4fT2K3cbT7cu8TZa+RTnyFruWO8JZ\n"
	"yQ9/b5imwXKc1BzQvDoFOFExB0mkm8jng53F+Gg+OEOdO6L8QSP+f0xsujmsBflk\n"
	"MilZrdWCmXftDxzOMUg0KBD9/yqwPhZpsFJu5KetgO+4BIZ7Pg5gMAW8znX7hTgb\n"
	"E3tkpusNNBwDJJTQWPL4jl5b8Ehd31N4dvpdgm50xBjuujNOKObqptmJ5qGR74VQ\n"
	"KCbwGdFeCF9xVKzBRkQlCQK8X5J1SXeIBiVj9QHNUWwYNIVsgPZdG0S+ue8CAwEA\n"
	"AaOBjTCBijAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDATBgNV\n"
	"HSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBQCiLaK\n"
	"LrqB0vaCnoNP1V8QVLlA8jAfBgNVHSMEGDAWgBT5qIYZY7akFBNgdg8BmjU27/G0\n"
	"rzANBgkqhkiG9w0BAQsFAAOCAYEANgnTu4nYiv1nH6Iqpnn48CNrGK25ax6FuPvc\n"
	"HxOyFFa9jomP8KjyNv3EsmmoBcQBkbRdAX8sFdtbyjILqRLoRMFO7D60BmCitGYH\n"
	"MDjEIkG9QjcCo03YIT93SORwnt1qrWh6paOH7Nme+CsgRyXN7iNNur2LgGSilQ7P\n"
	"Rs/vr0DdxmlUxUQHDa5GRIvU3FFs4NLC/9sQd3+JGqzDbY7UqLnP5fzn6/PSMKIw\n"
	"Gc4IzbJrqjFsyfjQkblM2eBwmkUD3SnTFWqYwUsohGlSxBwKSIyVzlyuoD1FXop7\n"
	"lgG8/a1D/ZFa34q8tj24Wnd9zdr/Jrv2g51OSf0VIbQdP92l2kDouobPS/7DTgPI\n"
	"D7h52NLVm8cbV1RqxbeS3spZ2OAQn8tLiTwz+abNdsikFjMvfXq61iIv3QASUyUB\n"
	"VydSB7stwAUd6wys2H7crmeiMMtgxSjZJtB4GDUCb24a+/a4IgpqxFzGDLE9Ur69\n"
	"D8aQbKGJzzih56a2wwc0ZqA0ilGm\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_rsa_pss2_cert = {
	(unsigned char *)server_ca3_rsa_pss2_cert_pem,
	sizeof(server_ca3_rsa_pss2_cert_pem) - 1
};

static char cli_ca3_rsa_pss_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEAjCCAjqgAwIBAgIMWSa+VhOfC8uEpb/cMD0GCSqGSIb3DQEBCjAwoA0wCwYJ\n"
	"YIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIDAgEgMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMDQwMjI5MTUyMTQyWhcNMjQwMjI5MTUyMTQxWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAVIwPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAY\n"
	"BgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogMCASADggEPADCCAQoCggEBAL8TnzAG\n"
	"W6iLlapD7ebOX8jXrmA9Pa/NKAxDeeDEu/7TMvtspK8LF92tcxi6p+O0OfRNEAJY\n"
	"XhT+WV3EIBV1XUMFgp9NGLWMhp+bhq80/ND5SAJ2hslaYyxnIu5lNdyKR5SyqkGw\n"
	"WgnYg1Nalf38stN7dClXZcs04t0SaCg1N10xv3iZsmzx7gRswY7V5+CCZG23vRS9\n"
	"PdGCW4LtBKoHFYWqJ/STrOXFTRrB2eM3UaNXff+cyramgFQj2BAi/zmMEwUtDvJE\n"
	"65KB8F6NPG0dLFIW+3p3yPNu5jjoiMqJJM1LtWFcj+hjJ4IJqFGvC2knjt27FlPa\n"
	"8dZ4FgVEOYQRuSUCAwEAAaNQME4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUjFqe\n"
	"vO9heHT9V24WV1ovs7pvUvMwHwYDVR0jBBgwFoAU+aiGGWO2pBQTYHYPAZo1Nu/x\n"
	"tK8wPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgw\n"
	"CwYJYIZIAWUDBAIBogMCASADggGBAI435L6mZnGnCtQdtUBGgypMP2g5VuSBu2lP\n"
	"5msLYuK2vPZTCtCLAg2JSsQhVaDDK+V7wtyXIgnEtQWrDE3RQBmWtCWpVrrP7kh3\n"
	"ZN751l6+z1UTEg8sVQ7MODbEZCB9+2XXAb50Oh4cO65IfUI5Sqnn2+k3ZPLp280s\n"
	"KdlaA4ZzmQSZcgEDWtoch8QiO+HvlXGqjejQUFh1ObBJXpXX5Q7NP5K7ChI82LPJ\n"
	"T+rdqTopIgM3nAg9Je7gqsHiPdEdpArKwQq9wMxTmtQECK6KInueaDXuoDs5xg6k\n"
	"XYQ1fiS0SI/pJ9xn0SCc6BNmkbfTpmKVwF9MWIyGyzWBhkSSWxsKbh5OuUCWJsyG\n"
	"eLOrPK9fVKv/YQCfDHC3F1WI6xtHg7CCD7vvyJv5bFH8LN8YGoZNt1ZfU1lNw7rP\n"
	"sRecz45/okiAbk9/SgnpzHInNBBzYu2Ym+yGVO/tIeErPXrnkM7uF9Di/K1n2+zF\n"
	"vXOeamGsi2jyiC5LbreWecbMnzi3vQ==\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t cli_ca3_rsa_pss_cert = {
	(unsigned char *)cli_ca3_rsa_pss_cert_pem,
	sizeof(cli_ca3_rsa_pss_cert_pem) - 1
};

#define cli_ca3_rsa_pss_key server_ca3_rsa_pss_key

/* server EdDSA key */
static char server_ca3_eddsa_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MC4CAQAwBQYDK2VwBCIEIBypI9w1qP3WLaiYuWB7zhA99GTG5UsKZVZqPHNlUaIv\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_eddsa_key = {
	(unsigned char *)server_ca3_eddsa_key_pem,
	sizeof(server_ca3_eddsa_key_pem) - 1
};

static char server_ca3_eddsa_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBEzCBxqADAgECAgxZLBvYDjrxFhfqLoIwBQYDK2VwMA0xCzAJBgNVBAYTAkdS\n"
	"MB4XDTA0MDIyOTE1MjE0MloXDTI0MDIyOTE1MjE0MVowDTELMAkGA1UEBhMCR1Iw\n"
	"KjAFBgMrZXADIQCrr5izw0GNQSIhwYanuHD7RG7HfiCHe9kipF3SlwnVSKNAMD4w\n"
	"DAYDVR0TAQH/BAIwADAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBSJg0wiKtJf\n"
	"jqv1BmHV8w0JD5X2BjAFBgMrZXADQQB94NbYtwGCvyI6EvBZk5xgOyWNdKVy9peh\n"
	"KKn/PNiAq4fPNEupyzC3AzE1xLzKLRArAFFDDUjPCwy3OR4js3MF\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_eddsa_cert = {
	(unsigned char *)server_ca3_eddsa_cert_pem,
	sizeof(server_ca3_eddsa_cert_pem) - 1
};

/* server Ed448 key */
static char server_ca3_ed448_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MEcCAQAwBQYDK2VxBDsEOXPoCtsxxy7itrHfeuQ2bG7oh3uerkBwhabkeSsNFYoS\n"
	"QYy6KKYld8lnhlYQQmMo6lx28x9GmpTiag==\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_ed448_key = {
	(unsigned char *)server_ca3_ed448_key_pem,
	sizeof(server_ca3_ed448_key_pem) - 1
};

static char server_ca3_ed448_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICqzCCAROgAwIBAgIUAvQ9bcei1eNZ9viV1kP7MKODp9YwDQYJKoZIhvcNAQEL\n"
	"BQAwDzENMAsGA1UEAxMEQ0EtMzAgFw0yMzA5MjgwNjU1NThaGA85OTk5MTIzMTIz\n"
	"NTk1OVowDTELMAkGA1UEBhMCR1IwQzAFBgMrZXEDOgAYxZxGeKtoWUL20zvrFClm\n"
	"irhECIIdccq6x0uZccYHfmRVkFoUI7iOFj6Mlsp5vg24XZ2tGF5MBACjYDBeMAwG\n"
	"A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTYq6RhA2qMWmYM\n"
	"UAEx3AlNSnhWHDAfBgNVHSMEGDAWgBT5qIYZY7akFBNgdg8BmjU27/G0rzANBgkq\n"
	"hkiG9w0BAQsFAAOCAYEAhEd0coRahGvMx8gLS8biuaqh50+9RJIjMpf+/0IQJ4DV\n"
	"FHT5E70YyaQ0YOsvyxGa04d+KyhdVLppD1pDztLGXYZWxzmowopwpgnpPNT25M+0\n"
	"aQOvCZZvRlqmwgUiRXdhSxqPsUj/73uUBPIjFknrxajoox7sOLris9ujmidqgBGa\n"
	"H1FVbQQQgDOBCKcKXTAllVKzS/ZLwlRHibbm+4UDxGk1tJv1dbnQhJk0FYSQZn3h\n"
	"ZVmSSfP4ZB+U+lsCshypBJ9qVZEqMM2b4m1wv/VAOuw0lGA2SiPub5q91hFYRdeL\n"
	"9FB78/WlrSCTbGeMzzDPXBf/Y2KvFAv3o7K0tsMg1vBsDJBARHEzo4GMRsYDZzvI\n"
	"JXb5tSmJOi/PBfup8GPiG0WbZV9nuvW8V/zmfaP3s9YBfYOtL/+nZch9VdSee2xp\n"
	"T8arukB/s2jLaXQUduD3hoFvFNgCvWJwAWQWNNyHN3ivArqNQpfl2Gtftmb6xCdW\n"
	"Xwt1/q2XKqqLpnF1N2wU\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_ed448_cert = {
	(unsigned char *)server_ca3_ed448_cert_pem,
	sizeof(server_ca3_ed448_cert_pem) - 1
};

static char server_ca3_gost01_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MEUCAQAwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgEEIgQgR1lBLIr4WBpn\n"
	"4MOCH8oxGWb52EPNL3gjNJiQuBQuf6U=\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_gost01_key = {
	(unsigned char *)server_ca3_gost01_key_pem,
	sizeof(server_ca3_gost01_key_pem) - 1
};

static char server_ca3_gost01_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC7TCCAVWgAwIBAgIIWcZJ7xuHksUwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xOTEwMDgxMDQ2NDBaGA85OTk5MTIzMTIzNTk1OVowDTELMAkG\n"
	"A1UEAxMCR1IwYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARA0Lvp\n"
	"9MaoYDxzkURVz71Q3Sw9Wrwa2F483xDd0mOID8CK7JY8C8gz/1dfZniUObT1JMa6\n"
	"hkGsQyFvPLD6Vr1bN6OBjTCBijAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxv\n"
	"Y2FsaG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB4AAMB0G\n"
	"A1UdDgQWBBSGUfwGWchcx3r3TNANllOEOFkTWDAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEACdzEVIyFvPlx2J7Ab4Hq\n"
	"Oz0IGk2QaZ4cJkWZxjrPc7u6XCeBah8TEtF12LJ6vXBS+Cf9IF50YIMK/8GjJjs1\n"
	"Allwdx79RuWFS2TdnsAjsAWwyKBQITkmv/kXULtExC9ospdGVIeYbdcmufgk023Q\n"
	"PJh5LAMXHZ1lrsI1DgBhihgZx86wTAGd8yRC+dratvSbawC0sFan8X1n9R/Fxkzt\n"
	"YuLEulh7FZpTWPYu30fyUrpEZVCWPlCzCrSijhCVBhAnT4eEGd7qmU0Oj+khHFNn\n"
	"iVJ40/3JG21Yln2t/8uY1YIM2+ISTk4n2gkmXHrRAfNi3bXupdQQyAqRRT7b/Y/y\n"
	"jhYzWekGLAvz0qrS78Ls8Kp7TfhIVEcWz9pfo77SmURxT6SDTiet7W5VD+VaS+hW\n"
	"jl4L+IGxCsBIY5mWlT8KYTNHG34ln+5W+TfZMGARZFf4ZfQi2lgs3p0oqn6f9c+w\n"
	"AdMyo73YqtbmVT2eGB05ezMeRl2Anjfwvj9JinhHMC04\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_gost01_cert = {
	(unsigned char *)server_ca3_gost01_cert_pem,
	sizeof(server_ca3_gost01_cert_pem) - 1
};

static char server_ca3_gost12_256_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MEgCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQg0+JttJEV\n"
	"Ud+XBzX9q13ByKK+j2b+mEmNIo1yB0wGleo=\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_gost12_256_key = {
	(unsigned char *)server_ca3_gost12_256_key_pem,
	sizeof(server_ca3_gost12_256_key_pem) - 1
};

static char server_ca3_gost12_256_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC8DCCAVigAwIBAgIIWcZKgxkCMvcwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xOTEwMDgxMDQ4MTZaGA85OTk5MTIzMTIzNTk1OVowDTELMAkG\n"
	"A1UEAxMCR1IwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARA\n"
	"J9sMEEx0JW9QsT5bDqyc0TNcjVg9ZSdp4GkMtShM+OOgyBGrWK3zLP5IzHYSXja8\n"
	"373QrJOUvdX7T7TUk5yU5aOBjTCBijAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuC\n"
	"CWxvY2FsaG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB4AA\n"
	"MB0GA1UdDgQWBBQYSEtdwsYrtnOq6Ya3nt8DgFPCQjAfBgNVHSMEGDAWgBT5qIYZ\n"
	"Y7akFBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAR0xtx7MWEP1KyIzM\n"
	"4lXKdTyU4Nve5RcgqF82yR/0odqT5MPoaZDvLuRWEcQryztZD3kmRUmPmn1ujSfc\n"
	"BbPfRnSutDXcf6imq0/U1/TV/BF3vpS1plltzetvibf8MYetHVFQHUBJDZJHh9h7\n"
	"PGwA9SnmnGKFIxFdV6bVOLkPR54Gob9zN3E17KslL19lNtht1pxk9pshwTn35oRY\n"
	"uOdxof9F4XjpI/4WbC8kp15QeG8XyZd5JWSl+niNOqYK31+ilQdVBr4RiZSDIcAg\n"
	"twS5yV9Ap+R8rM8TLbeT2io4rhdUgmDllUf49zV3t6AbVvbsQfkqXmHXW8uW2WBu\n"
	"A8FiXEbIIOb+QIW0ZGwk3BVQ7wdiw1M5w6kYtz5kBtNPxBmc+eu1+e6EAfYbFNr3\n"
	"pkxtMk3veYWHb5s3dHZ4/t2Rn85hWqh03CWwCkKTN3qmEs4/XpybbXE/UE49e7u1\n"
	"FkpM1bT/0gUNsNt5h3pyUzQZdiB0XbdGGFta3tB3+inIO45h\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_gost12_256_cert = {
	(unsigned char *)server_ca3_gost12_256_cert_pem,
	sizeof(server_ca3_gost12_256_cert_pem) - 1
};

static char server_ca3_gost12_512_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MGACAQAwFwYIKoUDBwEBAQIwCwYJKoUDBwECAQIBBEIEQJLtsCFM/m6blvHOJoqS\n"
	"FvrFIjlYFAJKVqIc8FoxuCaAmIXxG5sXuTRgx5+m3T6wDca9UYAqMvsIsEREObti\n"
	"+W8=\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_gost12_512_key = {
	(unsigned char *)server_ca3_gost12_512_key_pem,
	sizeof(server_ca3_gost12_512_key_pem) - 1
};

static char server_ca3_gost12_512_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDKzCCAZOgAwIBAgIIWcZKvSvigz0wDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xOTEwMDgxMTAwNDRaGA85OTk5MTIzMTIzNTk1OVowDTELMAkG\n"
	"A1UEAxMCR1IwgaAwFwYIKoUDBwEBAQIwCwYJKoUDBwECAQIBA4GEAASBgDIyIpfh\n"
	"R0umZWQl6GEhjjhjZ6cWlYJ41JHo6hx8cLxHopOjSrHEQRxabnfI07e9IjlK0MZu\n"
	"oS8ngfbyAEI0LycgiOgDTriO8l10NEM/Yr1l+A5qHsZ9Oh46ijUlPTT6WEZzK/yU\n"
	"RQmjg0TQFQUPQrwSfkW8lJzbINwaHCWWqSdxo4GNMIGKMAwGA1UdEwEB/wQCMAAw\n"
	"FAYDVR0RBA0wC4IJbG9jYWxob3N0MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1Ud\n"
	"DwEB/wQFAwMHgAAwHQYDVR0OBBYEFF7gSAq4EPp6G8FYvT+ECRRVrGTcMB8GA1Ud\n"
	"IwQYMBaAFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQAO\n"
	"kFNTy9UqIkG5tDiW+O8QuV8A+Xvw2CLiIqDvkLhR1FQnXYs5OFquNBLyA2NSR5bk\n"
	"OO+68sXj6iB9tGJWhHXo6efwsxR4maxHv7R8Gp6fFysEGtVV1MG+vpNOjoQNreVh\n"
	"41D9/FU7eVqe6oSw5DtuUQvwrk3jooT4b9dpk2g1ihY33BrpA+vg9XnvN3+7dDNd\n"
	"0xfRXKR9aGhWZsschps9xJqfzx63CZrH14+jHKxYPupSL7d/Akm3MDOf9XLa+vnY\n"
	"WG6lHpkvGl0b8A6yxHHqDCctnE+aJGK6lMyZ1cd8GiStgcihussKGKvKsKygAM4J\n"
	"zPxBQtTv11qjuyMksq5Gw6ctq/GO/M7eUoi/xf/O9+QOwDO/urocBJYY0BmsQWlR\n"
	"VFjuOouE2GN7UPo6VyMiXpe75Wi9CNX/szNF+HnS4hCJGV5kz4ULaJnFxPE/oQwa\n"
	"nlFDKO1feGQG0gOyf2jMzY1OD35SYss4Falc18iB3YQKigGkyqb+VeGyE8kq1UY=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_gost12_512_cert = {
	(unsigned char *)server_ca3_gost12_512_cert_pem,
	sizeof(server_ca3_gost12_512_cert_pem) - 1
};

/* shares server_ca3 key */
static char server_localhost6_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIENzCCAp+gAwIBAgIMV6MdMjdkWPp7Um/XMA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1MTU1WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MAAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4Z\n"
	"nJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wq\n"
	"HIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270\n"
	"tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2a\n"
	"QK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHG\n"
	"oszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKS\n"
	"G/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4t\n"
	"cZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCC\n"
	"nVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaOBnDCBmTAM\n"
	"BgNVHRMBAf8EAjAAMCMGA1UdEQQcMBqCCmxvY2FsaG9zdDaCDHd3dy5ub25lLm9y\n"
	"ZzATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQW\n"
	"BBQzneEn04vV/OsF/LXHgWlPXjvZ1jAfBgNVHSMEGDAWgBQtMwQbJ3+UBHzH4zVP\n"
	"6SWklOG3oTANBgkqhkiG9w0BAQsFAAOCAYEALXeJO70urguPXDXTPPfqOVZb9NOh\n"
	"+1rHRtt1LIr6WxGMLDIuUwwjhExSR/XDnhzgy1G6Zxodsm1FV5aEmDhU9cz0MpkF\n"
	"G1ndhGK+Y3Qey9L/8x7yuHoqLfcqiqe5Kxpq9zVfy87M1JC8FuFpRXgnXkbjnPRm\n"
	"rDA7d0KtJfU93mmoI1yPDqYcJK6I62waIfRn5AcgGiMr8tT5oreIXPhjxiU15Say\n"
	"ETqT0nSx3kB1VTm0K4mByIueGclnb5epUQ/suq9S++QW7Z9DD/8bfehXZaB1lb7r\n"
	"jTMFQAzmrR7x53ZwKWry5iu6MXxFnWKTpBdGcgztbj34NM4VLqrdC15c0lj+OJ/3\n"
	"0sbJ1YU3XCh6GZ96t3RPevSvimxMZfVquoBrr7/79PKxOnBY+amJYILqjzqvqIvr\n"
	"LoPj0OuKmN7XiWINFAgz5/oj8Bq/4vu8Bsu4fwbgMeHt5Z0eIo8XtqblxnCASFDZ\n"
	"yrRp0uKt24DKjSiJWnoqc+VjuvFECgGUzdts\n"
	"-----END CERTIFICATE-----\n";

static char server_localhost6_ca3_cert_chain_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIENzCCAp+gAwIBAgIMV6MdMjdkWPp7Um/XMA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1MTU1WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MAAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4Z\n"
	"nJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wq\n"
	"HIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270\n"
	"tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2a\n"
	"QK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHG\n"
	"oszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKS\n"
	"G/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4t\n"
	"cZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCC\n"
	"nVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaOBnDCBmTAM\n"
	"BgNVHRMBAf8EAjAAMCMGA1UdEQQcMBqCCmxvY2FsaG9zdDaCDHd3dy5ub25lLm9y\n"
	"ZzATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQW\n"
	"BBQzneEn04vV/OsF/LXHgWlPXjvZ1jAfBgNVHSMEGDAWgBQtMwQbJ3+UBHzH4zVP\n"
	"6SWklOG3oTANBgkqhkiG9w0BAQsFAAOCAYEALXeJO70urguPXDXTPPfqOVZb9NOh\n"
	"+1rHRtt1LIr6WxGMLDIuUwwjhExSR/XDnhzgy1G6Zxodsm1FV5aEmDhU9cz0MpkF\n"
	"G1ndhGK+Y3Qey9L/8x7yuHoqLfcqiqe5Kxpq9zVfy87M1JC8FuFpRXgnXkbjnPRm\n"
	"rDA7d0KtJfU93mmoI1yPDqYcJK6I62waIfRn5AcgGiMr8tT5oreIXPhjxiU15Say\n"
	"ETqT0nSx3kB1VTm0K4mByIueGclnb5epUQ/suq9S++QW7Z9DD/8bfehXZaB1lb7r\n"
	"jTMFQAzmrR7x53ZwKWry5iu6MXxFnWKTpBdGcgztbj34NM4VLqrdC15c0lj+OJ/3\n"
	"0sbJ1YU3XCh6GZ96t3RPevSvimxMZfVquoBrr7/79PKxOnBY+amJYILqjzqvqIvr\n"
	"LoPj0OuKmN7XiWINFAgz5/oj8Bq/4vu8Bsu4fwbgMeHt5Z0eIo8XtqblxnCASFDZ\n"
	"yrRp0uKt24DKjSiJWnoqc+VjuvFECgGUzdts\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
	"EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
	"NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
	"uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
	"kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
	"AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
	"JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
	"ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
	"ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
	"jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
	"A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
	"PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
	"QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
	"R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
	"cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
	"+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
	"EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
	"haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
	"frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost6_cert = {
	(unsigned char *)server_localhost6_ca3_cert_pem,
	sizeof(server_localhost6_ca3_cert_pem) - 1
};

const gnutls_datum_t server_ca3_localhost6_cert_chain = {
	(unsigned char *)server_localhost6_ca3_cert_chain_pem,
	sizeof(server_localhost6_ca3_cert_chain_pem) - 1
};

/* shares server_ca3 key */
static char server_ipaddr_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEAzCCAmugAwIBAgIMWNI1ISkCpEsFglgfMA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMDQwMjI5MTUyMTQyWhcNMjQwMjI5MTUyMTQxWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmq\n"
	"LPfAu7P4Hhmcm4KmEsRfuTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+S\n"
	"HFiIlEJfvCociQkrgSfloTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU0\n"
	"3LdpuR9TbvS2fMVjmaRjBiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4z\n"
	"ETxnMYOFbZpArkizpBi/RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyE\n"
	"VD1JsrlgccaizNUkiUi7Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWw\n"
	"wuDlnsmI0pIb9/4RH0LMMlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSb\n"
	"cCzHl25abi1xmbsV5ydomJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbh\n"
	"Gfo7V9z2gIKdUCLRXoUszhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQAB\n"
	"o2EwXzAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwHQYDVR0OBBYEFDOd\n"
	"4SfTi9X86wX8tceBaU9eO9nWMB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv\n"
	"8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQCNwaCnuNcrSpKjNI99kwuS2/LRnt40yN0B\n"
	"LvN4wnkfEh02LXg2ylXCYZZw59m3w7Cefr1BGLXJjbJTNHASjSOvmurJVEX5sqdX\n"
	"zGQs9HzysDvTVHQh1VUWXyj612DUWZoAYYaUg+CiAZLA/ShT+zN/OC8kWa1RXZPt\n"
	"BfTM7REBxAOxUEDuL1aa/KkFqXgy3cr795TWqdt0lZ/dk7kHxqZKR7nJ2TcOmYK9\n"
	"UdJWnmebDgjlRvXS4CgG8JNzyJtukogSjmp7qsxX9QZ1umUw3Lf7StSdXZT1oIDI\n"
	"evLJCTohtE3/ocRlHfQ9l+B8V+8z7YE+0liFwjwUyrYVUpJ2YuPmHHfauTI2JyVX\n"
	"Kk9dJopvnkhA6rIvNjkd3N3iWE3ftSkk/PV9Iu7PQ2jtR8JXkPMJfgq0owbxhn5N\n"
	"oqQW/zQU7pq4Y9+rvH2qPFSxHGmecBhxetXoAPT66hHJCUTAspF/5DgT6TVMu+Gs\n"
	"hiRt+POJ1lVlGUHsF9Z7IE/d+NCESwU=\n"
	"-----END CERTIFICATE-----\n";

static char server_ipaddr_ca3_cert_chain_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEAzCCAmugAwIBAgIMWNI1ISkCpEsFglgfMA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMDQwMjI5MTUyMTQyWhcNMjQwMjI5MTUyMTQxWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmq\n"
	"LPfAu7P4Hhmcm4KmEsRfuTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+S\n"
	"HFiIlEJfvCociQkrgSfloTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU0\n"
	"3LdpuR9TbvS2fMVjmaRjBiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4z\n"
	"ETxnMYOFbZpArkizpBi/RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyE\n"
	"VD1JsrlgccaizNUkiUi7Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWw\n"
	"wuDlnsmI0pIb9/4RH0LMMlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSb\n"
	"cCzHl25abi1xmbsV5ydomJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbh\n"
	"Gfo7V9z2gIKdUCLRXoUszhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQAB\n"
	"o2EwXzAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwHQYDVR0OBBYEFDOd\n"
	"4SfTi9X86wX8tceBaU9eO9nWMB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv\n"
	"8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQCNwaCnuNcrSpKjNI99kwuS2/LRnt40yN0B\n"
	"LvN4wnkfEh02LXg2ylXCYZZw59m3w7Cefr1BGLXJjbJTNHASjSOvmurJVEX5sqdX\n"
	"zGQs9HzysDvTVHQh1VUWXyj612DUWZoAYYaUg+CiAZLA/ShT+zN/OC8kWa1RXZPt\n"
	"BfTM7REBxAOxUEDuL1aa/KkFqXgy3cr795TWqdt0lZ/dk7kHxqZKR7nJ2TcOmYK9\n"
	"UdJWnmebDgjlRvXS4CgG8JNzyJtukogSjmp7qsxX9QZ1umUw3Lf7StSdXZT1oIDI\n"
	"evLJCTohtE3/ocRlHfQ9l+B8V+8z7YE+0liFwjwUyrYVUpJ2YuPmHHfauTI2JyVX\n"
	"Kk9dJopvnkhA6rIvNjkd3N3iWE3ftSkk/PV9Iu7PQ2jtR8JXkPMJfgq0owbxhn5N\n"
	"oqQW/zQU7pq4Y9+rvH2qPFSxHGmecBhxetXoAPT66hHJCUTAspF/5DgT6TVMu+Gs\n"
	"hiRt+POJ1lVlGUHsF9Z7IE/d+NCESwU=\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
	"EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
	"NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
	"uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
	"kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
	"AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
	"JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
	"ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
	"ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
	"jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
	"A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
	"PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
	"QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
	"R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
	"cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
	"+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
	"EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
	"haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
	"frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_ipaddr_cert = {
	(unsigned char *)server_ipaddr_ca3_cert_pem,
	sizeof(server_ipaddr_ca3_cert_pem) - 1
};

const gnutls_datum_t server_ca3_ipaddr_cert_chain = {
	(unsigned char *)server_ipaddr_ca3_cert_chain_pem,
	sizeof(server_ipaddr_ca3_cert_chain_pem) - 1
};

/* shares server_ca3 key - uses IDNA2003 encoding */
static char server_localhost_utf8_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIESDCCArCgAwIBAgIMWElUMBlK8XImg3gXMA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMDQwMjI5MTUyMTQyWhcNMjQwMjI5MTUyMTQxWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmq\n"
	"LPfAu7P4Hhmcm4KmEsRfuTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+S\n"
	"HFiIlEJfvCociQkrgSfloTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU0\n"
	"3LdpuR9TbvS2fMVjmaRjBiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4z\n"
	"ETxnMYOFbZpArkizpBi/RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyE\n"
	"VD1JsrlgccaizNUkiUi7Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWw\n"
	"wuDlnsmI0pIb9/4RH0LMMlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSb\n"
	"cCzHl25abi1xmbsV5ydomJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbh\n"
	"Gfo7V9z2gIKdUCLRXoUszhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQAB\n"
	"o4GlMIGiMAwGA1UdEwEB/wQCMAAwUgYDVR0RBEswSYITd3d3LnhuLS1reGF3aGt1\n"
	"LmNvbYIieG4tLWZpcXUxYXowM2MxOHQueG4tLW14YWgxYW1vLmNvbYIObG9jYWxo\n"
	"b3N0LXV0ZjgwHQYDVR0OBBYEFDOd4SfTi9X86wX8tceBaU9eO9nWMB8GA1UdIwQY\n"
	"MBaAFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQBHHhTy\n"
	"X3AjFcrDa27yN5lnfZfrJ1QGdjoxbcGlWuwI5+EsRInxZSvXQVyh+P9YTphdqAMj\n"
	"YsGCrzqD6+2SkBhrd7/KbmGZF3zFpqe9IcqS2m2u3Z0q4oNjhai86PIRlTSl+Dm/\n"
	"V0T98Fsx/Ec/T509E+HCSYhZgX1A1wCw0jrPJ4UcT9S0jwmP3q8KIXrVAC88tmX3\n"
	"eeVOoVI+lccju++fDaSQJFtZ8PVo8Yd8XDb/xu9ijRQNVom+1x70YvRo6jaSsX4k\n"
	"Y5gM1w3xTObKvo0YI/ot29DE0gE5xPYuiJOzooTNMBSklsB4sXS3Ehwpp+zuUAHQ\n"
	"h9I3os365QeRyB1IaWbO/7WK/zKPFbc3cyQLg8iGGeecH26CJ7vRlxDkvNvhscuh\n"
	"6Z3YK5DJdisRx5W3fW+JapAjsTXpYd/Aj4xMFoNXqvU3WaejB1TfQqxgBHw9Tapy\n"
	"PexWtASNmu1xcO13LdgN4Oa1OL4P4U9TQVwoCpkjlDSVNLqBC0N5kPmGkOY=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost_utf8_cert = {
	(unsigned char *)server_localhost_utf8_ca3_cert_pem,
	sizeof(server_localhost_utf8_ca3_cert_pem) - 1
};

/* shared the server_ca3 key, uses raw UTF8 on DnsName */
static char server_localhost_inv_utf8_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEQDCCAqigAwIBAgIMV9ZyrTt30lJ2pYe6MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwHhcNMDQwMjI5MTUyMTQyWhcNMjQwMjI5MTUyMTQxWjANMQsw\n"
	"CQYDVQQGEwJHUjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmq\n"
	"LPfAu7P4Hhmcm4KmEsRfuTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+S\n"
	"HFiIlEJfvCociQkrgSfloTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU0\n"
	"3LdpuR9TbvS2fMVjmaRjBiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4z\n"
	"ETxnMYOFbZpArkizpBi/RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyE\n"
	"VD1JsrlgccaizNUkiUi7Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWw\n"
	"wuDlnsmI0pIb9/4RH0LMMlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSb\n"
	"cCzHl25abi1xmbsV5ydomJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbh\n"
	"Gfo7V9z2gIKdUCLRXoUszhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQAB\n"
	"o4GdMIGaMAwGA1UdEwEB/wQCMAAwSgYDVR0RBEMwQYISd3d3Ls69zq/Ous6/z4Iu\n"
	"Y29tghvnroDkvZPkuK3mlocuzrXOvs+Ez4HOsS5jb22CDmxvY2FsaG9zdC11dGY4\n"
	"MB0GA1UdDgQWBBQzneEn04vV/OsF/LXHgWlPXjvZ1jAfBgNVHSMEGDAWgBT5qIYZ\n"
	"Y7akFBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAkUgmFO2bdws049Nz\n"
	"w55UaF7XxG8ER7kKzLCWgw8tuYjcIDKQ+/gD0hUuKBxCbuISdT32gfZTf+ZNKtEg\n"
	"7f9Lhr935ZoDCvyYnal1ploqAOu0ZDEXz+cU+OzreJ58J95LYX2we1lPqCYz0qo0\n"
	"6FeWrP6H6+azis2ee5XN+b20l/nRl3bNGZDnkl6+b3wPR6rIFaILcEZDl15SMgiW\n"
	"PlzJ0s97szWAO2ywLvNPdB66ugOvJY34ivTQOkCDi9css5faN1LcwmqDAeAq4DZt\n"
	"mZ8/504D1AUD9szneb2UgD9ZnPr4r45+qzE3lCtvmFGEddJ3c9zQVjnqEKljgG6S\n"
	"FdlAVVfxbwoAc24kN6UUEpLiabFoL071pZt1WoHOFA68yBxnC6CO/3vfVSF9Ftg3\n"
	"oUPldkvMs8+33YhojDKYXP5USoES2OPdofmq8LnTZj7c6ex+SvlRdOgHg4pd9lX2\n"
	"Efwe6rFJaNbKv9C9tWpPIPHRk/YkUIe29VUQR2m7UUpToBca\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost_inv_utf8_cert = {
	(unsigned char *)server_localhost_inv_utf8_ca3_cert_pem,
	sizeof(server_localhost_inv_utf8_ca3_cert_pem) - 1
};

/* server_ca3_ecc_key */
static char server_localhost_ca3_ecc_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC8zCCAVugAwIBAgIIV+OO5zqFDkowDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA5MjIwNzU3MjhaGA85OTk5MTIzMTIzNTk1OVowHTEbMBkG\n"
	"A1UEAxMSc2VydmVyIGNlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
	"QgAEbUnlVnL48xM0lK6iDhHcqaFuYh6M5lmA823GQlwi5skgg7rySR0YrTimX9F6\n"
	"K9kDCJu/7zmWlPiyb/1EFWEtk6OBjTCBijAMBgNVHRMBAf8EAjAAMBQGA1UdEQQN\n"
	"MAuCCWxvY2FsaG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMD\n"
	"B4AAMB0GA1UdDgQWBBTaH7JGYwVXx31AqONpQsb3l20EqDAfBgNVHSMEGDAWgBT5\n"
	"qIYZY7akFBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEATWsYCToPsxxU\n"
	"f1zJv3+FKcIGI+8U7akTlnJEk3l9/Gkmkp0tsudtpZb+//rXIem9XVMKDYBEzRxQ\n"
	"du3YleqR0Yj13S7piDHPl52PHJGvSHtLg4ooU74ZQcPFxoRxxNahYPb2Mhn0XqKh\n"
	"Yc7JHkW53UVusanRmBCQIxI6tVuDO3rB/tQM4ygD9wDeT16xnDhfwemKaskHKM44\n"
	"SMJJ9pY2zK1MvX5AZePTikMQqvc3aVfoE8Lv+4SGE/GyzvzaDOSzlwzNM6KBxerw\n"
	"1qwnVO/lphUG09X4oXXtOqlAHaIfUmRMqgMPZEtWMszIQo9XimPfoLW3xKVqDWjN\n"
	"EhHRLE0CCA/ip3lQ1bUt5EXhC1efPiOdEEYS5mHW7WAMAVi5aS1TzNLoJ4nahBwu\n"
	"EeGtmSH4rDZlHTNsiXwvxV3XqWc39TqlgY+NGToyU1tA4+tVtalJ08Q37sFxSUvJ\n"
	"Li9LPzU70EyX6WF+9FM45E4/Gt9Oh8btrYyjbyH/K2VI8qPRz5cW\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost_ecc_cert = {
	(unsigned char *)server_localhost_ca3_ecc_cert_pem,
	sizeof(server_localhost_ca3_ecc_cert_pem) - 1
};

/* shares server_ca3 key */
static char server_localhost_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEKDCCApCgAwIBAgIMV6MdMjbIDKHKsL32MA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1MTE4WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MAAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4Z\n"
	"nJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wq\n"
	"HIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270\n"
	"tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2a\n"
	"QK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHG\n"
	"oszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKS\n"
	"G/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4t\n"
	"cZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCC\n"
	"nVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaOBjTCBijAM\n"
	"BgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDATBgNVHSUEDDAKBggr\n"
	"BgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBQzneEn04vV/OsF/LXH\n"
	"gWlPXjvZ1jAfBgNVHSMEGDAWgBQtMwQbJ3+UBHzH4zVP6SWklOG3oTANBgkqhkiG\n"
	"9w0BAQsFAAOCAYEASbEdRkK44GUb0Y+80JdYGFV1YuHUAq4QYSwCdrT0hwJrFYI2\n"
	"s8+9/ncyzeyY00ryg6tPlKyE5B7ss29l8zcj0WJYsUk5kjV6uCWuo9/rqqPHK6Lc\n"
	"Qx1cONR4Vt+gD5TX0nRNuKaHVbBJARZ3YOl2F3nApcR/8boq+WNKGhGkzFMaKV+i\n"
	"IDpB0ziBUcb+q257lQGKrBuXl5nCd+PZswB//pZCsIkTF5jFdjeXvOvGDjYAr8rG\n"
	"KpoMTskNcBqgi59sJc8djWMbNt+15qH4mSvTUW1caukeJAr4mwHfrSK5k9ezSSp1\n"
	"EpbQ2Rp3xpbCgklhtsKHSJZ43sghZvCOxk8G3bRZ1/lW6sXvIPmLkvoeetTLvqYq\n"
	"t/+gfv4NJuyZhzuJHbxrxBJ3C9QjqTbpiUumeRQHXLa+vZJUKX7ak1KVubKiOC+x\n"
	"wyfgmq6quk5jPgOgMJWLwpA2Rm30wqX4OehXov3stSXFb+qASNOHlEtQdgKzIEX/\n"
	"6TXY44pCGHMFO6Kr\n"
	"-----END CERTIFICATE-----\n";

/* shares server_ca3 key with tlsfeature=5 */
static char server_ca3_tlsfeat_cert_pem[] =
	"-----BEGIN CERTIFICATE-----"
	"MIIEOjCCAqKgAwIBAgIUYBRfAcvgBUU4jCb8W89sQcPLqswwDQYJKoZIhvcNAQEL"
	"BQAwDzENMAsGA1UEAxMEQ0EtMzAgFw0xOTA2MDcyMTA4NDFaGA85OTk5MTIzMTIz"
	"NTk1OVowIjEgMB4GA1UEAxMXR251VExTIHRlc3QgY2VydGlmaWNhdGUwggGiMA0G"
	"CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4ZnJuCphLEX7k1"
	"5NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wqHIkJK4En5aEz"
	"SDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270tnzFY5mkYwYg"
	"juN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2aQK5Is6QYv0WE"
	"LS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHGoszVJIlIuxm5"
	"v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKSG/f+ER9CzDJX"
	"HgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4tcZm7FecnaJiT"
	"XD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCCnVAi0V6FLM4X"
	"aG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaN5MHcwEQYIKwYBBQUHARgE"
	"BTADAgEFMAwGA1UdEwEB/wQCMAAwFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0GA1Ud"
	"DgQWBBQzneEn04vV/OsF/LXHgWlPXjvZ1jAfBgNVHSMEGDAWgBT5qIYZY7akFBNg"
	"dg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEASMVR+C1x3pBRSRaaIYbFTC0X"
	"VXc66iQWDfpTSokLIEN/UVZzLsQw5p1PntPqnRRudDnXS77rNQSZcc4NTFYrzSqW"
	"WwdhIXtl3igLg5HMxU80dsr3LfGkzJ1iDS1RR0EGSvFjOE9ZUK0IBdsUvINqpj+l"
	"6qxL36yfxamuELIxvgmecIMvLzbe7tUjRXneNvLGsLAJcq5QQmNMCWiyywtHbFa0"
	"zbpxKMJmHMk0SbgZHUuFaASlAqVez19rJdzqQcJiw/YrMbbj/b2me1duLQ64dqGL"
	"5gKTyDMhk5td53R5uPnr7F6+1u8zRzqA6mBvTfEk4wJ6YmvqdBfC47xT+Ksba6dX"
	"Ugz+So2iu0rQxaLEBTZJ/gTXJEUafxUN4wF1ZOnUyltoqLJymhQoceoSwjYobOal"
	"FUZEJgFNA7j8tR7J3MtFUaJqFosuPtxhF8/CCPukKV7bRokqh7zK+F21iaQOYvJn"
	"AfuOg2g0ZMurGyS/yg8mVsGjh4bho9zPOlhPtFNM"
	"-----END CERTIFICATE-----";

/* Marked as decrypt-only */
static char server_localhost_ca3_rsa_decrypt_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEITCCAomgAwIBAgIIWU+IEie6JrYwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA2MjUwOTUzMjNaGA85OTk5MTIzMTIzNTk1OVowADCCAaIw\n"
	"DQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmqLPfAu7P4Hhmcm4KmEsRf\n"
	"uTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+SHFiIlEJfvCociQkrgSfl\n"
	"oTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU03LdpuR9TbvS2fMVjmaRj\n"
	"BiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4zETxnMYOFbZpArkizpBi/\n"
	"RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyEVD1JsrlgccaizNUkiUi7\n"
	"Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWwwuDlnsmI0pIb9/4RH0LM\n"
	"MlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSbcCzHl25abi1xmbsV5ydo\n"
	"mJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbhGfo7V9z2gIKdUCLRXoUs\n"
	"zhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQABo4GNMIGKMAwGA1UdEwEB\n"
	"/wQCMAAwFAYDVR0RBA0wC4IJbG9jYWxob3N0MBMGA1UdJQQMMAoGCCsGAQUFBwMB\n"
	"MA8GA1UdDwEB/wQFAwMHIAAwHQYDVR0OBBYEFDOd4SfTi9X86wX8tceBaU9eO9nW\n"
	"MB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUA\n"
	"A4IBgQAaq4+vai/FwYQ2fAjOsHsVV0nR5Zq55tT8Fexrj2/e9gr+bMV4HVxETByy\n"
	"fLtMHGYv+8BENDaI2EOHTyKp5O2DNbITJSN7/ZIO4Rsk+N5m2FyF7DV/sAoxhN7R\n"
	"mDy/jDtZyeIqKLptOQZbkRv3lf+vtJL3eakpgh5T/j14kT0QjLyJEZB1D9jurUsV\n"
	"+fxYxQUpv4YInDeEk5aKfvZNdkEpbv56GYNc15mNiKryXoszdm+TKmHSVFH9wUj3\n"
	"KAXBsQdMmZbd0ZFAEi7QV42Pr2x9+PrSE26bE6K31r02/RcxFQdL9E/3O+85S8eN\n"
	"yOZoC/PIrm0mKIPn2NBGSKtCG8V1sTHHJyCwqQERp3pkaB7A9biCKExQN1d3Gsbe\n"
	"C0R9bYimdbkYM6o7qi7OiLRKpYFgdVYaYEG3DRBpB3R3+EAKk91809tc9ow5xzkx\n"
	"lWryqIzutm6rcClAnqeBIZEZIIvqZH8RcPBQEUajNCWRpBsbwF1xdWvIhP2R3y69\n"
	"5dOfcuY=\n"
	"-----END CERTIFICATE-----\n";

/* Marked as sign-only */
static char server_localhost_ca3_rsa_sign_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEITCCAomgAwIBAgIIWU+LoyEYfBYwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNzA2MjUxMDA4MzZaGA85OTk5MTIzMTIzNTk1OVowADCCAaIw\n"
	"DQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmqLPfAu7P4Hhmcm4KmEsRf\n"
	"uTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+SHFiIlEJfvCociQkrgSfl\n"
	"oTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU03LdpuR9TbvS2fMVjmaRj\n"
	"BiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4zETxnMYOFbZpArkizpBi/\n"
	"RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyEVD1JsrlgccaizNUkiUi7\n"
	"Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWwwuDlnsmI0pIb9/4RH0LM\n"
	"MlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSbcCzHl25abi1xmbsV5ydo\n"
	"mJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbhGfo7V9z2gIKdUCLRXoUs\n"
	"zhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQABo4GNMIGKMAwGA1UdEwEB\n"
	"/wQCMAAwFAYDVR0RBA0wC4IJbG9jYWxob3N0MBMGA1UdJQQMMAoGCCsGAQUFBwMB\n"
	"MA8GA1UdDwEB/wQFAwMHgAAwHQYDVR0OBBYEFDOd4SfTi9X86wX8tceBaU9eO9nW\n"
	"MB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUA\n"
	"A4IBgQC1cJd/z1CQSyDfUd2uuNDTvA3WXWxNhqHMLitT1GJS6nUez+wCaWT9UfVy\n"
	"+56z/eMaVasZPQ8dOKYdPRuzL2l65DKUUaKFOyD+NGvOS08qKY+oVGN1Qbmaxbvt\n"
	"6rvzpW9UHn75zLDOUOMrGDkW5L36mMP8I0Y5AcNBrO5yFBvH8MAHr3zO2VvTSt6T\n"
	"ZHFrDlV/nL5E+swzrmF6MZXO1mupk/gtelYfRtigwSr51RY+Me3uaGNEQe30JLu6\n"
	"0gp6/otBns9qJjSgX9qWIj9iTHq4A2CiHZkb4j3+/TNNGB8dkBV+EvV8I4Bqdk33\n"
	"mz4hSjJBLqg2NYZ4TaztWFsgTvGOYncLGl5e4dIqB94ICEFIrWN32JzS61Mu5xlt\n"
	"qBh/JOUSdMe6csZrDIw//UhUgLj7KdFO5FhSW3DXEl9PZGWVR+LJ+T3HjomHf+Bb\n"
	"ATbBQk+9MkHTiDWxD4FbmPuSC/h4Vh+G1VkyrlClTLW6K/+0DmE2LPJvRV5udpux\n"
	"Ar7fYYU=\n"
	"-----END CERTIFICATE-----\n";

static char server_localhost_ca3_cert_chain_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEKDCCApCgAwIBAgIMV6MdMjbIDKHKsL32MA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
	"BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1MTE4WhgPOTk5OTEyMzEyMzU5NTla\n"
	"MAAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4Z\n"
	"nJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wq\n"
	"HIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270\n"
	"tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2a\n"
	"QK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHG\n"
	"oszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKS\n"
	"G/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4t\n"
	"cZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCC\n"
	"nVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaOBjTCBijAM\n"
	"BgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDATBgNVHSUEDDAKBggr\n"
	"BgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBQzneEn04vV/OsF/LXH\n"
	"gWlPXjvZ1jAfBgNVHSMEGDAWgBQtMwQbJ3+UBHzH4zVP6SWklOG3oTANBgkqhkiG\n"
	"9w0BAQsFAAOCAYEASbEdRkK44GUb0Y+80JdYGFV1YuHUAq4QYSwCdrT0hwJrFYI2\n"
	"s8+9/ncyzeyY00ryg6tPlKyE5B7ss29l8zcj0WJYsUk5kjV6uCWuo9/rqqPHK6Lc\n"
	"Qx1cONR4Vt+gD5TX0nRNuKaHVbBJARZ3YOl2F3nApcR/8boq+WNKGhGkzFMaKV+i\n"
	"IDpB0ziBUcb+q257lQGKrBuXl5nCd+PZswB//pZCsIkTF5jFdjeXvOvGDjYAr8rG\n"
	"KpoMTskNcBqgi59sJc8djWMbNt+15qH4mSvTUW1caukeJAr4mwHfrSK5k9ezSSp1\n"
	"EpbQ2Rp3xpbCgklhtsKHSJZ43sghZvCOxk8G3bRZ1/lW6sXvIPmLkvoeetTLvqYq\n"
	"t/+gfv4NJuyZhzuJHbxrxBJ3C9QjqTbpiUumeRQHXLa+vZJUKX7ak1KVubKiOC+x\n"
	"wyfgmq6quk5jPgOgMJWLwpA2Rm30wqX4OehXov3stSXFb+qASNOHlEtQdgKzIEX/\n"
	"6TXY44pCGHMFO6Kr\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
	"EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
	"NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
	"uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
	"kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
	"AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
	"JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
	"ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
	"ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
	"jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
	"A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
	"FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
	"PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
	"QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
	"R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
	"cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
	"+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
	"EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
	"haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
	"frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
	"-----END CERTIFICATE-----\n";

#define server_ca3_cert server_ca3_localhost_cert
#define server_ca3_cert_chain server_ca3_localhost_cert_chain
const gnutls_datum_t server_ca3_localhost_cert = {
	(unsigned char *)server_localhost_ca3_cert_pem,
	sizeof(server_localhost_ca3_cert_pem) - 1
};

const gnutls_datum_t server_ca3_localhost_rsa_decrypt_cert = {
	(unsigned char *)server_localhost_ca3_rsa_decrypt_cert_pem,
	sizeof(server_localhost_ca3_rsa_decrypt_cert_pem) - 1
};

const gnutls_datum_t server_ca3_localhost_rsa_sign_cert = {
	(unsigned char *)server_localhost_ca3_rsa_sign_cert_pem,
	sizeof(server_localhost_ca3_rsa_sign_cert_pem) - 1
};

const gnutls_datum_t server_ca3_tlsfeat_cert = {
	(unsigned char *)server_ca3_tlsfeat_cert_pem,
	sizeof(server_ca3_tlsfeat_cert_pem) - 1
};

const gnutls_datum_t server_ca3_localhost_cert_chain = {
	(unsigned char *)server_localhost_ca3_cert_chain_pem,
	sizeof(server_localhost_ca3_cert_chain_pem) - 1
};

/* shares server_ca3 key */
static char server_localhost_insecure_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDFzCCAX+gAwIBAgIIV90eOyTzpOcwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA5MTcxMDQzMDhaGA85OTk5MTIzMTIzNTk1OVowHjEcMBoG\n"
	"A1UEAxMTSW5zZWN1cmUgKDc2OCBiaXRzKTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgC\n"
	"YQCuxKP0RG8KHAp7HnqaFpcWnPVl72vmkLvBgC0h3gnVUO3a41//kkLOG0HGUOi6\n"
	"77cLNOzRRll9NPi1RwMNTKayA0cv+pJBsoNq/byOeWKJkKOgwTZD6Vi6X3MDtj7e\n"
	"3SECAwEAAaOBjTCBijAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9z\n"
	"dDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQW\n"
	"BBS4eSAgXUnLYP8HfA9SmoXjOAYLoDAfBgNVHSMEGDAWgBT5qIYZY7akFBNgdg8B\n"
	"mjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAFa7J4+vJ7V+4y+CaaATD/WATc9ZV\n"
	"ZUITpI6irjWneRPz0u0/3BLprKoCbO0m5QjoBaji1wUbVWpJir+N7QS577ufjwh0\n"
	"ViGFn1b3eU0wGPgz8n0B0vo6NifaQl1Df5PBN3Mfa+r0aUK3QYxnlHsXxanYaKzj\n"
	"9lpXUq57fpJJFSFASSzGSwkg8xiwlFBre/9jJ8sf1Blhu8M50NkOCdRdwpg/rbMI\n"
	"Oukh0pvJQYQfQsgxc/hySWfEtN0TThXLRFMRRcFFeRHK2LXyAo/sNzWJMIou7hBQ\n"
	"p1LNlCoUc3TGRKMQToEi+GIgjJx17zADze+1hHHE3aEEVGU9n3Gkj+hxy46LN5ke\n"
	"hDox4AzBf4+KaA/vdHGRvZjzhajaMdL6w8FJgmUc26L+kH/rsTuev+PrvqXuuy1W\n"
	"c2QqW3gu7oUy+g99TQFeXgyJHqv/cu/M0vhUV9wwHQJdj1bFCEaFW40MmQArXz5D\n"
	"F92lL9akoGYmyehqQHeRQsrVRKcCOiv8lgVF\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost_insecure_cert = {
	(unsigned char *)server_localhost_insecure_ca3_cert_pem,
	sizeof(server_localhost_insecure_ca3_cert_pem) - 1
};

static char server_ca3_localhost_insecure_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBywIBAAJhAK7Eo/REbwocCnseepoWlxac9WXva+aQu8GALSHeCdVQ7drjX/+S\n"
	"Qs4bQcZQ6Lrvtws07NFGWX00+LVHAw1MprIDRy/6kkGyg2r9vI55YomQo6DBNkPp\n"
	"WLpfcwO2Pt7dIQIDAQABAmBd9Md0Dcpoc/TKhfNBnb1yYcWoHJQ0q0DVYXRiDb3Z\n"
	"mZ2WHMFCY75YkdzFoj/MKAyrl+n6SJy5V2gwqEEW84pHH2AaAseWsF16rSRz958b\n"
	"7seVpNi304tOk4PS7B6+RAUCMQDXiT23wggUir6uVrx0UfHJUcsRltK0qco6Q7o3\n"
	"b+uwrIAbaNNg+aAqAXXU5XWdBpcCMQDPlBKn42C/XkAZ11zflbzjrq22ie0gaLKZ\n"
	"j92rCaU0/qX4VR8KK6J9PL6ZLoTWqQcCMQCzazhoLmoBh5nBkMxh3BD08FSluLJ/\n"
	"19NS+ywZl95P/NjLeFB1qnbsYLjQ1443f9MCMDE/w3FbzC97MCAxbZKKl0c5wXNG\n"
	"pCEFViKC9KfI4Q6CwGP75iJmmeW2zM3RMKkxbwIxAIAViD0cQjNL9keUVjtN68pK\n"
	"dD2lxHfq5Q1QxCSjl8EnBnjnbFJN9WmK9ztkK00Avg==\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_localhost_insecure_key = {
	(unsigned char *)server_ca3_localhost_insecure_key_pem,
	sizeof(server_ca3_localhost_insecure_key_pem) - 1
};

static char unknown_ca_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIID4DCCAkigAwIBAgIIVyG62RARjncwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UE\n"
	"AxMKVW5rbm93biBDQTAgFw0xNjA0MjgwNzI1MTNaGA85OTk5MTIzMTIzNTk1OVow\n"
	"FTETMBEGA1UEAxMKVW5rbm93biBDQTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC\n"
	"AYoCggGBALbdxniG+2wP/ONeZfvR7AJakVo5deFKIHVTiiBWwhg+HSjd4nfDa+vy\n"
	"Tt/wIdldP1PriD1Rigc8z68+RxPpGfAc197pKlKpO08I0L1RDKnjBWr4fGdCzE6u\n"
	"Z/ZsKVifoIZpdC8M2IYpAIMajEtnH53XZ1hTEviXTsneuiCTtap73OeSkL71SrIM\n"
	"kgBmAX17gfX3SxFjQUzOs6QMMOa3+8GW7RI+E/SyS1QkOO860dj9XYgOnTL20ibG\n"
	"cWF2XmTiQASI+KmHvYJCNJF/8pvmyJRyBHGZO830aBY0+DcS2bLKcyMiWfOJw7Wn\n"
	"paO7zSEC5WFgo4jdqroUBQdjQNCSSdrt1yYrAl1Sj2PMxYFX4H545Pr2sMpwC9An\n"
	"Pk9+uucT1Inj9615qbuXgFwhkgpK5pnPjzKaHp7ESlJj4/dIPTmhlt5BV+CLh7tS\n"
	"LzVLrddGU+os8JinT42radJ5V51Hn0C1CHIaFAuBCd5XRHXtrKb7WcnwCOxlcvux\n"
	"9h5/847F4wIDAQABozIwMDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT5qIYZ\n"
	"Y7akFBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAsCXvBLMc1YvZGBbM\n"
	"w2YalL7Gyw7t5TIbOhpIhsoWNrE8JNvwfU+xA0/hxA/UkbwwJOjntXFZ9eRIrjHU\n"
	"ULhqDZ1fAd7QnUQWuQjImU8XxnPjwgLG/tau9N3jdzJZy482vpytX94KdIQ+hPtC\n"
	"xA3fikG5F4cJCfu2RfaTskqikTO5XPzPdSNJiPk01jjh9ICc7cvS9smGxfTuZZOb\n"
	"+T1N8SV8uYkvPsiQ4uvO+ksxEdZ/z1jCjLyhnLXPgKdrjIgOb5wPxZUgwrg1n5fM\n"
	"Un72D43cnv5ykB2O9lXvPOLXlBz07ZwaiRsXDhh1/kmubOLERaw88bVUydYhE7SU\n"
	"eI34cw1eTtlKgFD+r+pPwRAzAkO/aCXVY6CsSLL4GyeXXvpxgngBiT8ArnntLHWd\n"
	"U1rpodAAdMBHDZf7Q8CXawI0EAIq0HpHCj3x2brKSf8eFMtl9FuaJ3KvM3ioXKYc\n"
	"nva6xGbu1R8UP4+fXCOFdiVixHEQR5k+mqd65vGGxovALAfY\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t unknown_ca_cert = { (unsigned char *)unknown_ca_cert_pem,
					 sizeof(unknown_ca_cert_pem) - 1 };

static const char server_ca3_pkcs12_pem[] =
	"-----BEGIN PKCS12-----\n"
	"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\n"
	"BAjXfJCHoHZI2QICCAA=\n"
	"-----END PKCS12-----\n";

const gnutls_datum_t server_ca3_pkcs12 = {
	(unsigned char *)server_ca3_pkcs12_pem,
	sizeof(server_ca3_pkcs12_pem) - 1
};

/* Raw public-key key material for testing */
static char rawpk_public_key_pem1[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyAeBq7Ti7oVExeVT1PqH\n"
	"GBXzC+johdeVnZgZRLhDTIaIGODV5F5JhE4NNb1O/DYLlAy5IIO8tfAE2KIxlarN\n"
	"H/+AcfV6ZJQSG4SSmhoIGzfdcdjuBmFfdfhO+z/cgqiewh53/fFCQlaJweHhpmim\n"
	"/LVL/M/1Rd6Urskv/5jXGG4FVUNfhXKQag0uzWsqcztCPX7Lrqr2BSOmkA1nWzdo\n"
	"h5oBuxdooaH9/kwphqJAp03LwtaSStX/yz6Mh+ZqEbBuM4mWw/xKzbEbs7zA+d8s\n"
	"ryHXkC8nsdA+h+IRd8bPa/KuWQNfjxXKNPzgmsZddHmHtYtWvAcoIMvtyO23Y2Nh\n"
	"N4V0/7fwFLbZtfUBg4pqUl2ktkdwsNguTT1qzJCsYhsHXaqqvHy+5HR2D0w07y2X\n"
	"1qCVmfHzBZCM5OhxoeoauE+xu+5nvYrgsgPE0y5Nty0y2MrApg3digaiKUXrI+mE\n"
	"VKn9vsQeaVvw9D6PgNQM99HkbGhRMGPOzcHjS/ZeLd1zAgMBAAE=\n"
	"-----END PUBLIC KEY-----";

const gnutls_datum_t rawpk_public_key1 = {
	(unsigned char *)rawpk_public_key_pem1,
	sizeof(rawpk_public_key_pem1) - 1
};

static char rawpk_private_key_pem1[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t rawpk_private_key1 = {
	(unsigned char *)rawpk_private_key_pem1,
	sizeof(rawpk_private_key_pem1) - 1
};

const char rawpk_public_key_pem2[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0tQAiQ13zWGZMV9YxFo2\n"
	"H15yERrkr8KD7z6QheVeatc2+5X0m5/+/o95nmnt6Mlwa27U78QwkHBccOaNkSi7\n"
	"HGMopaxatEsF/S30MDmhqOi9R2VtMwDaa2zWH/s2wPHn8efn2/zG0jeXCzNsXFs4\n"
	"zNApaZmTJCHaDRUE12adwP5i6GvUb978f27Cm0gnkSWBH9OdVnMunQkm/L16NI3E\n"
	"lvcDEEJbqhX2eswHenbhw//LiR1EKRtHEjWywAq5AeHeYNH+2zjff59SGD6Bn+W2\n"
	"vPKBhSWCyFDPGRfcYeCX2LFM7+Xx0j+GLzBnkjBhEgdsdLJ7Bt8aDToUJScLxeeP\n"
	"oOmL9e0bec20debwF0G/7QMlwRgDjV3sd3u+5RxRCeOh8Xqfbs/tij7tnU93orhc\n"
	"MzGjcn5XZ6WicyimuTruNznhKhNp6vmizCpwQAroimaZGV7F/8nvHInTZfpNH/+b\n"
	"++gYbddkH+MouxOXcAEUku6vN0JzDgA4qj4Tw7dffXSDAgMBAAE=\n"
	"-----END PUBLIC KEY-----\n";

const gnutls_datum_t rawpk_public_key2 = {
	(unsigned char *)rawpk_public_key_pem2,
	sizeof(rawpk_public_key_pem2) - 1
};

const char rawpk_private_key_pem2[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t rawpk_private_key2 = {
	(unsigned char *)rawpk_private_key_pem2,
	sizeof(rawpk_private_key_pem2) - 1
};

static char server_ca3_ml_dsa_44_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"bLhXCTNrwhbUjPWB\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_ml_dsa_44_key = {
	(unsigned char *)server_ca3_ml_dsa_44_key_pem,
	sizeof(server_ca3_ml_dsa_44_key_pem) - 1
};

static char server_ca3_ml_dsa_44_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"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\n"
	"AA4eLDk=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_ml_dsa_44_cert = {
	(unsigned char *)server_ca3_ml_dsa_44_cert_pem,
	sizeof(server_ca3_ml_dsa_44_cert_pem) - 1
};

static char server_ca3_ml_dsa_65_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"UvzW/CqkwyC8pW1s\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_ml_dsa_65_key = {
	(unsigned char *)server_ca3_ml_dsa_65_key_pem,
	sizeof(server_ca3_ml_dsa_65_key_pem) - 1
};

static char server_ca3_ml_dsa_65_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"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\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_ml_dsa_65_cert = {
	(unsigned char *)server_ca3_ml_dsa_65_cert_pem,
	sizeof(server_ca3_ml_dsa_65_cert_pem) - 1
};

static char server_ca3_ml_dsa_87_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"gSS9nZJSojUlwR/YkV5fh+YW3MWayASIzd+SWw==\n"
	"-----END PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_ml_dsa_87_key = {
	(unsigned char *)server_ca3_ml_dsa_87_key_pem,
	sizeof(server_ca3_ml_dsa_87_key_pem) - 1
};

static char server_ca3_ml_dsa_87_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"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\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_ml_dsa_87_cert = {
	(unsigned char *)server_ca3_ml_dsa_87_cert_pem,
	sizeof(server_ca3_ml_dsa_87_cert_pem) - 1
};

#endif /* GNUTLS_TESTS_CERT_COMMON_H */
