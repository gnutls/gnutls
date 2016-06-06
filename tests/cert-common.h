/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
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
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <gnutls/gnutls.h>


/* This file contains a lot of common parameters used by legacy and new
 * tests. The recommended to use for new tests are:
 *
 * CA: ca3_cert, ca3_key
 * TLS client: cli_ca3_cert, cli_ca3_key
 * IPv6 server: server_ca3_localhost6_cert, server_ca3_key
 * IPv4 server: server_ca3_localhost_cert, server_ca3_key
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

const gnutls_datum_t server_ecc_cert =
	{(void *) ecc_cert, sizeof(ecc_cert)};


const gnutls_datum_t server_ecc_key =
	{(void *) ecc_key, sizeof(ecc_key)};

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
    "dc8Siq5JojruiMizAf0pA7in\n" "-----END CERTIFICATE-----\n";

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

const gnutls_datum_t cert_dat =
	{(void *) pem1_cert, sizeof(pem1_cert)};


const gnutls_datum_t key_dat =
	{(void *) pem1_key, sizeof(pem1_key)};


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
	sizeof(server_cert_pem)
};

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
	sizeof(server_key_pem)
};

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

const gnutls_datum_t ca_cert = { ca_cert_pem,
	sizeof(ca_cert_pem)
};

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
	sizeof(server2_cert_pem)
};

static unsigned char server2_key_pem[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"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\n"
"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server2_key = { server2_key_pem,
	sizeof(server2_key_pem)
};

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

const gnutls_datum_t ca2_cert = { ca2_cert_pem,
	sizeof(ca2_cert_pem)
};

static unsigned char cert_pem[] =
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
const gnutls_datum_t cli_cert = { cert_pem, sizeof(cert_pem) - 1};

static unsigned char key_pem[] =
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
const gnutls_datum_t cli_key = { key_pem, sizeof(key_pem) - 1};

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
    "AoNBXjeBjgCGMei2m8E=\n" "-----END DSA PRIVATE KEY-----\n";

const gnutls_datum_t dsa_key = { (void*)dsa_key_pem,
	sizeof(dsa_key_pem)
};


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

const gnutls_datum_t ca3_key = { (void*)ca3_key_pem,
	sizeof(ca3_key_pem)
};

const gnutls_datum_t ca3_cert = { (void*)ca3_cert_pem,
	sizeof(ca3_cert_pem)
};

static char cli_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEPzCCAqegAwIBAgIIVzGiRh5+VCgwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA1MTAwODU2MzlaGA85OTk5MTIzMTIzNTk1OVowFjEUMBIG\n"
	"A1UEAxMLVGVzdCBjbGllbnQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQDhAB7O8se421OVNBKfW81pgGtnn4LNLz+0HYvkb7BbLdiqqqHWQH6BxY30W2q/\n"
	"bUHVaBFa2OufitMmDGX6iAuIuAshnqIb9h7U84UrHFVhjE9cjuykBhoJbr/5CNL/\n"
	"Xwzo0IAey+EkQyQ5jpyUioSoKktPJpbMlQsEHC2kDzimRwtOI2mZ8glaiz06xgfS\n"
	"FIrbET/mq74OSRoqt9LYLKnrXB2FRGtfV92WQFQG31cfxLkDZta5ARjzYaBfGXwe\n"
	"l6GQHZEuCmRlDPGinOGiobY/whkVCa07JLNE9a12nLRElu+Yt9mpoTCyreDWNkVe\n"
	"GpSNznLe9se1rZeDn/PHRf8UHr2PYpmyBSaSVhUUb217tS1JUODPdTr153XoBQvE\n"
	"2oAXYsaG4gQjn7g+KRdv5DFo7H+HDUG0SozMsxs2mEgtI8FEj42lNnY8JJ50axDP\n"
	"GyCez+JosHurUAisotRCVWnL4k19q5irO+Uw1fAxqg1BkN/2g6gWR1M/k/y3+AaT\n"
	"auUCAwEAAaOBlTCBkjAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMC\n"
	"MBwGA1UdEQQVMBOBEWhlbGxvQGV4YW1wbGUub3JnMA8GA1UdDwEB/wQFAwMHgAAw\n"
	"HQYDVR0OBBYEFF1eiuHfWOLdXHTtObu72NkxsoFqMB8GA1UdIwQYMBaAFPmohhlj\n"
	"tqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUAA4IBgQA/eaenR+0i8lTpzQlJ\n"
	"djl5CZfeY11oH3WH7rM6dDaBaZjz7VIG1ETBByMy/B+2hXOlBGGkbGwtKO01sAH8\n"
	"B91UOXvPkxIyofrhEBuGOQ3oN3eyAO48JxT9v6LSgzd82LPhtGErMbFkm/pFBjl4\n"
	"F0bBKdMEoPsV/hHnIswkLpefaZ9po5eOrihC3oYPoHhuizSfIn0kzmvyPElduBBN\n"
	"OcMPY26XF9tPSa3LKXA0UJo4mhpiVrWh9jbKLquaD+n/qKKV3mS++oytn4d2gdB6\n"
	"dcrQTNY74U7bUXutRqDNNlrAxIQ7Qh+stAiZ7CCm143GQBESRiqqKFpxdvVhpwDL\n"
	"H/buEo9I6ikYpwPAyIPfL9iMg13M/6NHg0s7C9psv0lInDCS2nFJG8L1Qp0Z6/Wt\n"
	"9yEjTuCSyfEdk/1Ar/jaAkKcdXRFptQuLtqFHYaBmXrWPqK4b6H0vKhvOUhXliZc\n"
	"0b7e0ldn20vEIdN3Qnoxf+7QVayrzKd7irovD8Xdg+R/E3s=\n"
	"-----END CERTIFICATE-----\n";

static char cli_ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t cli_ca3_key = { (void*)cli_ca3_key_pem,
	sizeof(cli_ca3_key_pem)
};

const gnutls_datum_t cli_ca3_cert = { (void*)cli_ca3_cert_pem,
	sizeof(cli_ca3_cert_pem)
};

static char server_ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIG5AIBAAKCAYEA2T14maos98C7s/geGZybgqYSxF+5NeTXKWpi9/vXmuIF8n3h\n"
	"Uh20mooT2rgVHAzFWy/8H5IcWIiUQl+8KhyJCSuBJ+WhM0gw2uqSPwiOZUm4l3TQ\n"
	"xmxS4eW/Brr4X88svJQ4xTTct2m5H1Nu9LZ8xWOZpGMGII7jf0YD6odG/DHE/sVH\n"
	"jfceD7kl15jAta97+8uCbjMRPGcxg4VtmkCuSLOkGL9FhC0uYVbwfBnT+V0MEycO\n"
	"Bx+Yv2BEu0xDVdkQcs0WPIRUPUmyuWBxxqLM1SSJSLsZub/DdiINXFure7dx57mW\n"
	"w2EQwhETIhIoAc/LxGWchbDC4OWeyYjSkhv3/hEfQswyVx4MQXLVfRBHNipkU9T/\n"
	"SXiP8WVDpfZSpY3PrfJtFJtwLMeXblpuLXGZuxXnJ2iYk1w/7RBuuKkylrQ7qCO/\n"
	"l/TIx3uZb39oCCU9wqCltuEZ+jtX3PaAgp1QItFehSzOF2hudF/TQuuukVRBZF4o\n"
	"fExwNYAvZvTSTKw9AgMBAAECggGAel8TMVRYMlOCKJWqtvit7QGJ7s6RMRewUCca\n"
	"iuB1ikyp1vgr1argEnGXT4yEb6GOBpjYKByRFRoSkfUFtJ8QXncAMS48CPwwcRDT\n"
	"wugZ9lp5ve9Sr4NTiOZ3Hd5yjN3SMIQ6GnR1pGfMnSXNidHGJRa+9IfHas2yvv38\n"
	"tL7xMJ0EgBM3BHRgnbDI7VKhs3afm63+0f64RdNHY/PkUpD+2/s9g6czDIq65qAn\n"
	"pXCTJJPSenN0hnS5AYzECtGh2JkFjXpF5B7/2pvZjqsy8eyjZURoQFLA5wWhLVr5\n"
	"AQDJzeK//D6OMAd6kuLKezQxVIN0F0eC6XKEhEvq96xegQk3aMXk2jCHz6IYV6pm\n"
	"zdnfIvP5fIP1HsL8JPiCQqBp7/MoSKlz/DCHH/6iQgQkIhxw/nYJd1+kjhHpm969\n"
	"fw6WzzCA7om0CbKhuHjRnnwk1OylqKhTrgfO1mcaEoH90NIszE3j5pwqiPMdv+J0\n"
	"k25pjaMDgeOd3bO8SW/oWQEH5LbBAoHBAP7QAaYg4Fsm0zr1Jvup6MsJdsI+2aTh\n"
	"4E+hrx/MKsd78mQpRNXvEVIeopp214rzqW/dv/4vMBoV9tRCuw5cJCZCHaeGZ4JF\n"
	"pU/+nBliukanL3XMN5Fp74vVthuQp69u3fa6YHHvL2L6EahSrHrbSE4+C5VYOV+Z\n"
	"nfKDHD9Vo1zH8Fjxl7JJWI/LgSXCChm6Y9Vq7LviL7hZc4BdCbGJfAfv56oGHavE\n"
	"zxU639fBbdhavNl6b9i7AeTD4Ad1KbsFrQKBwQDaQKP0eegbnHfHOdE+mb2aMtVN\n"
	"f3BI25VsBoNWD2A0VEFMQClUPMH17OyS2YidYeVbcneef3VlgrIJZvlRsr76LHxP\n"
	"vVtEug6ZgX5WS/DiJiZWESVJrGZ+gaeUIONGFObGO+Evvoe5bqSwm2Bu05HONb56\n"
	"Q5qx7gfo+kfxHm2vjOOKpc/ceEz2QeJ3rOGoetocmaObHcgFOFO0UC2oyAJ3MAtY\n"
	"8SkyiUJ/jDdCZbkVegT9kGe9OLKMpenG058uctECgcEAozqgM8mPrxR576SnakN3\n"
	"isjvOJOGXGcNiDVst5PUO6Gcrqj5HYpdsBtL0mMaxDo+ahjFKpET4UH8shBlP1er\n"
	"GI717CDfIcZ3lXzmhiSGa0gh0PYXCqGwAAXQ+Gt735fHvIu7yICN/Htw4EDFmJXs\n"
	"BaMdTHgNmL4RPg7bA39afM7fmjp5EI6HmuWkP4nDaqPJ3Cb4q4rDQvaaVLpEwWPu\n"
	"/i6iWno8e5JBjbn/NnkEYroNi8sw5sc0+VS4qE5XgySpAoHBAMB9bF0tu4nGqVl7\n"
	"49FrdO7v0HLGZ/jKOfIJmIIpk3bzrJecqxbRc1v79vbZhwUPl2LdBSU0Uw0RhQaH\n"
	"3HKyzH8HByio4DswQbofnJZt6ej7LqqP+qwMsmT24x7hFrHzs0m4/DXIvBnOvM/K\n"
	"afW1AY62leVthJ1TS4SuYQ8HAERpZTIeZcKUE4TJvPxB7NBUcdPxqXsgfA4mjKSm\n"
	"Zm7K4GnQZOGv6N7aclzeBMq5vtBzSr18RBJ+U/N6TUH/2Q/1UQKBwEPgS+LJCJAs\n"
	"qaeBPTgiuzv2a6umQpezxjCispnU5e0sOFHV/f5NVuEZDrdH7WDHAX8nAU8TdDZM\n"
	"/fqM4oOZJOY9yVsyXK9dN7YcG6lxlNbC8S4FatDorDr3DxmbeYqEMUfOR+H4VvgR\n"
	"OHw+G5gmNHBAh30wDR+bxepSNBAexjo18zbMgNJsdyjU8s562Q7/ejcTgqZYt4nZ\n"
	"r6wql68K+fJ1W38b+ENQ46bZZMvAh8z4MZyzBvS8M/grD0WBBwrWLA==\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_key = { (void*)server_ca3_key_pem,
	sizeof(server_ca3_key_pem)
};

/* shares server_ca3 key */
static char server_localhost6_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEMDCCApigAwIBAgIIVzGhKhP99McwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA1MTAwODUxNTVaGA85OTk5MTIzMTIzNTk1OVowADCCAaIw\n"
	"DQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANk9eJmqLPfAu7P4Hhmcm4KmEsRf\n"
	"uTXk1ylqYvf715riBfJ94VIdtJqKE9q4FRwMxVsv/B+SHFiIlEJfvCociQkrgSfl\n"
	"oTNIMNrqkj8IjmVJuJd00MZsUuHlvwa6+F/PLLyUOMU03LdpuR9TbvS2fMVjmaRj\n"
	"BiCO439GA+qHRvwxxP7FR433Hg+5JdeYwLWve/vLgm4zETxnMYOFbZpArkizpBi/\n"
	"RYQtLmFW8HwZ0/ldDBMnDgcfmL9gRLtMQ1XZEHLNFjyEVD1JsrlgccaizNUkiUi7\n"
	"Gbm/w3YiDVxbq3u3cee5lsNhEMIREyISKAHPy8RlnIWwwuDlnsmI0pIb9/4RH0LM\n"
	"MlceDEFy1X0QRzYqZFPU/0l4j/FlQ6X2UqWNz63ybRSbcCzHl25abi1xmbsV5ydo\n"
	"mJNcP+0QbripMpa0O6gjv5f0yMd7mW9/aAglPcKgpbbhGfo7V9z2gIKdUCLRXoUs\n"
	"zhdobnRf00LrrpFUQWReKHxMcDWAL2b00kysPQIDAQABo4GcMIGZMAwGA1UdEwEB\n"
	"/wQCMAAwIwYDVR0RBBwwGoIKbG9jYWxob3N0NoIMd3d3Lm5vbmUub3JnMBMGA1Ud\n"
	"JQQMMAoGCCsGAQUFBwMBMA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFDOd4SfT\n"
	"i9X86wX8tceBaU9eO9nWMB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv8bSv\n"
	"MA0GCSqGSIb3DQEBCwUAA4IBgQBeG1Mj+13pX+4qcbZIlcLqsrRjCFeF/3XpbL7f\n"
	"bUNaa+DYOOKy8d8/PHpS5uZHxwYOOK13+YOGr8hFBbXiGtl4uKbCmPd23kMfUzbI\n"
	"iTuu0DvuENtl6zjY44bjuXxhg9vBC3b2CygF8IWOHuXSVCgNMLzMDEA71uOzpgAT\n"
	"OQv+oDAURkWwMZWsGyb30YdoYb2QCqRLdMtVdoGkWq9CniE8rgHmrggSxkdCSOSY\n"
	"rPwjCCwCxXQqtZMvZYUws+vrXvPOvZHauQFhvuw6EHV62lQnY9JD8nqtimwuskWw\n"
	"hgcyhy4hgvmx7MRF1E+dc/lWSvNSHS6u8n4cTsHeHv2IOPl87y2jXR5lEoMItjZf\n"
	"D9B6K0w488yvj1+aheV0mbQDMgR0pzWOVH0oJ6RCM1AFgNU+7/d9ztqBusYJhuL7\n"
	"/MT4qYlyaZ3OzkIcD2kfmPLfX6FV5FCfVfNvKeCwvctisKsuJZ1/CIsjpoYJk7uu\n"
	"YeI3wIhmivXBor8p5hUzrWqT2y0=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost6_cert = { (void*)server_localhost6_ca3_cert_pem,
	sizeof(server_localhost6_ca3_cert_pem)-1
};


/* shares server_ca3 key */
static char server_localhost_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEITCCAomgAwIBAgIIVzGhBTuLU+swDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMzAgFw0xNjA1MTAwODUxMThaGA85OTk5MTIzMTIzNTk1OVowADCCAaIw\n"
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
	"MA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFDOd4SfTi9X86wX8tceBaU9eO9nW\n"
	"MB8GA1UdIwQYMBaAFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqGSIb3DQEBCwUA\n"
	"A4IBgQAAS3T2uhrGl99HErgOFyGLX6c/+moBjJDtMckBW8T3ajxOHzw7XI6I821a\n"
	"MPVXaXXHmnTUFhAHZrjpn5UYIwEJUaimtCviumHcK0h/yWnHdbxs+aglu66aJ5V0\n"
	"uvPdtLNBtS1y3SryTtskbZ3RPjHiON+brrVH0KcoT+t92T3CDtv0r37k92QKZlRK\n"
	"K/wnqTOBUEhvpSztFai5vPy8QWv/RSHb2vFZeJkdiXybcedmLLmp56rWbzzCvfzj\n"
	"mfOAFD0oGD8BTDTz55IrAfMvth7OYVqF0Se530c1GRxZwqYrEcfDJAc8QqfnYzkR\n"
	"6KRXCVCbJ5CKi3grTzqcAJYsy9sxE2afaa/hh/XnMwYtHgIE1xfrcDnnBuNyYWHZ\n"
	"GJaVdRTPtaRXUAJZtGLpy6SBEWGMP7wyhoFdbA3IWYbfypyM/t/LpQHtLzM3N7s8\n"
	"oXG/Pucnsyp8fJ3LEJW0STMsWBoPPdfJFdTxK5i+bcmKq3OFPIGfXgw1Jf5vGfgM\n"
	"MTK0U84=\n"
	"-----END CERTIFICATE-----\n";

#define server_ca3_cert server_ca3_localhost_cert
const gnutls_datum_t server_ca3_localhost_cert = { (void*)server_localhost_ca3_cert_pem,
	sizeof(server_localhost_ca3_cert_pem)-1};

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

const gnutls_datum_t unknown_ca_cert = { (void*)unknown_ca_cert_pem,
	sizeof(unknown_ca_cert_pem)
};

static const char server_ca3_pkcs12_pem[] =
	"-----BEGIN PKCS12-----\n"
	"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\n"
	"wVWVn1UTBAjIzPZeicMLMAICKAA=\n"
	"-----END PKCS12-----\n";

const gnutls_datum_t server_ca3_pkcs12 = { (void*)server_ca3_pkcs12_pem,
	sizeof(server_ca3_pkcs12_pem)-1
};
