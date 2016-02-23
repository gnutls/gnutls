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
