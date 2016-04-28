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


static char ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDYDCCAcigAwIBAgIBADANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCIYDzIwMTQwNDA0MTk1OTA1WhgPOTk5OTEyMzEyMzU5NTlaMA8xDTALBgNVBAMT\n"
	"BENBLTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD46JAPKrTsNTHl\n"
	"zD06eIYBF/8Z+TR0wukp9Cdh8Sw77dODLjy/QrVKiDgDZZdyUc8Agsdr86i95O0p\n"
	"w19Np3a0wja0VC9uwppZrpuHsrWukwxIBXoViyBc20Y6Ce8j0scCbR10SP565qXC\n"
	"i8vr86S4xmQMRZMtwohP/GWQzt45jqkHPYHjdKzwo2b2XI7joDq0dvbr3MSONkGs\n"
	"z7A/1Bl3iH5keDTWjqpJRWqXE79IhGOhELy+gG4VLJDGHWCr2mq24b9Kirp+TTxl\n"
	"lUwJRbchqUqerlFdt1NgDoGaJyd73Sh0qcZzmEiOI2hGvBtG86tdQ6veC9dl05et\n"
	"pM+6RMABAgMBAAGjQzBBMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcE\n"
	"ADAdBgNVHQ4EFgQUGD0RYr2H7kfjQUcBMxSTCDQnhu0wDQYJKoZIhvcNAQELBQAD\n"
	"ggGBABHQqbXJVHxXAlfq0wOoy/11B4fhXJOxBQy1uvC8PSsZaGUJLH1P/8f+gyn0\n"
	"oweedIG+CBMvDTlGnnDrUPZbN8K5HqPpsST9jIDsqAiFKEdi9AuN4/zAjrQq2NjN\n"
	"ZtWIacIIRq2k7Qpk5nJn29HBKVabj/SJWuTNN8ume79IqanrMzmuou87QHr1vVOC\n"
	"wlSvQ6osHLFBF2QJ6tbT5ZSIy4VJyjyrMt0nOQ5Gl+fLUpcpcymI3MGbEh/WJONV\n"
	"CbvFIWdIuUb3T9EVFivMTeNJo6QxLI6vasnJJ0Jgs3yOtRZPVRx6F206EbzLiNfj\n"
	"ozEI0j1HdJy8niNwEW0tCzVi/CS5QC/nk1/qXCffxDcGihEBzM3pFxXKQ5YJpSe2\n"
	"GVoXfD0uDOccHcYaYbomGi2T63FJ4rG9eKPyYngjKD6aVJcOvldEeUwfYzNKbkFK\n"
	"fsI5r+CO25C2qpVomnv7xZBomenu7F8c6RFIjYSIYTGTsgGCe20K7YrLjVErkeLG\n"
	"1vDaOg==\n"
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
	"MIIEHzCCAoegAwIBAgIIVyG4kiR7VLIwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMDAgFw0xNjA0MjgwNzE1MzFaGA85OTk5MTIzMTIzNTk1OVowFjEUMBIG\n"
	"A1UEAxMLVGVzdCBjbGllbnQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQDhAB7O8se421OVNBKfW81pgGtnn4LNLz+0HYvkb7BbLdiqqqHWQH6BxY30W2q/\n"
	"bUHVaBFa2OufitMmDGX6iAuIuAshnqIb9h7U84UrHFVhjE9cjuykBhoJbr/5CNL/\n"
	"Xwzo0IAey+EkQyQ5jpyUioSoKktPJpbMlQsEHC2kDzimRwtOI2mZ8glaiz06xgfS\n"
	"FIrbET/mq74OSRoqt9LYLKnrXB2FRGtfV92WQFQG31cfxLkDZta5ARjzYaBfGXwe\n"
	"l6GQHZEuCmRlDPGinOGiobY/whkVCa07JLNE9a12nLRElu+Yt9mpoTCyreDWNkVe\n"
	"GpSNznLe9se1rZeDn/PHRf8UHr2PYpmyBSaSVhUUb217tS1JUODPdTr153XoBQvE\n"
	"2oAXYsaG4gQjn7g+KRdv5DFo7H+HDUG0SozMsxs2mEgtI8FEj42lNnY8JJ50axDP\n"
	"GyCez+JosHurUAisotRCVWnL4k19q5irO+Uw1fAxqg1BkN/2g6gWR1M/k/y3+AaT\n"
	"auUCAwEAAaN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjAP\n"
	"BgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBRdXorh31ji3Vx07Tm7u9jZMbKBajAf\n"
	"BgNVHSMEGDAWgBQYPRFivYfuR+NBRwEzFJMINCeG7TANBgkqhkiG9w0BAQsFAAOC\n"
	"AYEATOwassPHaWyIHVwSVfRjqivtgC5ZDZOllmPCl11j3ml2u4X2E5bsILXI/Tb3\n"
	"i2Kd1G/NXI+ITSzAot7jY2HC1Q8i8bjZFJaks7Dk+R4/Ozh0ZWw70hLFCcbnC/8/\n"
	"WCeOxQYKhoZIrN3I6Yl3Ls2+yRnUyOgF67rq5tj7a+FOO2RMjoP1WrtzHG0pQwzb\n"
	"yuF6LztHh7ZE7y2fBkWOvSiMgTyd0I4UjaS8WSbWIAj6N4CKFkSwUdc0DU6QqEbA\n"
	"gIU0JpnM3rMumSxDLa2BInW/8iY1YEl5MAGWzrb0RNEDxEkrAR1t+QVhBK2nzJkh\n"
	"4KUaKOqR1kD2ROSipndXz/lmlNteCBKwHSgmCJNJDXwDyyHGh4HA/FMb35f+1Yfa\n"
	"8EUwTIsYEartB+dWn7Wl1sSAbrbz1pCejxI4Z27r154Blho1G31e8XdJM+XJmV3C\n"
	"dc0NdLNVapvVCuCIaefQf3KFeeFXAZv62HSoKHNRaGVt6PnGOjEq3qdbQlceIyZF\n"
	"N6A1\n"
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

static char server_ca3_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEHzCCAoegAwIBAgIIVyG5MAKg0A4wDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
	"AxMEQ0EtMDAgFw0xNjA0MjgwNzE4MDhaGA85OTk5MTIzMTIzNTk1OVowFjEUMBIG\n"
	"A1UEAxMLVGVzdCBzZXJ2ZXIwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
	"gQDZPXiZqiz3wLuz+B4ZnJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUc\n"
	"DMVbL/wfkhxYiJRCX7wqHIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhf\n"
	"zyy8lDjFNNy3abkfU270tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1\n"
	"r3v7y4JuMxE8ZzGDhW2aQK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV\n"
	"2RByzRY8hFQ9SbK5YHHGoszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigB\n"
	"z8vEZZyFsMLg5Z7JiNKSG/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKl\n"
	"jc+t8m0Um3Asx5duWm4tcZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gI\n"
	"JT3CoKW24Rn6O1fc9oCCnVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJM\n"
	"rD0CAwEAAaN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDATAP\n"
	"BgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBQzneEn04vV/OsF/LXHgWlPXjvZ1jAf\n"
	"BgNVHSMEGDAWgBQYPRFivYfuR+NBRwEzFJMINCeG7TANBgkqhkiG9w0BAQsFAAOC\n"
	"AYEAFCY8NhmFgy7wWKlaU06i9CcP37BOM43c3F23wOuQ2cwxVLXCToYo92lwNMuW\n"
	"B+nN6TDgAahB7dh9Hpkz1swWDzcflm4Ckcd5EVP7mJZx07rWwl7InSsYZ5sUtVuZ\n"
	"Pkoum8bNaqfHZ6wnO3hyvp/68lhnwSc12c1ZjdFwDArbQY4jvwnAXNPWiV6XmHIe\n"
	"fUH8m9oacKHDGVY0PpZy+0ehO3KSzrBdv6zRSSiI+gdyRzjDI6vjbj3z+afddnWT\n"
	"asdnr8RLwpUaidB7MYAf3Ajnuacez/pZ9TVhNnMoN9DqHgY70kULC5sjK0joYj1d\n"
	"5YqmNJF4F5zcff3i0Jo4Dpmj0NTMAHz1HlftTjGrQf17CQdev4QxVQSoSaASf4XO\n"
	"nZHnn1YseYvmVV/FGLJ4/wgyl6Kqla+Dwy0+jB3GsVNL0CfdBQtPDoYYhffb238R\n"
	"AqnDX/ymatC2YqqY7sq4LXd37gh0Us/Wxr5wN3RETo6/qPN9HiBVN/1vYGvhTpUL\n"
	"PBwN\n"
	"-----END CERTIFICATE-----\n";

static char server_ca3_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_key = { (void*)server_ca3_key_pem,
	sizeof(server_ca3_key_pem)
};

const gnutls_datum_t server_ca3_cert = { (void*)server_ca3_cert_pem,
	sizeof(server_ca3_cert_pem)
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

const gnutls_datum_t unknown_ca_cert = { (void*)unknown_ca_cert_pem,
	sizeof(unknown_ca_cert_pem)
};
