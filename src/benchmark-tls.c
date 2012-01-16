/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define fail(...) \
	{ \
		fprintf(stderr, __VA_ARGS__); \
		exit(1); \
	}

#include "../tests/eagain-common.h"
#include "benchmark.h"

#define PRIO_DH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+DHE-RSA"
#define PRIO_ECDH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-RSA:+CURVE-SECP192R1"
#define PRIO_ECDHE_ECDSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-ECDSA:+CURVE-SECP192R1"
#define PRIO_RSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+RSA"

#define PRIO_AES_CBC_SHA1 "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_ARCFOUR_128_MD5 "NONE:+VERS-TLS1.0:+ARCFOUR-128:+MD5:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_AES_GCM "NONE:+VERS-TLS1.2:+AES-128-GCM:+AEAD:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_CAMELLIA_CBC_SHA1 "NONE:+VERS-TLS1.0:+CAMELLIA-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"

// #define PARAMS_1024 

#ifdef PARAMS_1024

static const int rsa_bits = 1024, ec_bits = 192;

const char *pkcs3 = 
  "-----BEGIN DH PARAMETERS-----\n"
  "MIIBCwKBgQCsIrA9BK23OUVIwrC4c65YJ2t8bqoGpJpuISjO07lAbWHWa47Kf9/t\n"
  "F9ckO2AF6Yj1Y7xS+FSCDeoIZsp0LCq3nAP9Ls25fgHrKSMPQBJt2vd5mUdm90Wr\n"
  "wCK2YjogQ7YVQlovVHsnJWC6Kf0P+OQ4hrihoBCGSj9sGK3wH57m+wKBgH5xlPNR\n"
  "pI8E2WBNqB6y4sV3eMGRvygScbbFUFFO1ccmNJl5Y5L/O+fP0ZXtmUJVsSvlY0fp\n"
  "Kcl6k5WCWMY8h6iHlJ9teHmC4s2jifXtaV759kJXdqrGEjRPEku50y3ANzDLzklW\n"
  "8R7HcSO397vIdouaUt38FbQESnIWOIZqDtq6AgIAnw==\n"
  "-----END DH PARAMETERS-----\n";

/* RSA key of 1024 bits */
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

#else

static const int rsa_bits = 1840, ec_bits = 192;

/* DH of 1840 bits that is pretty close equivalent to 192 bits of ECDH.
 */
const char *pkcs3 =
  "-----BEGIN DH PARAMETERS-----\n"
  "MIIB1gKB5kX/Dun+gVTZ1WXWxpS5efQUQY8XNGxi2V0IYHSqKMkrt8UGruv4Gqop\n"
  "vAoG/+llD/t84cIdUxNwHtLd5y/ae7lFOKFNhP+glvK/GsCfTcACRy9OFKphWi6E\n"
  "NDMyWV0miiZgIc/LrXgC4RcDMlmxRR3UW/+eVu1ti6PLMLYSooMwn60K6CWmgaM6\n"
  "VZaiD++gQtsgJdJv2+eNiVotodBPItJ5KcaPNVEdP1D8MzljO98UIOBR3YnalIAW\n"
  "oyTjWMcX5oxwIR4eSywPeUQokMFFAKxZfo6/IUv05sQ9semagqAilg52Q5CfAoHm\n"
  "RL1euKirrpaXqUtrV8r0l962oVFlLD92ReJOcjHFni8FY26qZ4IZba1lLP2Q4DTX\n"
  "ovR7HPMaa6Ss6EdR2hba8Q1LAiCCUFH5jiKjMU8bSM2Zi23GOdoHqYpHMbcSKkpX\n"
  "IQpbHHNap53/VxcPj4PK9SbQLt0KWe/253l8Ib5zivb6jKSOY/KzwoXO+MiPae01\n"
  "BdQhrMtsdntRWo5jChSBUidGP7orra3gPBOXhWdNeeTTshc0AZdSWP3NicokW/q7\n"
  "jHBuaadmhVv3yd6BvFkSePhVWcSKXXG27K9d3RNsXmaBasNYIhsCAgDf\n"
  "-----END DH PARAMETERS-----\n";

static unsigned char server_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC3TCCAeCgAwIBAgIETwIyNzANBgkqhkiG9w0BAQsFADAhMQswCQYDVQQGEwJH\n"
  "UjESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTEyMDEwMjIyMzk1MloXDTE3MDYwNjIy\n"
  "Mzk1NlowITELMAkGA1UEBhMCR1IxEjAQBgNVBAMTCWxvY2FsaG9zdDCCAQUwDQYJ\n"
  "KoZIhvcNAQEBBQADgfMAMIHvAoHnAMnMTaYe76aNxyhPDDZ1YWuj8SQh9PC7PRDD\n"
  "8qL+G8se+DwiJOL3fjRCXi2R1zt6gUrJmycmW+1xc9GdVST6oO09ZG6NQ8CRvU+K\n"
  "EcaDRQojUFM9QLmkDO1MyEZDMuXBpM+9TFkyDWgrsgYgcNU+Y9FN9Y45OT780+kl\n"
  "DjZItjl1jnD3tfWaYORQE//Xy4i2HrxTgikP26PB+3ynI+SDj7Sdt4oasgUo1Fpd\n"
  "OWDQ0hYQ6sn51mOYUnhYZax5y4lI6Cm4KOQc1NMn3iaX5+nS5YGcFhS/Usb8KsX1\n"
  "fHGsvePSyS/oxTMlAgMBAAGjVTBTMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI\n"
  "KwYBBQUHAwEwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUgQI1pnj7olEUcUu3\n"
  "SVCbJwYyuF4wDQYJKoZIhvcNAQELBQADgecAs2veVEtkSIlj2nEy1NI/lr0Wf51K\n"
  "0E2/oAeZJGoGo4wK5HUDfW2HlO+UVTkPei2Zk5Kjl/hpd9zG4BhTurL5mncPntXx\n"
  "Q6F3FMklBld4AYKeq5SSl+GG/PoEDzEJjazABCWgLa/U3EYjuwSXZj9RMibB6NQX\n"
  "bKCaj4cjRZSa1UmdLl2KTgRfG1ZDU4EBObagkdaOGD0XJ8EEZaBRktMtT8byxM8A\n"
  "m2pRMdwPvbxENmMhLXcIPQTaPaEYZyq9LA8Pee5wJosN66l8JVlsz2XEcH35DcG0\n"
  "bSUX8CSDmUPyHRyzVNeEcHc=\n"
  "-----END CERTIFICATE-----\n";

static unsigned char server_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEKQIBAAKB5wDJzE2mHu+mjccoTww2dWFro/EkIfTwuz0Qw/Ki/hvLHvg8IiTi\n"
  "9340Ql4tkdc7eoFKyZsnJlvtcXPRnVUk+qDtPWRujUPAkb1PihHGg0UKI1BTPUC5\n"
  "pAztTMhGQzLlwaTPvUxZMg1oK7IGIHDVPmPRTfWOOTk+/NPpJQ42SLY5dY5w97X1\n"
  "mmDkUBP/18uIth68U4IpD9ujwft8pyPkg4+0nbeKGrIFKNRaXTlg0NIWEOrJ+dZj\n"
  "mFJ4WGWsecuJSOgpuCjkHNTTJ94ml+fp0uWBnBYUv1LG/CrF9XxxrL3j0skv6MUz\n"
  "JQIDAQABAoHnALSPqarKY4STt2/JyxOvU8wMlOfPumrsHmex7JkK5bOJsnOb2YV8\n"
  "DeCUwc/kfsEpjCZu3fTZzcdXjFoyfMzptLSSChshK05TGSDiWaVWL6AymNziIdf5\n"
  "gdeSrGCyIAiUi/OVXYsxze03q8LvpAYqHQZayysto69IOe6P5Qt17xYPgsRIA6k9\n"
  "LAgBIjCN2ukgR/fWERGSn2jC/aBlO3jwmG80LsdPNaQ6+esQcwjwMjFajkf5A1XE\n"
  "OiYlIdmUS2liuWnUQK+D76WSUTrlwKKjxQiB0A9wugCN43BWHfV/Kf6ohIM1kIAB\n"
  "AnQA/g8rrF0cTe6ZsiZU0m7nyIQkmATENlLhu37DtcsdqTAwV3+UqzLIh46sHiRa\n"
  "D3SKlhhNs6iTqw/Wv02ZHy+//pxCmWWNAxhhwPCM6/OO6i5oEYU4uH+llEcu5Flh\n"
  "udFt7fMy/tzpwPsZRFpXaO1wScU2AQJ0AMtW7rsVrdqZqOdVGNI7vRsLC1SM26j4\n"
  "2bouNvKPuaLOsLBSlFopSpFRDgOxe+OOqk9Reg6RzO/q+496bEOqixofCE5Gfc/I\n"
  "pwlwwRGTP7sA0w6Y+Vo+qiATht/YaruscXL3AdQ3BulaqunAzsKN0Iz2ZSUCdACu\n"
  "bTX74fVj4BPvxvdnfrNt7KO/J06bSW4nr1GpB6n2ldoqyLIGlBgvUZoEG8slX0si\n"
  "387BMVUpFffHYfxl9/+mTBxBewJEhMHgmIb4HEEbsP7MQJ3/tcu1sOWV63P4Aryp\n"
  "qNZzOrLWRs9DKY9nv9TfISIBAnMFNzCeadrwvXpAnMUrN08Nb4YV4BsORXvIM8FD\n"
  "DX60d1q+2w9lFKQOACc83wOPfaxOpodb8k9wY/WZ44j9X1V8EQm0gEhf2QS30EWT\n"
  "ftRmponDWRckQnE4q2eNPE7Yi37JdR594/9wYtv5bPGgueR8iSFlAnQAjinshgPe\n"
  "kfAYhgSBbyJJvmCCp3jSra5JzoBnmMy2JyEJT+trCs9pmaP79GP/6BjPXHImnN0w\n"
  "PsTvmNPD3U2BqsGRuu6OGg9VRP/LDLpPGmV7j8nTraVJCkc4w/n/gazAbPydZZbz\n"
  "qRP/3et96JUHZnmn6g==\n"
  "-----END RSA PRIVATE KEY-----\n";
#endif

static unsigned char server_ecc_key_pem[] =
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MGACAQEEGQCovzs4UsfRncfJXO3WOZUe/Zf+usKzEcWgCgYIKoZIzj0DAQGhNAMy\n"
  "AAREwuCcUHKNWyetsymkAaqA0GCgksI2AjewpOWsraGrfea3GPw1uuyOQRMR7kka\n"
  "v6s=\n"
  "-----END EC PRIVATE KEY-----\n";

static unsigned char server_ecc_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBYDCCARWgAwIBAgIETuILrDAKBggqhkjOPQQDAjAcMQswCQYDVQQGEwJCRTEN\n"
  "MAsGA1UEChMEVGVzdDAeFw0xMTEyMDkxMzIyNTJaFw0xNzA4MTExMzIyNTlaMBwx\n"
  "CzAJBgNVBAYTAkJFMQ0wCwYDVQQKEwRUZXN0MEkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
  "AQEDMgAERMLgnFByjVsnrbMppAGqgNBgoJLCNgI3sKTlrK2hq33mtxj8NbrsjkET\n"
  "Ee5JGr+ro1UwUzAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8G\n"
  "A1UdDwEB/wQFAwMHgAAwHQYDVR0OBBYEFKeR27mtYWFaH43U2zEvjd28Zf+CMAoG\n"
  "CCqGSM49BAMCAzkAMDYCGQD7WWWiFV+ddI7tIyMFepKFA1dX4nlc/+ICGQCCPdHc\n"
  "gMyHv2XyfOGHLhq0HmDTOOiwfC4=\n"
  "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
  sizeof (server_cert_pem)
};

const gnutls_datum_t server_key = { server_key_pem,
  sizeof (server_key_pem)
};

const gnutls_datum_t server_ecc_cert = { server_ecc_cert_pem,
  sizeof (server_ecc_cert_pem)
};

const gnutls_datum_t server_ecc_key = { server_ecc_key_pem,
  sizeof (server_ecc_key_pem)
};

char buffer[64 * 1024];

static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}

static void test_ciphersuite(const char *cipher_prio, int size)
{
    /* Server stuff. */
    gnutls_anon_server_credentials_t s_anoncred;
    const gnutls_datum_t p3 = { (char *) pkcs3, strlen(pkcs3) };
    static gnutls_dh_params_t dh_params;
    gnutls_session_t server;
    int sret, cret;
    const char *str;
    /* Client stuff. */
    gnutls_anon_client_credentials_t c_anoncred;
    gnutls_session_t client;
    /* Need to enable anonymous KX specifically. */
    int ret;
    struct benchmark_st st;

    /* Init server */
    gnutls_anon_allocate_server_credentials(&s_anoncred);
    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_import_pkcs3(dh_params, &p3, GNUTLS_X509_FMT_PEM);
    gnutls_anon_set_server_dh_params(s_anoncred, dh_params);
    gnutls_init(&server, GNUTLS_SERVER);
    ret = gnutls_priority_set_direct(server, cipher_prio, &str);
    if (ret < 0) {
        fprintf(stderr, "Error in %s\n", str);
        exit(1);
    }
    gnutls_credentials_set(server, GNUTLS_CRD_ANON, s_anoncred);
    gnutls_dh_set_prime_bits(server, 1024);
    gnutls_transport_set_push_function(server, server_push);
    gnutls_transport_set_pull_function(server, server_pull);
    gnutls_transport_set_ptr(server, (gnutls_transport_ptr_t) server);
    reset_buffers();

    /* Init client */
    gnutls_anon_allocate_client_credentials(&c_anoncred);
    gnutls_init(&client, GNUTLS_CLIENT);

    ret = gnutls_priority_set_direct(client, cipher_prio, &str);
    if (ret < 0) {
        fprintf(stderr, "Error in %s\n", str);
        exit(1);
    }
    gnutls_credentials_set(client, GNUTLS_CRD_ANON, c_anoncred);
    gnutls_transport_set_push_function(client, client_push);
    gnutls_transport_set_pull_function(client, client_pull);
    gnutls_transport_set_ptr(client, (gnutls_transport_ptr_t) client);

    HANDSHAKE(client, server);

    fprintf(stdout, "Testing %s with %d packet size: ",
            gnutls_cipher_suite_get_name(gnutls_kx_get(server),
                                         gnutls_cipher_get(server),
                                         gnutls_mac_get(server)), size);
    fflush(stdout);

    gnutls_rnd(GNUTLS_RND_NONCE, buffer, sizeof(buffer));

    start_benchmark(&st);

    do {
        do {
            ret = gnutls_record_send(client, buffer, size);
        }
        while (ret == GNUTLS_E_AGAIN);

        if (ret < 0) {
            fprintf(stderr, "Failed sending to server\n");
            exit(1);
        }

        do {
            ret = gnutls_record_recv(server, buffer, sizeof(buffer));
        }
        while (ret == GNUTLS_E_AGAIN);

        if (ret < 0) {
            fprintf(stderr, "Failed receiving from client\n");
            exit(1);
        }

        st.size += size;
    }
    while (benchmark_must_finish == 0);

    stop_benchmark(&st, NULL);

    gnutls_bye(client, GNUTLS_SHUT_WR);
    gnutls_bye(server, GNUTLS_SHUT_WR);

    gnutls_deinit(client);
    gnutls_deinit(server);

    gnutls_anon_free_client_credentials(c_anoncred);
    gnutls_anon_free_server_credentials(s_anoncred);

    gnutls_dh_params_deinit(dh_params);

}

static void test_ciphersuite_kx(const char *cipher_prio)
{
    /* Server stuff. */
    gnutls_anon_server_credentials_t s_anoncred;
    const gnutls_datum_t p3 = { (char *) pkcs3, strlen(pkcs3) };
    static gnutls_dh_params_t dh_params;
    gnutls_session_t server;
    int sret, cret;
    const char *str;
    const char *suite = NULL;
    /* Client stuff. */
    gnutls_anon_client_credentials_t c_anoncred;
    gnutls_certificate_credentials_t c_certcred, s_certcred;
    gnutls_session_t client;
    /* Need to enable anonymous KX specifically. */
    int ret;
    struct benchmark_st st;

    /* Init server */
    gnutls_certificate_allocate_credentials(&s_certcred);
    gnutls_anon_allocate_server_credentials(&s_anoncred);
    gnutls_dh_params_init(&dh_params);
    if ((ret=gnutls_dh_params_import_pkcs3(dh_params, &p3, GNUTLS_X509_FMT_PEM)) < 0) {
      fprintf(stderr, "Error importing the PKCS #3 params: %s\n", gnutls_strerror(ret));
      exit(1);
    }
    gnutls_anon_set_server_dh_params(s_anoncred, dh_params);
    gnutls_certificate_set_dh_params(s_certcred, dh_params);

    gnutls_certificate_set_x509_key_mem (s_certcred, &server_cert, &server_key,
                                         GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_key_mem (s_certcred, &server_ecc_cert, &server_ecc_key,
                                         GNUTLS_X509_FMT_PEM);

    start_benchmark(&st);

    do {
        gnutls_init(&server, GNUTLS_SERVER);
        ret = gnutls_priority_set_direct(server, cipher_prio, &str);
        if (ret < 0) {
            fprintf(stderr, "Error in %s\n", str);
            exit(1);
        }
        gnutls_credentials_set(server, GNUTLS_CRD_ANON, s_anoncred);
        gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, s_certcred);
        gnutls_transport_set_push_function(server, server_push);
        gnutls_transport_set_pull_function(server, server_pull);
        gnutls_transport_set_ptr(server, (gnutls_transport_ptr_t) server);
        reset_buffers();

        /* Init client */
        gnutls_anon_allocate_client_credentials(&c_anoncred);
        gnutls_certificate_allocate_credentials(&c_certcred);

        gnutls_init(&client, GNUTLS_CLIENT);

        ret = gnutls_priority_set_direct(client, cipher_prio, &str);
        if (ret < 0) {
            fprintf(stderr, "Error in %s\n", str);
            exit(1);
        }
        gnutls_credentials_set(client, GNUTLS_CRD_ANON, c_anoncred);
        gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE, c_certcred);

        gnutls_transport_set_push_function(client, client_push);
        gnutls_transport_set_pull_function(client, client_pull);
        gnutls_transport_set_ptr(client, (gnutls_transport_ptr_t) client);

        HANDSHAKE(client, server);

        if (suite == NULL)
            suite = gnutls_cipher_suite_get_name(gnutls_kx_get(server),
                                                 gnutls_cipher_get(server),
                                                 gnutls_mac_get(server));

        gnutls_deinit(client);
        gnutls_deinit(server);

        st.size += 1;
    }
    while (benchmark_must_finish == 0);

    fprintf(stdout, "Tested %s: ", suite);
    stop_benchmark(&st, "transactions");

    gnutls_anon_free_client_credentials(c_anoncred);
    gnutls_anon_free_server_credentials(s_anoncred);

    gnutls_dh_params_deinit(dh_params);

}

void benchmark_tls(int debug_level)
{
    gnutls_global_set_log_function(tls_log_func);
    gnutls_global_set_log_level(debug_level);
    gnutls_global_init();

    printf("Testing throughput in cipher/MAC combinations:\n");

    test_ciphersuite(PRIO_ARCFOUR_128_MD5, 1024);
    test_ciphersuite(PRIO_ARCFOUR_128_MD5, 4096);
    test_ciphersuite(PRIO_ARCFOUR_128_MD5, 8 * 1024);
    test_ciphersuite(PRIO_ARCFOUR_128_MD5, 15 * 1024);

    test_ciphersuite(PRIO_AES_GCM, 1024);
    test_ciphersuite(PRIO_AES_GCM, 4096);
    test_ciphersuite(PRIO_AES_GCM, 8 * 1024);
    test_ciphersuite(PRIO_AES_GCM, 15 * 1024);

    test_ciphersuite(PRIO_AES_CBC_SHA1, 1024);
    test_ciphersuite(PRIO_AES_CBC_SHA1, 4096);
    test_ciphersuite(PRIO_AES_CBC_SHA1, 8 * 1024);
    test_ciphersuite(PRIO_AES_CBC_SHA1, 15 * 1024);

    test_ciphersuite(PRIO_CAMELLIA_CBC_SHA1, 1024);
    test_ciphersuite(PRIO_CAMELLIA_CBC_SHA1, 4096);
    test_ciphersuite(PRIO_CAMELLIA_CBC_SHA1, 8 * 1024);
    test_ciphersuite(PRIO_CAMELLIA_CBC_SHA1, 15 * 1024);

    printf("\nTesting key exchanges (RSA/DH bits: %d, EC bits: %d):\n", rsa_bits, ec_bits);
    test_ciphersuite_kx(PRIO_DH);
    test_ciphersuite_kx(PRIO_ECDH);
    test_ciphersuite_kx(PRIO_ECDHE_ECDSA);
    test_ciphersuite_kx(PRIO_RSA);

    gnutls_global_deinit();
    
}
