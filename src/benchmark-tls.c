/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
/* DH of 1248 bits that is pretty close equivalent to 192 bits of ECDH.
 */
const char *pkcs3 =
  "-----BEGIN DH PARAMETERS-----\n"
  "MIIBQwKBnQDgLx3SqWyHOfGn/03r1tRwf3pByo3C4V1YIjjDQUoIzn82tRMPEKsL\n"
  "vos7WXjKgF1+S+T5Y9A7XqivGv1XJ1ZmDvewXVRByxjGRZbkoqCPw4Zv0Uyl9pjV\n"
  "WaR/Y/emZrN51K0zkdFJCzCt3lPlO3UprnYYHkySRpxTJ4ab5iXRFXETA5rJ5WH0\n"
  "itGpoR5xb2fR1Gmg5kXCNutkZ9cCgZwqJUZwqKIHJ9cYtzvZXFpjZNgF+mRWyiFr\n"
  "AQooJbFbVX3o2seJZl3mMqaetaLHF+L8anZFQipNgxenzQgEWEv8FubHXStaOnX1\n"
  "cwjwwxmCUK4lpfCQZtJ1K3os2JCcNaTBUyxAfiXFIYJmO/os0hFhR6a4EjIlkcq0\n"
  "yDDLN1weTNOpBPstp1WGHZCsKdJZzgfVvYL6er4zVBtBS0cCAgCg\n"
  "-----END DH PARAMETERS-----\n";

static unsigned char server_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICPjCCAYugAwIBAgIETuIMgTANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJC\n"
  "RTENMAsGA1UEChMEVGVzdDAeFw0xMTEyMDkxMzI2MjZaFw0yMDA1MDcxMzI2Mjha\n"
  "MBwxCzAJBgNVBAYTAkJFMQ0wCwYDVQQKEwRUZXN0MIG7MA0GCSqGSIb3DQEBAQUA\n"
  "A4GpADCBpQKBnQDTfzWWQ0miI6Gll+Vy4Cv/SSSCJssOZpQmKOHCUFzRO83/iSvb\n"
  "zJqZlyHB8YuPhM8sXv8MQqblbLZKhqbF5dyCbaZi5U3Emis6HS9epyjiifEPxPl2\n"
  "ph6dWCy9QjMkkcTCAANgiszc6Vz1M0gx7shaZXnjHpUByWwdRuVo9GLZRmfr916s\n"
  "8TnJdOihzNy+P9z9akUtepM7DQhyCgUCAwEAAaNVMFMwDAYDVR0TAQH/BAIwADAT\n"
  "BgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBTC\n"
  "8dyNXAOY/Uxa2V/QzsDserss6TANBgkqhkiG9w0BAQsFAAOBnQAfBWi5NIKO3/pY\n"
  "SrADjk5lCjysCheEfnb6hMU6ZVfauwm3ZCzkjYS8r936BC/fWss1oASxnUnznQvz\n"
  "TV/nJPz3LjXWHg+cmihM5WtEc0wANvpgnWme2AsO3zLecNRziEU4PU/9Al+I8v9S\n"
  "hCjm85krIhIb3tG6K08sUtPRV6lK47J+KudgCFwXaRMsG6w05Z2Lo3HCk02uenSz\n"
  "flQ=\n"
  "-----END CERTIFICATE-----\n";

static unsigned char server_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIC2gIBAAKBnQDTfzWWQ0miI6Gll+Vy4Cv/SSSCJssOZpQmKOHCUFzRO83/iSvb\n"
  "zJqZlyHB8YuPhM8sXv8MQqblbLZKhqbF5dyCbaZi5U3Emis6HS9epyjiifEPxPl2\n"
  "ph6dWCy9QjMkkcTCAANgiszc6Vz1M0gx7shaZXnjHpUByWwdRuVo9GLZRmfr916s\n"
  "8TnJdOihzNy+P9z9akUtepM7DQhyCgUCAwEAAQKBnQDDsmSCOpbKmY+8KtXbusPb\n"
  "PvGyIHUpSQ9yU8e5xiRsUpslBOb5RdQTpD1PONK7JNeSJgB3dsD5buMqCHgOi8fD\n"
  "Q/R+c9DGxySSbGjle2Nwhm0gSKgLWZDGTewu+NPiL/RsS5TZja7lNOO6Bbnb064Q\n"
  "iawYLjsDv1jgeBHMBgqD4nwoGMsgA2vy6kIBhyIgMDRlLxUA4K2zQa3gTy0CTwDX\n"
  "pEfrmNgPuFvrP5CGjG442H1MkLA/Wlb27S0ZYmbYKjxpjgKFJnGWxTCX5L4Ce4DL\n"
  "a6gJDDkyGW+md1HTtxBrM84TGnz/Zt/YY62YQ4MCTwD7FFghc0zsEwpocZlIzbor\n"
  "HHqpOq92kov3CF7kOS/uyn7LPcTgKk1qDW/mFkl584EseCNH3WZpnvAbtjPmGvMt\n"
  "p8Fva3qWeBzKLDkOndcCTjgsY0/MEPyHWep+NHfYPR4xxvIa/s6CCgVo40api4Dj\n"
  "/7i/dYiZ6x0LYQ0wWQ7sfTCAatVwibWzSpJior40AeLrK9NuIwGlGsqTrLTtYQJO\n"
  "CeJfJdH4MUL+oeX29trCfXf9jDP3PF/AitUVhz6JGIl4PGAOJBUGPyqQQSqXcemY\n"
  "KDwCh427vmS3Zx/hIynkcOOtxckhZlMMLxlWlbC5Ak4HC5VbKuw7nqMmDAnJ9kAO\n"
  "bJAUaXQAEw4BnUY/+8oZe/4KIgrWkwIS+cWtMzEQenQ/uJn08nhIEHMPsa/hYHTm\n"
  "jNKkrVgy360hqYj0lm4=\n"
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

    printf("\nTesting key exchanges:\n");
    test_ciphersuite_kx(PRIO_DH);
    test_ciphersuite_kx(PRIO_ECDH);
    test_ciphersuite_kx(PRIO_ECDHE_ECDSA);
    test_ciphersuite_kx(PRIO_RSA);

    gnutls_global_deinit();
    
}
