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
#include <math.h>

#define fail(...) \
	{ \
		fprintf(stderr, __VA_ARGS__); \
		exit(1); \
	}

#include "../tests/eagain-common.h"
#include "benchmark.h"

const char* side = "";

#define PRIO_DH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+DHE-RSA"
#define PRIO_ECDH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-RSA:+CURVE-SECP192R1"
#define PRIO_ECDHE_ECDSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-ECDSA:+CURVE-SECP192R1"
#define PRIO_RSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+RSA"

#define PRIO_AES_CBC_SHA1 "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_ARCFOUR_128_MD5 "NONE:+VERS-TLS1.0:+ARCFOUR-128:+MD5:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_AES_GCM "NONE:+VERS-TLS1.2:+AES-128-GCM:+AEAD:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_CAMELLIA_CBC_SHA1 "NONE:+VERS-TLS1.0:+CAMELLIA-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"

static const int rsa_bits = 1776, ec_bits = 192;

/* DH of 1840 bits that is pretty close equivalent to 192 bits of ECDH.
 */
const char *pkcs3 =
"-----BEGIN DH PARAMETERS-----\n"
"MIIBxgKB3gNZMD2odqYk7HGnT+kh72vcnGrDhFMad1m4VlYZoLClkRUOH05W9gKF\n"
"hjBzlg5zO1Pp14hpSNWdfXcd2glWE2wzkxxxztzt23gdXK1GjfupnALyPS2Q0Oj7\n"
"UiLDfos46vXOSzqO3vBElM2HJQ6N1TRU+EqD5t/6aTAV6iAD+yz2Fyv4Xs+rgJC2\n"
"IbpunLzM2IhH2u9tLUXGkBzHPW/6Q+fJRhn88OLBC9vwOHPQvw779+FB0NPue1Qs\n"
"vb+4HSywpOr4BtNLWST2MzhCYBApvV1dKcZLI5k5Cfmp5ryV+wKB3gEUe9uAk+5I\n"
"ENkTLC7XLLNGjPEKwQhBzE7Nh7RKWlZRX+B/cX5/iT7ZF9+N83O/wf2AxEV6CRWV\n"
"WiCjvML/wbskpGoGmrPyef7bLHI62x4/nNacGGWEichPW8Sn/qaT80FHyYM0m7Ha\n"
"+Q9kYUSx0u1CW//3nGvma5dh/c2iiq8r7J9w2PSYynHts4bYMrRRx2PVeGhvU8+X\n"
"nRkYOqptEqoB6NG5kPRL8b5jJSp7J2hN7shDjQB/s9/N8rvF8tRmMUTJpk3Fwr9F\n"
"LVdX3640cbukwFTKlkqZ1evymVzx0wICAL0=\n"
"-----END DH PARAMETERS-----\n";

static unsigned char server_cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIEEzCCAx6gAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBuDELMAkGA1UEBhMCR1Ix\n"
"EjAQBgNVBAoTCUtva28gaW5jLjEXMBUGA1UECxMOc2xlZXBpbmcgZGVwdC4xDzAN\n"
"BgNVBAgTBkF0dGlraTEVMBMGA1UEAxMMQ2luZHkgTGF1cGVyMRcwFQYKCZImiZPy\n"
"LGQBARMHY2xhdXBlcjEMMAoGA1UEDBMDRHIuMQ8wDQYDVQRBEwZqYWNrYWwxHDAa\n"
"BgkqhkiG9w0BCQEWDW5vbmVAbm9uZS5vcmcwIhgPMjAxMjA2MDYxOTAxMjdaGA8y\n"
"MDE5MDcxMDE5MDEyN1owgbgxCzAJBgNVBAYTAkdSMRIwEAYDVQQKEwlLb2tvIGlu\n"
"Yy4xFzAVBgNVBAsTDnNsZWVwaW5nIGRlcHQuMQ8wDQYDVQQIEwZBdHRpa2kxFTAT\n"
"BgNVBAMTDENpbmR5IExhdXBlcjEXMBUGCgmSJomT8ixkAQETB2NsYXVwZXIxDDAK\n"
"BgNVBAwTA0RyLjEPMA0GA1UEQRMGamFja2FsMRwwGgYJKoZIhvcNAQkBFg1ub25l\n"
"QG5vbmUub3JnMIH9MA0GCSqGSIb3DQEBAQUAA4HrADCB5wKB3wC/VSBHG5adM0r0\n"
"E80dgVvt+oVnnDcKYcm9q2WbknTL6dFgjjcEbiHDKmnr1hgyT9jfQVE/ve2XnZqA\n"
"kbpYMNrQbdieclNycjoXCj3BJSJXXz3Ra6O4DLNh0/XwsxbVd/tMSQvwAK0MR60K\n"
"/yfruL2oxe8j7uDmS5oY8b5O9nP/EVW2u7P1KVhrNxC2rGoaK6iRpgkAX3oP2YVM\n"
"hLfPONpDgYGxBvrO0tlpHCYL+miWdRzIDPMYtdcU1v1zVSKAsvJ2dgEwP6FoSiWP\n"
"nkw3U41i4oe+T7kVEk1F9QLCnXsCAwEAAaNrMGkwDAYDVR0TAQH/BAIwADAUBgNV\n"
"HREEDTALgglsb2NhbGhvc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0PAQH/\n"
"BAUDAwegADAdBgNVHQ4EFgQUMwvofEmn5CtM4GygipfIuebOssgwDQYJKoZIhvcN\n"
"AQELBQADgd8AdP87xzJGv3ddODGoCaVNipkO96HDwt1fC4Jtp1VTn1V4JRaL4e4D\n"
"0dlFMq30kmrLTxNSET7MJ5l2m0XZS7jhbl5UW9jLCv1GurMaVuYK4v0LGGezODoH\n"
"8naZkxWYGS16kssPu0SDE0V9gWF31IXs2qs0PHvvpI5WFmjrOPX3RfFeVNhmc5sv\n"
"1cy+hnM9wxcT2r+jpKn3mYVVcnG7ANZyLKzLwN/PGkYB+tv8sS0ojxMKZLQjr9xs\n"
"z1plHeDzm0/t7gsAkrL8ynSkBBJ1SLqaKMmlP1DmgU/zTlMTyKrG\n"
"-----END CERTIFICATE-----\n";

static unsigned char server_key_pem[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEBAIBAAKB3wC/VSBHG5adM0r0E80dgVvt+oVnnDcKYcm9q2WbknTL6dFgjjcE\n"
"biHDKmnr1hgyT9jfQVE/ve2XnZqAkbpYMNrQbdieclNycjoXCj3BJSJXXz3Ra6O4\n"
"DLNh0/XwsxbVd/tMSQvwAK0MR60K/yfruL2oxe8j7uDmS5oY8b5O9nP/EVW2u7P1\n"
"KVhrNxC2rGoaK6iRpgkAX3oP2YVMhLfPONpDgYGxBvrO0tlpHCYL+miWdRzIDPMY\n"
"tdcU1v1zVSKAsvJ2dgEwP6FoSiWPnkw3U41i4oe+T7kVEk1F9QLCnXsCAwEAAQKB\n"
"3iYR2gpMAvvkaNWH2xgz1QbVAhZLjugR7QJASEdcLMEmFPMRWQEYqL8cgVbbkpTw\n"
"Lka9yFzWfZ/dTBCo7lr93Yv7T063kMME12oeL4tuyBZ6bOJueHT2kfq1Igpyl+iB\n"
"pw7WuflXKRd4a4X0nwzYBQxYWH7bKkQRZDlViKuOXKVzgT7GqD6cbTZbc/8wUTi7\n"
"HoyMlz4d+YH/XL5Zt6SM7cMuJ/VOGGUcBiXqlixzulloihkPwJeg6zxx0e1dVy4q\n"
"jvVhb+hmypWajjBDPUwIGFih0lZJ6rqIDyls/ZK2AQJwAPFeAMubo1KWcFU+nHoK\n"
"Q/jdOjpuAt7fwczkqhb6uOrJtS4RUtF3x3jfESFYf6Btnt6Slj1HpNKHbud2Weyw\n"
"i3lIkkmQq4+8uRjZXlNtp2Sd33NFeYE1D8ll3V2wiwiCOPJxYWpOOwHs7pkcOsAD\n"
"ywJwAMruluGFAUhoCxXOGzbJeXOC0U+LbwU72Xgk9zhEX6chaklKgdSnJ8DlHnYe\n"
"R+wc2vXRfSGlT1OH0X8ezn82QV8UmYo6cNpMTNarW0rzpFir51owvYSBPnPB+DLX\n"
"0JausRZoI6fyZSw4Vxt9PN13EQJwANnEX2FUfcmQs68le1ZclrEdIGEBSpO9PARZ\n"
"tuBeu6IR9OaoeJlGwXDbiYAVcajT3oefp++ICTxtNvGchUuYiW4WvO2kmjVoJ3Q1\n"
"Afaxs1qDWcyNvS+HKUQjJNNX6kj1/N040JRyGqkFFMyNfLArewJwAL/KfLkJjmvT\n"
"QV7LW3cNNYbRRWdLXZLxvJfLQAdiv5BiiWRZUZkcnfq10HNMLSdfIiYfZocNCIrm\n"
"mz3sbLdYHLJy8qXsk8oNQLXGX9LXsCTJ2y6nUAZSbCbVVPEgfRhcZCvMIp7Q/YOs\n"
"f88QLx0UMQJvYsEnYagLe9EfC0d8fXTKJr143FMxas7j3eftxLEBnx7ZsqCbJD1o\n"
"UsvWkp5I3kqIABEqY1ZJV/gU41MceuWURSVADpuuRDLzv8WPdeffad9o2hX/bkI6\n"
"2INKeuq1nILiEHAZLloH6/fdjpWZYF0D\n"
"-----END RSA PRIVATE KEY-----\n";

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
    fprintf(stderr, "%s|<%d>| %s", side, level, str);
}

static void test_ciphersuite(const char *cipher_prio, int size)
{
    /* Server stuff. */
    gnutls_anon_server_credentials_t s_anoncred;
    const gnutls_datum_t p3 = { (void*) pkcs3, strlen(pkcs3) };
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

    fprintf(stdout, "Testing %s with %d packet size...\n",
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
    fprintf(stdout, "\n");

    gnutls_bye(client, GNUTLS_SHUT_WR);
    gnutls_bye(server, GNUTLS_SHUT_WR);

    gnutls_deinit(client);
    gnutls_deinit(server);

    gnutls_anon_free_client_credentials(c_anoncred);
    gnutls_anon_free_server_credentials(s_anoncred);

    gnutls_dh_params_deinit(dh_params);

}

static
double calc_avg(unsigned int *diffs, unsigned int diffs_size)
{
double avg = 0;
unsigned int i;

  for(i=0;i<diffs_size;i++)
    avg += diffs[i];
    
  avg /= diffs_size;

  return avg;
}

static
double calc_sstdev(unsigned int *diffs, unsigned int diffs_size, double avg)
{
double sum = 0, d;
unsigned int i;

  for (i=0;i<diffs_size;i++) {
    d = ((double)diffs[i] - avg);
    d *= d;
    
    sum += d;
  }
  sum /= diffs_size - 1;
  
  return sum;
}


unsigned int diffs[32*1024];
unsigned int diffs_size = 0;

static void test_ciphersuite_kx(const char *cipher_prio)
{
    /* Server stuff. */
    gnutls_anon_server_credentials_t s_anoncred;
    const gnutls_datum_t p3 = { (void*) pkcs3, strlen(pkcs3) };
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
    struct timespec tr_start, tr_stop;
    double avg, sstddev;

    diffs_size = 0;

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

    /* Init client */
    gnutls_anon_allocate_client_credentials(&c_anoncred);
    gnutls_certificate_allocate_credentials(&c_certcred);

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

        gettime(&tr_start);

        HANDSHAKE(client, server);

        gettime(&tr_stop);

        if (suite == NULL)
            suite = gnutls_cipher_suite_get_name(gnutls_kx_get(server),
                                                 gnutls_cipher_get(server),
                                                 gnutls_mac_get(server));

        gnutls_deinit(client);
        gnutls_deinit(server);

        diffs[diffs_size++] = timespec_sub_ms(&tr_stop, &tr_start);
        if (diffs_size > sizeof(diffs))
          abort();

        st.size += 1;
    }
    while (benchmark_must_finish == 0);

    fprintf(stdout, "Benchmarked %s.\n", suite);
    stop_benchmark(&st, "transactions");

    avg = calc_avg(diffs, diffs_size);
    sstddev = calc_sstdev(diffs, diffs_size, avg);

    printf("  Average handshake time: %.2f ms, sample variance: %.2f\n\n", avg, sstddev);

    gnutls_anon_free_client_credentials(c_anoncred);
    gnutls_anon_free_server_credentials(s_anoncred);

    gnutls_dh_params_deinit(dh_params);

}

void benchmark_tls(int debug_level, int ciphers)
{
    gnutls_global_set_log_function(tls_log_func);
    gnutls_global_set_log_level(debug_level);
    gnutls_global_init();

    if (ciphers != 0)
      {
        printf("Testing throughput in cipher/MAC combinations:\n\n");

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
      }
    else
      {
        printf("\nTesting key exchanges (RSA/DH bits: %d, EC bits: %d):\n\n", rsa_bits, ec_bits);
        test_ciphersuite_kx(PRIO_DH);
        test_ciphersuite_kx(PRIO_ECDH);
        test_ciphersuite_kx(PRIO_ECDHE_ECDSA);
        test_ciphersuite_kx(PRIO_RSA);
      }

    gnutls_global_deinit();
    
}
