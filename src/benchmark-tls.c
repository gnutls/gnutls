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
#define PRIO_ECDH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-RSA:+CURVE-SECP224R1"
#define PRIO_ECDHE_ECDSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ECDHE-ECDSA:+CURVE-SECP224R1"
#define PRIO_RSA "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+RSA"

#define PRIO_AES_CBC_SHA1 "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_ARCFOUR_128_MD5 "NONE:+VERS-TLS1.0:+ARCFOUR-128:+MD5:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_AES_GCM "NONE:+VERS-TLS1.2:+AES-128-GCM:+AEAD:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_CAMELLIA_CBC_SHA1 "NONE:+VERS-TLS1.0:+CAMELLIA-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"

/* #define PARAMS_1024 */

#ifdef PARAMS_1024
const char *pkcs3 = 
  "-----BEGIN DH PARAMETERS-----\n"
  "MIGHAoGBAO6vCrmts43WnDP4CvqPxehgcmGHdf88C56iMUycJWV21nTfdJbqgdM4\n"
  "O0gT1pLG4ODV2OJQuYvkjklcHWCJ2tFdx9e0YVTWts6O9K1psV1JglWbKXvPGIXF\n"
  "KfVmZg5X7GjtvDwFcmzAL9TL9Jduqpr9UTj+g3ZDW5/GHS/A6wbjAgEC\n"
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
/* DH of 2432 bits that is pretty equivalent to 224 bits of ECDH.
 */
const char *pkcs3 =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIICagKCATEBWS7COZB/f58zwMlPUWBEoRwPjS8W0vMl2bGvnbCBYuUkgk0T5uUz\n"
    "bLOV6vMNWxkO/jNLyR06T3nHiqr0j+pYkpGv3PXy0IcIG4CsXySicqCAn/9zmiVO\n"
    "GTkqAZfMskByWZRkSRU9lW8ca7po+PpJ9id2I0SlhDwgcpjw4f47ajXOBeil0uXs\n"
    "NWtQZlcd1NFjTDaToAnmN6x+pS6BXZ2It0/sPPGNdTsvF7Ym0fWWMV6JbZlXDODL\n"
    "kaT81cCdygUvaPEOUAcm/TXcelaTiBMlU2uBtfFjuI45+kzEWkNCNENvULyCoqZ+\n"
    "AH/dqer/DqnliJX7tnnlQLsuT7EIIyXtfM0F7XMLGU3WlKxpgWmWDdhpGHcM5xfv\n"
    "trUZWr/DWfeWyhwDDYashpYXcrYHf7iP3wKCATEA4nwYa0AFL3i1+4DNvZr0O47x\n"
    "pRf7dMK29Nh/WDdhIvl51c532I/2vBSUH4Mjd+Ao+rBxYAutRcz3kF+YhQjcdCMf\n"
    "/aKnbtepJ9Lz5xOKfqZdFfR2ANw7I+rNNd0LKHnzpm12xTZcAX7IT4eoIxrB2FYw\n"
    "vcQ6K2Soaan0clq8iCPuPx1HBPDNpFvQ7H+kF7o9Z0+7W7jFLpsdc2+x1mlo5/iT\n"
    "hw0yjuqm4rNX7VU/Vw1H1m/OIXarzURSE2C70uXBQaaDbOTDb+LZOExR1tGS16ZM\n"
    "PreiK1pH8v64OAbihB+OYd/QLU2y6YBjGPHxJQ/bAYFCnsEslkkgOot6bv81iktB\n"
    "mPny0He9Qafb1DaNMcXBBG9tZVMJD7HwobjciAQJx+bz9Ckb0EvkyD5N2t5ovw==\n"
    "-----END DH PARAMETERS-----\n" "\n";

static unsigned char server_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDfDCCAjSgAwIBAgIETuDcSzANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJU\n"
  "RTENMAsGA1UEChMEVGVzdDAeFw0xMTEyMDgxNTQ4MjhaFw0xNzA3MTcxNTQ4MzNa\n"
  "MBwxCzAJBgNVBAYTAlRFMQ0wCwYDVQQKEwRUZXN0MIIBUjANBgkqhkiG9w0BAQEF\n"
  "AAOCAT8AMIIBOgKCATEA0TxV0Cmz6FWfCsp/A9EDTvg73O4c76pGmDub2JLlVAHW\n"
  "ayC+3ovSgr6wKx1czC6smO2Q2LHsGMIYGBXekpdqOTMv5W40MwI7pQapHgjMZVoT\n"
  "fkUAP8ADiM/1qX1ehWjJ+Qj7U+wYN/O9UE6N0mRT/PIyIzit6sJ5DcGukKHwELho\n"
  "kYGsbWmozckbsIBcDyTZRQnN9d0puAACvGb7vtufiI/BCAKqCP+oczgXQUzeipEB\n"
  "wZlLWt+pDrfpqVec+A4NoJoMM/yOtmpwmdRJiczAhFyYKJFb9qwWQaqLhWCT4VAn\n"
  "MGD4wIBKmHzHettNgSwbtYJaaIY75eJjgCio+Q4CxGl0+JHQdymejgnA0hy1geG5\n"
  "fKxStGE/6ZU3pltmQ+D1iBPf53LbSYHwtyMJhrfsYwIDAQABo2YwZDAMBgNVHRMB\n"
  "Af8EAjAAMA8GA1UdEQQIMAaCBHRlc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYD\n"
  "VR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUbgzSzUa25oFNSFNk47uKeEBMkWUwDQYJ\n"
  "KoZIhvcNAQELBQADggExAKCDFHsfu/plC+Xiz+9dGk7PIxHuS8jPZRLSIsoI1c7H\n"
  "1zge+HzRm9ZaUY8ph8+7soKiqFVmAK/WajNQ4JdhQQUFo/0oreobJmUwZSSE+Ldn\n"
  "bRRTVo0yrgQ4r/7aemsG70yQnFjC+Ir1lPuYfaeC170rK0zbMIr1trRSU19UICYg\n"
  "JPK8Uud24sf0h1YCIMza9OpVQIijeRg7RV/Wmux5NR7os/VGjIVC17Li/I5mR1QF\n"
  "+HUSbyul/nMluBRdmUFJKF/OA47JS6Z6ck3AsTKXiYvSauprWfhjIvMt6BIU0Ktj\n"
  "g9aaTXRYhanfR/epxAnvcM51BeAfofPr69yR5ZHCUqCR0AYLuQ2oy6Hw0VP56SrS\n"
  "dcFFMceU7oOpOD0C72fDKCABg15liSCb2sUS58M5ts8=\n"
  "-----END CERTIFICATE-----\n";

static unsigned char server_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "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\n"
  "8bZaNY7zXZVgrVoVGCvq6Q==\n"
  "-----END RSA PRIVATE KEY-----\n";
#endif

static unsigned char server_ecc_key_pem[] =
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MGgCAQEEHHX3xeBOGgIxxtuhhpbwdwZnJztR7+uZTHnYuL+gBwYFK4EEACGhPAM6\n"
  "AATS8yZ/9bStGhSoHEflSr5z+xHvoSWbJkx7bOPdT09EnSZoqy0Q4eSloNpJTqzY\n"
  "fKL0vzzBLVlfSA==\n"
  "-----END EC PRIVATE KEY-----\n";

static unsigned char server_ecc_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICsDCCAWigAwIBAgIETeC0kjANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5H\n"
  "bnVUTFMgVGVzdCBDQTAeFw0xMTA1MjgwODM4NDNaFw0zODEwMTIwODM4NDZaMDEx\n"
  "LzAtBgNVBAMTJkdudVRMUyBUZXN0IHNlcnZlciAoRUNEU0EgY2VydGlmaWNhdGUp\n"
  "ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE0vMmf/W0rRoUqBxH5Uq+c/sR76ElmyZM\n"
  "e2zj3U9PRJ0maKstEOHkpaDaSU6s2Hyi9L88wS1ZX0ijgY0wgYowDAYDVR0TAQH/\n"
  "BAIwADAUBgNVHREEDTALgglsb2NhbGhvc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\n"
  "DwYDVR0PAQH/BAUDAweAADAdBgNVHQ4EFgQUJ97Q83IFpLgqeOnT1rX/JzCvlTQw\n"
  "HwYDVR0jBBgwFoAUTVa3agBY8WeS9KZ1VRuOUwED788wDQYJKoZIhvcNAQELBQAD\n"
  "ggExAErP9z8CCwt7YwA+SHoulNjqcXsngeKAKN9fVgV/XuspG6L2nU1WZvCjjFj6\n"
  "jggMbJSElyCuLZJKlTC/DihXUgRXyswOzg9qQ7dDv+V/Qi95XH5slXNzYxMQSdoA\n"
  "IaULVVDZcMFMVSc+TyAchJ6XwUY9umiysz3lSOioMQCch4MA366ZNqqnq5OD4moH\n"
  "1SUX8CbRjA6SLpvffexLTB2Af+mFi8ReTkXCwB1LGEH1HRp/XzBc+/F9mavy3g/6\n"
  "Hnjf2E1h2GDYXcJCVfE+ArjNS+R94jJwRMFBvwD/x2hsvpSajDpO0+GIxlGGKdyh\n"
  "7o4puz/BqHwSzX9h7I7RvFEogDUNUzLgHMdcjq5usnmQpdWNUP8Xs/WqLjML+/PT\n"
  "+jyCwmll0lPlC2RqAx3pM1XrjjQ=\n"
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
