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

#define PRIO_DH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_ECDH "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-ECDH:+CURVE-SECP224R1"

#define PRIO_AES_CBC_SHA1 "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_ARCFOUR_128_MD5 "NONE:+VERS-TLS1.0:+ARCFOUR-128:+MD5:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_AES_GCM "NONE:+VERS-TLS1.2:+AES-128-GCM:+AEAD:+SIGN-ALL:+COMP-NULL:+ANON-DH"
#define PRIO_CAMELLIA_CBC_SHA1 "NONE:+VERS-TLS1.0:+CAMELLIA-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+ANON-DH"

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
    gnutls_session_t client;
    /* Need to enable anonymous KX specifically. */
    int ret;
    struct benchmark_st st;

    /* Init server */
    gnutls_anon_allocate_server_credentials(&s_anoncred);
    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_import_pkcs3(dh_params, &p3, GNUTLS_X509_FMT_PEM);
    gnutls_anon_set_server_dh_params(s_anoncred, dh_params);

    start_benchmark(&st);

    do {
        gnutls_init(&server, GNUTLS_SERVER);
        ret = gnutls_priority_set_direct(server, cipher_prio, &str);
        if (ret < 0) {
            fprintf(stderr, "Error in %s\n", str);
            exit(1);
        }
        gnutls_credentials_set(server, GNUTLS_CRD_ANON, s_anoncred);
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
    printf("\n");

    printf("Testing key exchanges:\n");
    test_ciphersuite_kx(PRIO_DH);
    test_ciphersuite_kx(PRIO_ECDH);


    gnutls_global_deinit();
    
}
