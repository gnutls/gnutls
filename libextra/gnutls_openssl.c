/*
 * Copyright (c) 2002 Andrew McDonald <andrew@mcdonald.org.uk>
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <gnutls.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "gnutls-openssl.h"

static int last_error = 0;


/* Library initialisation functions */

int SSL_library_init(void)
{
    gnutls_global_init();
    /* NB: we haven't got anywhere to call gnutls_global_deinit() */
    return 1;
}

void OpenSSL_add_all_algorithms(void)
{
    return;
}


/* SSL_CTX structure handling */

SSL_CTX *SSL_CTX_new(SSL_METHOD *method)
{
    SSL_CTX *ctx;
    
    ctx = (SSL_CTX *)calloc(1, sizeof(SSL_CTX));
    ctx->method = method;

    return ctx;
}

void SSL_CTX_free(SSL_CTX *ctx)
{
    free(ctx->method);
    free(ctx);
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    return 0;
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *certfile, int type)
{
    ctx->certfile = (char *)calloc(1, strlen(certfile)+1);
    if (!ctx->certfile)
        return -1;
    memcpy(ctx->certfile, certfile, strlen(certfile));

    ctx->certfile_type = type;

    return 1;
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *keyfile, int type)
{
    ctx->keyfile = (char *)calloc(1, strlen(keyfile)+1);
    if (!ctx->keyfile)
        return -1;
    memcpy(ctx->keyfile, keyfile, strlen(keyfile));

    ctx->keyfile_type = type;

    return 1;

}

void SSL_CTX_set_verify(SSL_CTX *ctx, int verify_mode,
                        int (*verify_callback)(int, X509_STORE_CTX *))
{
    ctx->verify_mode = verify_mode;
    ctx->verify_callback = verify_callback;
}

unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long options)
{
    return (ctx->options |= options);
}


/* SSL structure handling */

SSL *SSL_new(SSL_CTX *ctx)
{
    SSL *ssl;
    int err;

    ssl = (SSL *)calloc(1, sizeof(SSL));
    if (!ssl)
        return NULL;

    err = gnutls_certificate_allocate_sc(&ssl->gnutls_cred);
    if (err < 0)
    {
        last_error = err;
        free(ssl);
        return NULL;
    }

    gnutls_init(&ssl->gnutls_state, GNUTLS_CLIENT);

    gnutls_protocol_set_priority (ssl->gnutls_state, ctx->method->protocol_priority);
    gnutls_cipher_set_priority (ssl->gnutls_state, ctx->method->cipher_priority);
    gnutls_compression_set_priority (ssl->gnutls_state, ctx->method->comp_priority);
    gnutls_kx_set_priority (ssl->gnutls_state, ctx->method->kx_priority);
    gnutls_mac_set_priority (ssl->gnutls_state, ctx->method->mac_priority);

    gnutls_cred_set (ssl->gnutls_state, GNUTLS_CRD_CERTIFICATE, ssl->gnutls_cred);
    if (ctx->certfile)
        gnutls_certificate_set_x509_trust_file(ssl->gnutls_cred, ctx->certfile,
                                               ctx->certfile_type);
    if (ctx->keyfile)
        gnutls_certificate_set_x509_key_file(ssl->gnutls_cred, ctx->certfile,
                                             ctx->keyfile, ctx->keyfile_type);

    ssl->verify_mode = ctx->verify_mode;
    ssl->verify_callback = ctx->verify_callback;

    ssl->options = ctx->options;

    return ssl;
}

void SSL_free(SSL *ssl)
{
    gnutls_certificate_free_sc(ssl->gnutls_cred);
    gnutls_deinit(ssl->gnutls_state);
    free(ssl);
    return;
}

void SSL_load_error_strings(void)
{
    return;
}

int SSL_get_error(SSL *ssl, int ret)
{
    if (ret > 0)
        return SSL_ERROR_NONE;

    return SSL_ERROR_ZERO_RETURN;
}

int SSL_set_fd(SSL *ssl, int fd)
{
    gnutls_transport_set_ptr (ssl->gnutls_state, fd);
    return 1;
}


void SSL_set_connect_state(SSL *ssl)
{
    return;
}

int SSL_pending(SSL *ssl)
{
    return gnutls_record_check_pending(ssl->gnutls_state);
}

void SSL_set_verify(SSL *ssl, int verify_mode,
                    int (*verify_callback)(int, X509_STORE_CTX *))
{
    ssl->verify_mode = verify_mode;
    ssl->verify_callback = verify_callback;
}


/* SSL connection open/close/read/write functions */

int SSL_connect(SSL *ssl)
{
    X509_STORE_CTX *store;
    int cert_list_size = 0;
    int err;

    err = gnutls_handshake(ssl->gnutls_state);
    ssl->last_error = err;

    if (err < 0)
    {
        last_error = err;
        return 0;
    }

    store = (X509_STORE_CTX *)calloc(1, sizeof(X509_STORE_CTX));
    store->ssl = ssl;
    store->cert_list = gnutls_certificate_get_peers(ssl->gnutls_state,
                                                    &cert_list_size);

    if (ssl->verify_callback)
    {
        ssl->verify_callback(1 /*FIXME*/, store);
    }
    ssl->state = SSL_ST_OK;

    err = store->error;
    free(store);

    return 1;
}

int SSL_shutdown(SSL *ssl)
{
    if (!ssl->shutdown)
    {
        gnutls_bye(ssl->gnutls_state, GNUTLS_SHUT_WR);
        ssl->shutdown++;
    }
    else
    {
        gnutls_bye(ssl->gnutls_state, GNUTLS_SHUT_RDWR);
        ssl->shutdown++;
    }

    /* FIXME */
    return 1;
}

int SSL_read(SSL *ssl, const void *buf, int len)
{
    int ret;

    ret = gnutls_record_recv(ssl->gnutls_state, buf, len);
    ssl->last_error = ret;

    if (ret < 0)
    {
        last_error = ret;
        return 0;
    }

    return ret;
}

int SSL_write(SSL *ssl, const void *buf, int len)
{
    int ret;

    ret = gnutls_record_send(ssl->gnutls_state, buf, len);
    ssl->last_error = ret;

    if (ret < 0)
    {
        last_error = ret;
        return 0;
    }

    return ret;
}


/* SSL_METHOD functions */

SSL_METHOD *SSLv23_client_method(void)
{
    SSL_METHOD *m;
    m = (SSL_METHOD *)calloc(1, sizeof(SSL_METHOD));
    if (!m)
        return NULL;

    m->protocol_priority[0] = GNUTLS_TLS1;
    m->protocol_priority[1] = GNUTLS_SSL3;
    m->protocol_priority[2] = 0;

    m->cipher_priority[0] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
    m->cipher_priority[1] = GNUTLS_CIPHER_3DES_CBC;
    m->cipher_priority[2] = GNUTLS_CIPHER_RIJNDAEL_256_CBC;
    m->cipher_priority[3] = GNUTLS_CIPHER_ARCFOUR;
    m->cipher_priority[4] = 0;

    m->comp_priority[0] = GNUTLS_COMP_ZLIB;
    m->comp_priority[1] = GNUTLS_COMP_NULL;
    m->comp_priority[2] = 0;

    m->kx_priority[0] = GNUTLS_KX_DHE_RSA;
    m->kx_priority[1] = GNUTLS_KX_RSA;
    m->kx_priority[2] = GNUTLS_KX_DHE_DSS;
    m->kx_priority[3] = 0;

    m->mac_priority[0] = GNUTLS_MAC_SHA;
    m->mac_priority[1] = GNUTLS_MAC_MD5;
    m->mac_priority[2] = 0;

    return m;
}


/* SSL_CIPHER functions */

SSL_CIPHER *SSL_get_current_cipher(SSL *ssl)
{
    SSL_CIPHER *sslc;

    sslc = (SSL_CIPHER *)calloc(1, sizeof(SSL_CIPHER));
    if (!sslc)
        return NULL;

    sslc->version = gnutls_protocol_get_version(ssl->gnutls_state);
    sslc->cipher = gnutls_cipher_get(ssl->gnutls_state);
    sslc->kx = gnutls_kx_get(ssl->gnutls_state);
    sslc->mac = gnutls_mac_get(ssl->gnutls_state);
    sslc->compression = gnutls_compression_get(ssl->gnutls_state);
    sslc->cert = gnutls_cert_type_get(ssl->gnutls_state);

    return sslc;
}

const char *SSL_CIPHER_get_name(SSL_CIPHER *cipher)
{
    if (!cipher)
        return ("NONE");

    /* FIXME? - the openssl name is of the form "DES-CBC3-SHA" */
    return gnutls_cipher_get_name(cipher->cipher);
}

int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *bits)
{
    int bit_result;

    if (!cipher)
        return 0;

    /* FIXME: ought to do this by parsing data returned by cipher_get_name */
    switch(cipher->cipher)
    {
    case GNUTLS_CIPHER_ARCFOUR:
    case GNUTLS_CIPHER_RIJNDAEL_128_CBC:
    case GNUTLS_CIPHER_TWOFISH_128_CBC:
        bit_result = 128;
        break;
    case GNUTLS_CIPHER_3DES_CBC:
        bit_result = 168;
        break;
    case GNUTLS_CIPHER_RIJNDAEL_256_CBC:
        bit_result = 256;
        break;
    default:
        bit_result = 0;
        break;
    }

    if (bits)
        *bits = bit_result;

    return bit_result;
}

const char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
{
    const char *ret;

    if (!cipher)
        return ("(NONE)");

    ret = gnutls_protocol_get_name(cipher->version);
    if (ret)
        return ret;

    return ("unknown");
}


/* X509 functions */

X509_NAME *X509_get_subject_name(X509 *cert)
{
    gnutls_x509_dn *dn;
    dn = (gnutls_x509_dn *)calloc(1, sizeof(gnutls_x509_dn));
    if (gnutls_x509_extract_certificate_dn(cert, dn) < 0)
    {
        free(dn);
        return NULL;
    }
    return dn;
}

char *X509_NAME_oneline(gnutls_x509_dn *name, char *buf, int len)
{
    memset(buf, 0, len);
    if (!buf)
        return NULL;

    snprintf(buf, len-1, "C=%s, ST=%s, L=%s, O=%s, OU=%s, CN=%s/Email=%s",
             name->country, name->state_or_province_name,
             name->locality_name, name->organization,
             name->organizational_unit_name,
             name->common_name, name->email);
    return buf;
}


/* BIO functions */

void BIO_get_fd(GNUTLS_STATE gnutls_state, int *fd)
{
    *fd = gnutls_transport_get_ptr(gnutls_state);
}


/* error handling */

unsigned long ERR_get_error(void)
{
    unsigned long ret;

    ret = -1 * last_error;
    last_error = 0;

    return ret;
}

char *ERR_error_string(unsigned long e, char *buf)
{
    return gnutls_strerror(-1 * e);
}


/* RAND functions */

int RAND_status(void)
{
    return 1;
}

void RAND_seed(const void *buf, int num)
{
    return;
}

int RAND_bytes(unsigned char *buf, int num)
{
    gcry_randomize(buf, num, GCRY_STRONG_RANDOM);
    return 1;
}

const char *RAND_file_name(char *buf, size_t len)
{
    return "";
}

int RAND_load_file(const char *name, long maxbytes)
{
    return maxbytes;
}

int RAND_write_file(const char *name)
{
    return 0;
}


/* message digest functions */

void MD5_Init(MD5_CTX *ctx)
{
    ctx->handle = gcry_md_open(GCRY_MD_MD5, 0);
}

void MD5_Update(MD5_CTX *ctx, const void *buf, int len)
{
    gcry_md_write(ctx->handle, buf, len);
}

void MD5_Final(unsigned char *md, MD5_CTX *ctx)
{
    unsigned char *local_md;

    gcry_md_final(ctx->handle);
    local_md = gcry_md_read(ctx->handle, 0);
    if (md)
        memcpy(md, local_md, gcry_md_get_algo_dlen(GCRY_MD_MD5));
    gcry_md_close(ctx->handle);
}

unsigned char *MD5(const unsigned char *buf, unsigned long len,
                   unsigned char *md)
{
    unsigned char *local_md;

    if (!md)
        return NULL;

    local_md = alloca(gcry_md_get_algo_dlen(GCRY_MD_MD5));

    gcry_md_hash_buffer(GCRY_MD_MD5, local_md, buf, len);

    memcpy(md, local_md, gcry_md_get_algo_dlen(GCRY_MD_MD5));
    
    return md;
}

void RIPEMD160_Init(RIPEMD160_CTX *ctx)
{
    ctx->handle = gcry_md_open(GCRY_MD_RMD160, 0);
}

void RIPEMD160_Update(RIPEMD160_CTX *ctx, const void *buf, int len)
{
    gcry_md_write(ctx->handle, buf, len);
}

void RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *ctx)
{
    unsigned char *local_md;
    gcry_md_final(ctx->handle);
    local_md = gcry_md_read(ctx->handle, 0);
    if (md)
        memcpy(md, local_md, gcry_md_get_algo_dlen(GCRY_MD_RMD160));
    gcry_md_close(ctx->handle);
}

unsigned char *RIPEMD160(const unsigned char *buf, unsigned long len,
                         unsigned char *md)
{
    unsigned char *local_md;

    if (!md)
        return NULL;

    local_md = alloca(gcry_md_get_algo_dlen(GCRY_MD_RMD160));

    gcry_md_hash_buffer(GCRY_MD_RMD160, local_md, buf, len);

    memcpy(md, local_md, gcry_md_get_algo_dlen(GCRY_MD_RMD160));
    
    return md;
}
