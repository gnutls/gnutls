 /*
 Copyright (c) 2002 Andrew McDonald <andrew@mcdonald.org.uk>

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the Free
 Software Foundation; either version 2 of the License, or (at your option)
 any later version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 more details.

 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <gnutls.h>
#include <gcrypt.h>
#include "gnutls-openssl.h"

static int last_error = 0;

void SSL_CTX_free(SSL_CTX *ctx)
{
    free(ctx->method->protocol_priority);
    free(ctx->method->cipher_priority);
    free(ctx->method->comp_priority);
    free(ctx->method->kx_priority);
    free(ctx->method->mac_priority);
    free(ctx->method);
    free(ctx);

    gnutls_global_deinit();
}


unsigned long ERR_get_error(void)
{
    unsigned long ret;

    ret = -1 * last_error;
    last_error = 0;

    return ret;
}

int SSL_get_error(SSL *ssl, int ret)
{
    if (ret > 0)
	return SSL_ERROR_NONE;

    return SSL_ERROR_ZERO_RETURN;
}

char *ERR_error_string(unsigned long e, char *buf)
{
    return gnutls_strerror(-1 * e);
}


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

int SSL_library_init(void)
{
    gnutls_global_init();
    return 1;
}

void SSL_load_error_strings(void)
{
    return;
}

SSL_CTX *SSL_CTX_new(SSL_METHOD *method)
{
    SSL_CTX *ctx;
    gnutls_global_init();
    
    ctx = (SSL_CTX *)calloc(sizeof(SSL_CTX), 1);
    ctx->method = method;
}

SSL *SSL_new(SSL_CTX *ctx)
{
    SSL *ssl;
    int err;

    ssl = (SSL *)calloc(sizeof(SSL), 1);
    if (!ssl)
	return NULL;

    err = gnutls_certificate_allocate_sc(&ssl->cred);
    if (err < 0)
    {
	last_error = err;
	free(ssl);
	return NULL;
    }

    gnutls_init(&ssl->state, GNUTLS_CLIENT);

    gnutls_protocol_set_priority (ssl->state, ctx->method->protocol_priority);
    gnutls_cipher_set_priority (ssl->state, ctx->method->cipher_priority);
    gnutls_compression_set_priority (ssl->state, ctx->method->comp_priority);
    gnutls_kx_set_priority (ssl->state, ctx->method->kx_priority);
    gnutls_mac_set_priority (ssl->state, ctx->method->mac_priority);

    gnutls_cred_set (ssl->state, GNUTLS_CRD_CERTIFICATE, ssl->cred);

    return ssl;
}

SSL_METHOD *SSLv23_client_method(void)
{
    SSL_METHOD *m;
    m = (SSL_METHOD *)calloc(sizeof(SSL_METHOD), 1);
    if (!m)
	return;

    m->protocol_priority = (int *)calloc(sizeof(int), 3);
    m->protocol_priority[0] = GNUTLS_TLS1;
    m->protocol_priority[1] = GNUTLS_SSL3;
    m->protocol_priority[2] = 0;

    m->cipher_priority = (int *)calloc(sizeof(int), 5);
    m->cipher_priority[0] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
    m->cipher_priority[1] = GNUTLS_CIPHER_3DES_CBC;
    m->cipher_priority[2] = GNUTLS_CIPHER_RIJNDAEL_256_CBC;
    m->cipher_priority[3] = GNUTLS_CIPHER_ARCFOUR;
    m->cipher_priority[4] = 0;

    m->comp_priority = (int *)calloc(sizeof(int), 3);
    m->comp_priority[0] = GNUTLS_COMP_ZLIB;
    m->comp_priority[1] = GNUTLS_COMP_NULL;
    m->comp_priority[2] = 0;

    m->kx_priority = (int *)calloc(sizeof(int), 4);
    m->kx_priority[0] = GNUTLS_KX_DHE_RSA;
    m->kx_priority[1] = GNUTLS_KX_RSA;
    m->kx_priority[2] = GNUTLS_KX_DHE_DSS;
    m->kx_priority[3] = 0;

    m->mac_priority = (int *)calloc(sizeof(int), 3);
    m->mac_priority[0] = GNUTLS_MAC_SHA;
    m->mac_priority[1] = GNUTLS_MAC_MD5;
    m->mac_priority[2] = 0;

    return m;
}

void SSL_free(SSL *ssl)
{
    gnutls_certificate_free_sc(ssl->cred);
    gnutls_deinit(ssl->state);
    free(ssl);
    return;
}


int SSL_set_fd(SSL *ssl, int fd)
{
    gnutls_transport_set_ptr (ssl->state, fd);
    return 1;
}


int SSL_connect(SSL *ssl)
{
    int err;

    err = gnutls_handshake(ssl->state);
    ssl->last_error = err;

    if (err < 0)
    {
	last_error = err;
	return 0;
    }

    return 1;
}


int SSL_write(SSL *ssl, const void *buf, int num)
{
    int ret;

    ret = gnutls_record_send(ssl->state, buf, num);
    ssl->last_error = ret;

    if (ret < 0)
    {
	last_error = ret;
	return 0;
    }

    return ret;
}


int SSL_read(SSL *ssl, const void *buf, int num)
{
    int ret;

    ret = gnutls_record_recv(ssl->state, buf, num);
    ssl->last_error = ret;

    if (ret < 0)
    {
	last_error = ret;
	return 0;
    }

    return ret;
}


int SSL_pending(SSL *ssl)
{
    return gnutls_record_check_pending(ssl->state);
}
