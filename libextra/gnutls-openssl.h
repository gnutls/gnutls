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

#ifndef SSL_COMPAT_H
#define SSL_COMPAT_H
#include <gnutls.h>

#define SSL_ERROR_NONE                  0
#define SSL_ERROR_SSL                   1
#define SSL_ERROR_WANT_READ             2
#define SSL_ERROR_WANT_WRITE            3
#define SSL_ERROR_SYSCALL               5
#define SSL_ERROR_ZERO_RETURN           6

typedef struct
{
    int *protocol_priority;
    int *cipher_priority;
    int *comp_priority;
    int *kx_priority;
    int *mac_priority;
} SSL_METHOD;

typedef struct
{
    SSL_METHOD *method;

} SSL_CTX;

typedef struct
{
    GNUTLS_STATE state;
    GNUTLS_CERTIFICATE_CLIENT_CREDENTIALS cred;
    int last_error;
} SSL;


unsigned long ERR_get_error(void);
int SSL_get_error(SSL *ssl, int ret);
char *ERR_error_string(unsigned long e, char *buf);

int  RAND_status(void);
int RAND_bytes(unsigned char *buf, int num);

int SSL_library_init(void);
#define OpenSSL_add_ssl_algorithms()    SSL_library_init()
#define SSLeay_add_ssl_algorithms()     SSL_library_init()
void SSL_load_error_strings(void);

SSL_CTX *SSL_CTX_new(SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);

SSL_METHOD *SSLv23_client_method(void);
int SSL_set_fd(SSL *ssl, int fd);

int SSL_connect(SSL *ssl);


int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_read(SSL *ssl, const void *buf, int num);

int SSL_pending(SSL *ssl);
#endif
