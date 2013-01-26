/* -*- c -*-
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_SBUF_H
#define GNUTLS_SBUF_H

#include <gnutls/gnutls.h>

/* Buffered session I/O */
typedef struct gnutls_sbuf_st *gnutls_sbuf_t;
typedef struct gnutls_credentials_st *gnutls_credentials_t;

typedef enum
{
  GNUTLS_VMETHOD_INSECURE = 0,
  GNUTLS_VMETHOD_TOFU = 1<<0,
  GNUTLS_VMETHOD_SINGLE_CA = 1<<1,
  GNUTLS_VMETHOD_SYSTEM_CAS = 1<<2
} gnutls_vmethod_t;

ssize_t gnutls_sbuf_printf (gnutls_sbuf_t sb, const char *fmt, ...)
#ifdef __GNUC__
   __attribute__ ((format (printf, 2, 3)))
#endif
;

ssize_t gnutls_sbuf_write (gnutls_sbuf_t sb, const void *data,
                           size_t data_size);

ssize_t gnutls_sbuf_flush (gnutls_sbuf_t sb);

int gnutls_sbuf_handshake(gnutls_sbuf_t sb);
ssize_t gnutls_sbuf_read(gnutls_sbuf_t sb, void* data, size_t data_size);

ssize_t
gnutls_sbuf_getdelim (gnutls_sbuf_t sbuf, char **lineptr, size_t *n, int delimiter);

#define gnutls_sbuf_getline(sbuf, ptr, n) gnutls_sbuf_getdelim(sbuf, ptr, n, '\n')

#define GNUTLS_SBUF_QUEUE_FLUSHES 1
void gnutls_sbuf_deinit(gnutls_sbuf_t sb);

int gnutls_sbuf_sinit (gnutls_sbuf_t * isb, gnutls_session_t session,
                       unsigned int flags);

int gnutls_sbuf_client_init (gnutls_sbuf_t * isb, const char* hostname, 
                             const char* service,
                             gnutls_transport_ptr fd, 
                             const char* priority, gnutls_credentials_t cred,
                             unsigned int flags);

/* High level credential structures */
int gnutls_credentials_init (gnutls_credentials_t* cred);
void gnutls_credentials_deinit (gnutls_credentials_t cred);

int gnutls_credentials_set_trust (gnutls_credentials_t cred, unsigned vflags, 
                                  const char* ca_file, const char* crl_file,
                                  const char* tofu_file);


#endif /* GNUTLS_SBUF_H */
