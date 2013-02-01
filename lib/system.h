/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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

#ifndef SYSTEM_H
#define SYSTEM_H

#include <gnutls_int.h>

#ifndef _WIN32
# include <sys/uio.h>            /* for writev */
#else
# include <windows.h>            /* for Sleep */
#endif

int system_errno (gnutls_transport_ptr_t);
int system_recv_timeout(gnutls_transport_ptr_t ptr, unsigned int ms);

#ifdef _WIN32
ssize_t system_write (gnutls_transport_ptr_t ptr, const void *data,
                      size_t data_size);
#else
#define HAVE_WRITEV
ssize_t system_writev (gnutls_transport_ptr_t ptr, const giovec_t * iovec,
                       int iovec_cnt);
#endif
ssize_t system_read (gnutls_transport_ptr_t ptr, void *data, size_t data_size);

#ifdef _WIN32
#define HAVE_WIN32_LOCKS
#else
#ifdef HAVE_LIBPTHREAD
#define HAVE_PTHREAD_LOCKS
#else
#define HAVE_NO_LOCKS
#endif
#endif

extern gnutls_time_func gnutls_time;

static inline void millisleep(unsigned int ms)
{
#ifdef _WIN32
  Sleep(ms);
#else
struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = ms*1000*1000;
  
  nanosleep(&ts, NULL);
#endif
}

int _gnutls_find_config_path(char* path, size_t max_size);
int _gnutls_ucs2_to_utf8(const void* data, size_t size, gnutls_datum_t *output);

int gnutls_system_global_init (void);
void gnutls_system_global_deinit (void);

#endif /* SYSTEM_H */
