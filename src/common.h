/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define SERVER "127.0.0.1"

#include <config.h>
#include <gnutls/gnutls.h>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#ifndef _WIN32
# include <netinet/in.h>
#endif

#include <signal.h>
#ifdef _WIN32
#include <io.h>
#include <winbase.h>
#undef OCSP_RESPONSE
#endif

#ifndef __attribute__
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define __attribute__(Spec)     /* empty */
#endif
#endif

/* the number of elements in the priority structures.
 */
#define PRI_MAX 16

extern const char str_unknown[];

int print_info (gnutls_session_t state, int verbose, int print_cert);
void print_cert_info (gnutls_session_t, int flag, int print_cert);
void print_cert_info_compact (gnutls_session_t session);

void print_list (const char* priorities, int verbose);
int cert_verify (gnutls_session_t session, const char* hostname);

const char *raw_to_string (const unsigned char *raw, size_t raw_size);
void pkcs11_common (void);
int check_command(gnutls_session_t session, const char* str);

int
pin_callback (void *user, int attempt, const char *token_url,
              const char *token_label, unsigned int flags, char *pin,
              size_t pin_max);

void pkcs11_common (void);
