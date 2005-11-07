/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef AUTH_PSK_H
# define AUTH_PSK_H

#include <gnutls_auth.h>

typedef struct gnutls_psk_client_credentials_st
{
  gnutls_datum username;
  gnutls_datum key;
  gnutls_psk_client_credentials_function *get_function;
} psk_client_credentials_st;

typedef struct gnutls_psk_server_credentials_st
{
  char *password_file;
  /* callback function, instead of reading the
   * password files.
   */
  gnutls_psk_server_credentials_function *pwd_callback;
} psk_server_cred_st;

/* these structures should not use allocated data */
typedef struct psk_server_auth_info_st
{
  char username[MAX_SRP_USERNAME + 1];
} *psk_server_auth_info_t;


#ifdef ENABLE_PSK

typedef struct psk_server_auth_info_st psk_server_auth_info_st;

#endif /* ENABLE_PSK */

#endif
