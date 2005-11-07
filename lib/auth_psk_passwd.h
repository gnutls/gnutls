/*
 * Copyright (C) 2005 Free Software Foundation
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

#ifdef ENABLE_PSK

typedef struct {
    char *username;
    gnutls_datum_t key;
} PSK_PWD_ENTRY;

/* this is locally allocated. It should be freed using the provided function */
int _gnutls_psk_pwd_read_entry(gnutls_session_t state, char *username,
			       PSK_PWD_ENTRY **);
void _gnutls_psk_entry_free(SRP_PSK_ENTRY * entry);

#endif				/* ENABLE_SRP */
