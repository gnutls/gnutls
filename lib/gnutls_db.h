/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

void gnutls_set_cache_expiration( GNUTLS_STATE state, int seconds);
int gnutls_db_set_name( GNUTLS_STATE state, const char* filename);
int _gnutls_server_register_current_session( GNUTLS_STATE state);
int _gnutls_server_restore_session( GNUTLS_STATE state, uint8* session_id, int session_id_size);
int gnutls_db_clean( GNUTLS_STATE state);
int _gnutls_db_remove_session( GNUTLS_STATE state, uint8* session_id, int session_id_size);
int _gnutls_store_session( GNUTLS_STATE state, gnutls_datum session_id, gnutls_datum session_data);
gnutls_datum _gnutls_retrieve_session( GNUTLS_STATE state, gnutls_datum session_id);
int _gnutls_remove_session( GNUTLS_STATE state, gnutls_datum session_id);
