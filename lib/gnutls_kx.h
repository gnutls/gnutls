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

int _gnutls_send_server_kx_message(int cd, GNUTLS_STATE state);
int _gnutls_send_server_kx_message2(int cd, GNUTLS_STATE state);
int _gnutls_send_client_kx_message(int cd, GNUTLS_STATE state);
int _gnutls_send_client_kx_message0(int cd, GNUTLS_STATE state);
int _gnutls_recv_server_kx_message(int cd, GNUTLS_STATE state);
int _gnutls_recv_server_kx_message2(int cd, GNUTLS_STATE state);
int _gnutls_recv_client_kx_message(int cd, GNUTLS_STATE state);
int _gnutls_recv_client_kx_message0(int cd, GNUTLS_STATE state);
int _gnutls_send_client_certificate_verify(int cd, GNUTLS_STATE state);
int _gnutls_send_certificate(int cd, GNUTLS_STATE state);
int _gnutls_generate_master( GNUTLS_STATE state);
int _gnutls_recv_certificate(SOCKET cd, GNUTLS_STATE state);
int _gnutls_send_client_certificate(SOCKET cd, GNUTLS_STATE state);

