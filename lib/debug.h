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

#ifdef DEBUG
void _gnutls_print_state(GNUTLS_STATE state);
void _gnutls_print_TLSCompressed(GNUTLSCompressed * compressed);
void _gnutls_print_TLSPlaintext(GNUTLSPlaintext * plaintext);
void _gnutls_print_TLSCiphertext( GNUTLSCiphertext *);
char * _gnutls_bin2hex(const unsigned char *old, const size_t oldlen);
void _gnutls_dump_mpi(char* prefix,MPI a);
char* _gnutls_packet2str( int packet);
char* _gnutls_alert2str( int alert);
#endif
