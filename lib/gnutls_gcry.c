/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>

/* Functions that refer to the libgcrypt library.
 */
 
void _gnutls_mpi_release( MPI* x) {
	if (*x==NULL) return;
	gcry_mpi_release(*x);
	*x=NULL;
}

MPI _gnutls_mpi_new( int bits) {
	return gcry_mpi_new( bits);
}

int _gnutls_mpi_scan( GCRY_MPI *ret_mpi, const opaque *buffer, size_t *nbytes ) {
	return gcry_mpi_scan( ret_mpi, GCRYMPI_FMT_STD, buffer, nbytes);

}

int _gnutls_mpi_scan_raw( GCRY_MPI *ret_mpi, const opaque *buffer, size_t *nbytes ) {
	return gcry_mpi_scan( ret_mpi, GCRYMPI_FMT_USG, buffer, nbytes);

}

int _gnutls_mpi_print( opaque *buffer, size_t *nbytes, const GCRY_MPI a ) {
	return gcry_mpi_print( GCRYMPI_FMT_STD, buffer, nbytes, a);
}

int _gnutls_mpi_print_raw( opaque *buffer, size_t *nbytes, const GCRY_MPI a ) {
	return gcry_mpi_print( GCRYMPI_FMT_USG, buffer, nbytes, a);
}
