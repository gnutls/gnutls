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
#include <x509_asn1.h>
#include <gnutls_errors.h>

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
	return gcry_mpi_scan( ret_mpi, GCRYMPI_FMT_USG, buffer, nbytes);

}

int _gnutls_mpi_print( opaque *buffer, size_t *nbytes, const GCRY_MPI a ) {
	return gcry_mpi_print( GCRYMPI_FMT_USG, buffer, nbytes, a);
}


/* this function reads an integer
 * from asn1 structs. Combines the read and mpi_scan
 * steps.
 */
int _gnutls_x509_read_int( node_asn* node, char* value, char* tmpstr, int tmpstr_size, MPI* ret_mpi) {
int len, result;

	len = tmpstr_size - 1;
	result = asn1_read_value(node, value, tmpstr, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (_gnutls_mpi_scan( ret_mpi, tmpstr, &len) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}
