#ifndef GNUTLS_GCRY_H
# define GNUTLS_GCRY_H

# include <gcrypt.h>

MPI _gnutls_mpi_new( int);

# define _gnutls_mpi_alloc_like(x) _gnutls_mpi_new(gcry_mpi_get_nbits(x)) 

void _gnutls_mpi_release( MPI* x);

int _gnutls_mpi_scan( GCRY_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );
int _gnutls_mpi_scan_raw( GCRY_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );

int _gnutls_mpi_print( opaque *buffer, size_t *nbytes, const GCRY_MPI a );
int _gnutls_mpi_print_raw( opaque *buffer, size_t *nbytes, const GCRY_MPI a );

#endif
