#ifndef GNUTLS_GCRY_H
# define GNUTLS_GCRY_H

# include <gcrypt.h>

MPI _gnutls_mpi_new( int);

# define _gnutls_mpi_alloc_like(x) _gnutls_mpi_new(gcry_mpi_get_nbits(x)) 

void _gnutls_mpi_release( MPI* x);

int _gnutls_mpi_scan( GCRY_MPI *ret_mpi, enum gcry_mpi_format format,
                                       const char *buffer, size_t *nbytes );


#endif
