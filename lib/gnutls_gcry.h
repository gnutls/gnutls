#ifndef GNUTLS_GCRY_H
# define GNUTLS_GCRY_H

# include <gcrypt.h>

# define gcry_mpi_alloc_like(x) gcry_mpi_new(gcry_mpi_get_nbits(x)) 

void _gnutls_mpi_release( MPI* x);

#endif
