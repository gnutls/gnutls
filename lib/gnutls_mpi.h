#ifndef GNUTLS_MPI_H
# define GNUTLS_MPI_H

# include <gcrypt.h>
# include <libasn1.h>

#define GNUTLS_MPI GCRY_MPI

#define _gnutls_mpi_new gcry_mpi_new
#define _gnutls_mpi_snew gcry_mpi_snew
#define _gnutls_mpi_copy gcry_mpi_copy
#define _gnutls_mpi_set_ui gcry_mpi_set_ui
#define _gnutls_mpi_set gcry_mpi_set
#define _gnutls_mpi_randomize gcry_mpi_randomize
#define _gnutls_mpi_get_nbits gcry_mpi_get_nbits
#define _gnutls_mpi_powm gcry_mpi_powm
#define _gnutls_mpi_invm _gcry_mpi_invm
#define _gnutls_mpi_addm gcry_mpi_addm
#define _gnutls_mpi_subm gcry_mpi_subm
#define _gnutls_mpi_mulm gcry_mpi_mulm
#define _gnutls_mpi_mul gcry_mpi_mul
#define _gnutls_mpi_add gcry_mpi_add

# define _gnutls_mpi_alloc_like(x) _gnutls_mpi_new(_gnutls_mpi_get_nbits(x)) 

void _gnutls_mpi_release( MPI* x);

int _gnutls_mpi_scan( GNUTLS_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );
int _gnutls_mpi_scan_pgp( GNUTLS_MPI *ret_mpi, const opaque *buffer, size_t *nbytes );

int _gnutls_mpi_print( opaque *buffer, size_t *nbytes, const GNUTLS_MPI a );
int _gnutls_mpi_print_lz( opaque *buffer, size_t *nbytes, const GNUTLS_MPI a );

int _gnutls_x509_read_int( ASN1_TYPE node, char* value, char* tmpstr, int tmpstr_size, MPI* ret_mpi);

asn1_retCode _gnutls_asn1_create_element(ASN1_TYPE definitions,char *source_name,
                                 ASN1_TYPE *element, char *dest_name);

#endif
