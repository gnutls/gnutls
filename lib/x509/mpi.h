#include "x509.h"

int _gnutls_x509_crt_get_mpis( gnutls_x509_crt cert,
	GNUTLS_MPI* params, int *params_size);
int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params);

int _gnutls_x509_write_rsa_params( GNUTLS_MPI * params, int params_size,
	opaque * der, int* dersize);

int _gnutls_x509_read_uint( ASN1_TYPE node, const char* value, 
	unsigned int* ret);

int _gnutls_x509_read_int( ASN1_TYPE node, const char* value, 
	GNUTLS_MPI* ret_mpi);
int _gnutls_x509_write_int( ASN1_TYPE node, const char* value, GNUTLS_MPI mpi, int lz);
int _gnutls_x509_write_uint32( ASN1_TYPE node, const char* value, uint32 num);
