#include <gnutls_int.h>
#include "x509.h"

int _gnutls_x509_crt_get_mpis( gnutls_x509_crt cert,
	GNUTLS_MPI* params, int *params_size);
int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params);

int _gnutls_x509_write_rsa_params( GNUTLS_MPI * params, int params_size,
	gnutls_datum* der);
int _gnutls_x509_write_dsa_params( GNUTLS_MPI * params, int params_size,
        gnutls_datum* der);
int _gnutls_x509_write_dsa_public_key( GNUTLS_MPI * params, int params_size,
	gnutls_datum* der);

int _gnutls_x509_read_uint( ASN1_TYPE node, const char* value, 
	unsigned int* ret);

int _gnutls_x509_read_int( ASN1_TYPE node, const char* value, 
	GNUTLS_MPI* ret_mpi);
int _gnutls_x509_write_int( ASN1_TYPE node, const char* value, GNUTLS_MPI mpi, int lz);
int _gnutls_x509_write_uint32( ASN1_TYPE node, const char* value, uint32 num);

int _gnutls_x509_write_sig_params( ASN1_TYPE dst, const char* dst_name,
	gnutls_pk_algorithm pk_algorithm, GNUTLS_MPI * params, int params_size);
