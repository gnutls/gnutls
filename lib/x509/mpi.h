#include "x509.h"

int _gnutls_x509_crt_get_mpis( gnutls_x509_crt cert,
	GNUTLS_MPI* params, int *params_size);
int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params);

int _gnutls_x509_write_rsa_params( GNUTLS_MPI * params, int params_size,
	opaque * der, int* dersize);

