#include "x509.h"

int _gnutls_x509_certificate_get_mpis( gnutls_x509_certificate cert,
	GNUTLS_MPI* params, int *params_size);
int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
