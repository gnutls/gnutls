#include <gnutls_int.h>
#include "x509.h"

int _gnutls_x509_crt_get_mpis(gnutls_x509_crt_t cert,
			      mpi_t * params, int *params_size);
int _gnutls_x509_read_rsa_params(opaque * der, int dersize,
				 mpi_t * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize,
				 mpi_t * params);
int _gnutls_x509_read_dsa_params(opaque * der, int dersize,
				 mpi_t * params);

int _gnutls_x509_write_rsa_params(mpi_t * params, int params_size,
				  gnutls_datum_t * der);
int _gnutls_x509_write_dsa_params(mpi_t * params, int params_size,
				  gnutls_datum_t * der);
int _gnutls_x509_write_dsa_public_key(mpi_t * params, int params_size,
				      gnutls_datum_t * der);

int _gnutls_x509_read_uint(ASN1_TYPE node, const char *value,
			   unsigned int *ret);

int _gnutls_x509_read_int(ASN1_TYPE node, const char *value,
			  mpi_t * ret_mpi);
int _gnutls_x509_write_int(ASN1_TYPE node, const char *value, mpi_t mpi,
			   int lz);
int _gnutls_x509_write_uint32(ASN1_TYPE node, const char *value,
			      uint32 num);

int _gnutls_x509_write_sig_params(ASN1_TYPE dst, const char *dst_name,
				  gnutls_pk_algorithm_t pk_algorithm,
				  mpi_t * params, int params_size);
