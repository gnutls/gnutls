#ifndef CRL_H
# define CRL_H

#include "x509.h"

typedef struct gnutls_x509_crl_int {
	ASN1_TYPE crl;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_crl_int;

typedef struct gnutls_x509_crl_int *gnutls_x509_crl;

int _gnutls_x509_crl_get_raw_issuer_dn( gnutls_x509_crl crl,
	gnutls_const_datum* dn);

#endif
