
typedef struct gnutls_crl_int {
	ASN1_TYPE crl;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_crl_int;

typedef struct gnutls_crl_int *gnutls_crl;
