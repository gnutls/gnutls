
typedef struct gnutls_x509_certificate_int {
	ASN1_TYPE cert;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_certificate_int;

typedef struct gnutls_x509_certificate_int *gnutls_x509_certificate;
