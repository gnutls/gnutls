
typedef struct gnutls_x509_certificate_int {
	ASN1_TYPE cert;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_certificate_int;

typedef struct gnutls_x509_certificate_int *gnutls_x509_certificate;

int gnutls_x509_certificate_get_issuer_dn_by_oid(gnutls_x509_certificate cert, const char* oid, char *buf,
					 int *sizeof_buf);
int gnutls_x509_certificate_get_subject_alt_name(gnutls_x509_certificate cert, 
	int seq, char *ret, int *ret_size, int* critical);
int gnutls_x509_certificate_get_dn_by_oid(gnutls_x509_certificate cert, const char* oid, char *buf,
					 int *sizeof_buf);
