#ifndef X509_H
# define X509_H

typedef struct gnutls_x509_crl_int {
	ASN1_TYPE crl;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_crl_int;

typedef struct gnutls_x509_certificate_int {
	ASN1_TYPE cert;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_certificate_int;

typedef struct gnutls_x509_certificate_int *gnutls_x509_certificate;
typedef struct gnutls_x509_crl_int *gnutls_x509_crl;

int gnutls_x509_certificate_get_issuer_dn_by_oid(gnutls_x509_certificate cert, const char* oid, 
	int indx, char *buf, int *sizeof_buf);
int gnutls_x509_certificate_get_subject_alt_name(gnutls_x509_certificate cert, 
	int seq, char *ret, int *ret_size, int* critical);
int gnutls_x509_certificate_get_dn_by_oid(gnutls_x509_certificate cert, const char* oid, 
	int indx, char *buf, int *sizeof_buf);
int gnutls_x509_certificate_get_ca_status(gnutls_x509_certificate cert, int* critical);
int gnutls_x509_certificate_get_pk_algorithm( gnutls_x509_certificate cert, int* bits);

int _gnutls_x509_certificate_get_raw_issuer_dn( gnutls_x509_certificate cert,
	gnutls_const_datum* start);
int _gnutls_x509_certificate_get_raw_dn( gnutls_x509_certificate cert,
	gnutls_const_datum* start);

int gnutls_x509_certificate_get_serial(gnutls_x509_certificate cert, char* result, int* result_size);

int _gnutls_x509_compare_raw_dn(const gnutls_const_datum * dn1,
	const gnutls_const_datum * dn2);

int gnutls_x509_certificate_check_revocation(gnutls_x509_certificate cert, gnutls_x509_crl * crl_list, int crl_list_length);


int _gnutls_x509_crl_get_raw_issuer_dn( gnutls_x509_crl crl,
	gnutls_const_datum* dn);
int gnutls_x509_crl_get_certificate_count(gnutls_x509_crl crl);
int gnutls_x509_crl_get_certificate(gnutls_x509_crl crl, int index,
				    unsigned char *serial,
				    int *serial_size, time_t * time);

void gnutls_x509_crl_deinit(gnutls_x509_crl crl);
int gnutls_x509_crl_init(gnutls_x509_crl * crl);
int gnutls_x509_crl_import(gnutls_x509_crl crl, const gnutls_datum * data,
			   gnutls_x509_certificate_format format);

int gnutls_x509_certificate_init(gnutls_x509_certificate * cert);
void gnutls_x509_certificate_deinit(gnutls_x509_certificate cert);
int gnutls_x509_certificate_import(gnutls_x509_certificate cert, const gnutls_datum * data,
	gnutls_x509_certificate_format format);

int gnutls_x509_certificate_get_key_usage(gnutls_x509_certificate cert, unsigned int *key_usage,
	int *critical);
int gnutls_x509_certificate_get_version(gnutls_x509_certificate cert);

#endif
