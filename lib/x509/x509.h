#ifndef X509_H
# define X509_H

typedef struct gnutls_x509_crl_int {
	ASN1_TYPE crl;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_crl_int;

typedef struct gnutls_x509_crt_int {
	ASN1_TYPE cert;
	gnutls_datum signed_data; /* Holds the signed data of the CRL.
				   */
	gnutls_datum signature;
	gnutls_pk_algorithm signature_algorithm;
} gnutls_x509_crt_int;

typedef struct gnutls_x509_privkey_int {
	gnutls_datum raw; /* we only keep raw data for the moment */
} gnutls_x509_privkey_int;

typedef struct gnutls_x509_crt_int *gnutls_x509_crt;
typedef struct gnutls_x509_crl_int *gnutls_x509_crl;
typedef struct gnutls_x509_privkey_int *gnutls_x509_privkey;

int gnutls_x509_crt_get_issuer_dn_by_oid(gnutls_x509_crt cert, const char* oid, 
	int indx, char *buf, int *sizeof_buf);
int gnutls_x509_crt_get_subject_alt_name(gnutls_x509_crt cert, 
	int seq, char *ret, int *ret_size, int* critical);
int gnutls_x509_crt_get_dn_by_oid(gnutls_x509_crt cert, const char* oid, 
	int indx, char *buf, int *sizeof_buf);
int gnutls_x509_crt_get_ca_status(gnutls_x509_crt cert, int* critical);
int gnutls_x509_crt_get_pk_algorithm( gnutls_x509_crt cert, int* bits);

int _gnutls_x509_crt_get_raw_issuer_dn( gnutls_x509_crt cert,
	gnutls_const_datum* start);
int _gnutls_x509_crt_get_raw_dn( gnutls_x509_crt cert,
	gnutls_const_datum* start);

int gnutls_x509_crt_get_serial(gnutls_x509_crt cert, char* result, int* result_size);

int _gnutls_x509_compare_raw_dn(const gnutls_const_datum * dn1,
	const gnutls_const_datum * dn2);

int gnutls_x509_crt_check_revocation(gnutls_x509_crt cert, gnutls_x509_crl * crl_list, int crl_list_length);


int _gnutls_x509_crl_get_raw_issuer_dn( gnutls_x509_crl crl,
	gnutls_const_datum* dn);
int gnutls_x509_crl_get_certificate_count(gnutls_x509_crl crl);
int gnutls_x509_crl_get_certificate(gnutls_x509_crl crl, int index,
				    unsigned char *serial,
				    int *serial_size, time_t * time);

void gnutls_x509_crl_deinit(gnutls_x509_crl crl);
int gnutls_x509_crl_init(gnutls_x509_crl * crl);
int gnutls_x509_crl_import(gnutls_x509_crl crl, const gnutls_datum * data,
			   gnutls_x509_crt_fmt format);

int gnutls_x509_crt_init(gnutls_x509_crt * cert);
void gnutls_x509_crt_deinit(gnutls_x509_crt cert);
int gnutls_x509_crt_import(gnutls_x509_crt cert, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);

int gnutls_x509_crt_get_key_usage(gnutls_x509_crt cert, unsigned int *key_usage,
	int *critical);
int gnutls_x509_crt_get_version(gnutls_x509_crt cert);

int gnutls_x509_privkey_init(gnutls_x509_privkey * key);
void gnutls_x509_privkey_deinit(gnutls_x509_privkey key);
int gnutls_x509_privkey_import(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);
int gnutls_x509_privkey_get_pk_algorithm( gnutls_x509_privkey key);

#endif
