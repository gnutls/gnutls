
typedef struct gnutls_pkcs7_int {
	ASN1_TYPE pkcs7;
} gnutls_pkcs7_int;

typedef struct gnutls_pkcs7_int *gnutls_pkcs7;

int gnutls_pkcs7_init(gnutls_pkcs7 * pkcs7);
void gnutls_pkcs7_deinit(gnutls_pkcs7 pkcs7);
int gnutls_pkcs7_import(gnutls_pkcs7 pkcs7, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);
int gnutls_pkcs7_get_certificate(gnutls_pkcs7 pkcs7, 
	int indx, unsigned char* certificate, int* certificate_size);
int gnutls_pkcs7_get_certificate_count(gnutls_pkcs7 pkcs7);
