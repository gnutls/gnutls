
typedef struct gnutls_pkcs12_int {
	ASN1_TYPE pkcs12;
} gnutls_pkcs12_int;

typedef struct gnutls_pkcs12_int *gnutls_pkcs12;

int gnutls_pkcs12_init(gnutls_pkcs12 * pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12 pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12 pkcs12, const gnutls_datum * data,
	gnutls_x509_crt_fmt format, const char* password, unsigned int flags);
