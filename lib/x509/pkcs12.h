
typedef struct gnutls_pkcs12_int {
	ASN1_TYPE pkcs12;
} gnutls_pkcs12_int;

typedef enum gnutls_pkcs12_bag_type {
	GNUTLS_BAG_EMPTY = 0,

	GNUTLS_BAG_PKCS8_ENCRYPTED_KEY=1,
	GNUTLS_BAG_PKCS8_KEY,
	GNUTLS_BAG_CERTIFICATE,
	GNUTLS_BAG_CRL,
	GNUTLS_BAG_ENCRYPTED=10
} gnutls_pkcs12_bag_type;

typedef struct gnutls_pkcs12_bag_int {
	gnutls_datum data;
	gnutls_pkcs12_bag_type type;
} gnutls_pkcs12_bag_int;

typedef struct gnutls_pkcs12_int *gnutls_pkcs12;
typedef struct gnutls_pkcs12_bag_int *gnutls_pkcs12_bag;

int gnutls_pkcs12_init(gnutls_pkcs12 * pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12 pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12 pkcs12, const gnutls_datum * data,
	gnutls_x509_crt_fmt format, const char* password, unsigned int flags);

int gnutls_pkcs12_get_bag(gnutls_pkcs12 pkcs12, 
	int indx, gnutls_pkcs12_bag bag);

int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag * bag);
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag bag);

int 
_pkcs12_string_to_key (int id, const char *salt, int salt_size, int iter, const char *pw,
               int req_keylen, unsigned char *keybuf);
