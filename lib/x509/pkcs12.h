
typedef struct gnutls_pkcs12_int {
	ASN1_TYPE pkcs12;
} gnutls_pkcs12_int;

typedef enum gnutls_pkcs12_bag_type {
	GNUTLS_BAG_EMPTY = 0,

	GNUTLS_BAG_PKCS8_ENCRYPTED_KEY=1,
	GNUTLS_BAG_PKCS8_KEY,
	GNUTLS_BAG_CERTIFICATE,
	GNUTLS_BAG_CRL,
	GNUTLS_BAG_ENCRYPTED=10,
	GNUTLS_BAG_UNKNOWN=20
} gnutls_pkcs12_bag_type;

#define MAX_BAG_ELEMENTS 32

typedef struct gnutls_pkcs12_bag_int {
	gnutls_datum data[MAX_BAG_ELEMENTS];
	gnutls_pkcs12_bag_type type[MAX_BAG_ELEMENTS];
	int bag_elements;
} gnutls_pkcs12_bag_int;

#define BAG_PKCS8_KEY "1.2.840.113549.1.12.10.1.1"
#define BAG_PKCS8_ENCRYPTED_KEY "1.2.840.113549.1.12.10.1.2"
#define BAG_CERTIFICATE "1.2.840.113549.1.12.10.1.3"
#define BAG_CRL "1.2.840.113549.1.12.10.1.4"

typedef struct gnutls_pkcs12_int *gnutls_pkcs12;
typedef struct gnutls_pkcs12_bag_int *gnutls_pkcs12_bag;

int gnutls_pkcs12_init(gnutls_pkcs12 * pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12 pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12 pkcs12, const gnutls_datum * data,
	gnutls_x509_crt_fmt format, unsigned int flags);

int gnutls_pkcs12_get_bag(gnutls_pkcs12 pkcs12, 
	int indx, gnutls_pkcs12_bag bag);

int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag * bag);
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag bag);

int 
_pkcs12_string_to_key (unsigned int id, const opaque *salt, unsigned int salt_size, 
	unsigned int iter, const char *pw,
	unsigned int req_keylen, opaque *keybuf);

int _gnutls_x509_decrypt_pkcs7_encrypted_data( const gnutls_datum* data,
        const char* password, gnutls_datum* dec);
int _pkcs12_decode_safe_contents( const gnutls_datum* content, gnutls_pkcs12_bag bag);
int _pkcs12_check_pass( const char* pass, size_t plen);
