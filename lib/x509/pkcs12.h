
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

struct bag_element {
	gnutls_datum data;
	gnutls_pkcs12_bag_type type;
	gnutls_datum local_key_id;
	char * friendly_name;
};

typedef struct gnutls_pkcs12_bag_int {
	struct bag_element element[MAX_BAG_ELEMENTS];
	int bag_elements;
} gnutls_pkcs12_bag_int;

#define BAG_PKCS8_KEY "1.2.840.113549.1.12.10.1.1"
#define BAG_PKCS8_ENCRYPTED_KEY "1.2.840.113549.1.12.10.1.2"
#define BAG_CERTIFICATE "1.2.840.113549.1.12.10.1.3"
#define BAG_CRL "1.2.840.113549.1.12.10.1.4"

/* PKCS #7
 */
#define DATA_OID "1.2.840.113549.1.7.1"
#define ENC_DATA_OID "1.2.840.113549.1.7.6"

/* Bag attributes
 */
#define FRIENDLY_NAME_OID "1.2.840.113549.1.9.20"
#define KEY_ID_OID "1.2.840.113549.1.9.21"

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

int _gnutls_pkcs7_decrypt_data( const gnutls_datum* data,
        const char* password, gnutls_datum* dec);

typedef enum schema_id {
	PBES2,			/* the stuff in PKCS #5 */
	PKCS12_3DES_SHA1, /* the fucking stuff in PKCS #12 */
	PKCS12_ARCFOUR_SHA1
} schema_id;

int _gnutls_pkcs7_encrypt_data(schema_id schema, const gnutls_datum * data,
					      const char *password,
					      gnutls_datum * enc);
int _pkcs12_decode_safe_contents( const gnutls_datum* content, gnutls_pkcs12_bag bag);
int _pkcs12_check_pass( const char* pass, size_t plen);

int
_pkcs12_encode_safe_contents( gnutls_pkcs12_bag bag, ASN1_TYPE* content, int *enc);

int _pkcs12_decode_crt_bag( gnutls_pkcs12_bag_type type, const gnutls_datum* in,
		gnutls_datum* out);
int _pkcs12_encode_crt_bag( gnutls_pkcs12_bag_type type, const gnutls_datum* raw,
		gnutls_datum* out);
