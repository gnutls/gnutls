#define svoid void /* for functions that allocate using secure_free */
#define secure_free free
#define secure_malloc malloc
#define secure_realloc realloc
#define secure_calloc calloc
#define gnutls_malloc malloc
#define gnutls_realloc realloc
#define gnutls_calloc calloc
#define gnutls_free free

#define rotl64(x,n)   (((x) << ((uint16)(n))) | ((x) >> (64 - (uint16)(n))))
#define rotr64(x,n)   (((x) >> ((uint16)(n))) | ((x) << (64 - (uint16)(n))))
#define rotl32(x,n)   (((x) << ((uint16)(n))) | ((x) >> (32 - (uint16)(n))))
#define rotr32(x,n)   (((x) >> ((uint16)(n))) | ((x) << (32 - (uint16)(n))))
#define rotl16(x,n)   (((x) << ((uint16)(n))) | ((x) >> (16 - (uint16)(n))))
#define rotr16(x,n)   (((x) >> ((uint16)(n))) | ((x) << (16 - (uint16)(n))))

#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))
#define byteswap32(x)  ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
#define byteswap64(x)  ((rotl64(x, 8) & 0x00ff00ff00ff00ff) | (rotr64(x, 8) & 0xff00ff00ff00ff00))

typedef unsigned char opaque;

/* STATE */
enum ConnectionEnd { GNUTLS_SERVER, GNUTLS_CLIENT };
enum BulkCipherAlgorithm { CIPHER_NULL, CIPHER_3DES = 4 };
enum CipherType { CIPHER_STREAM, CIPHER_BLOCK };
enum IsExportable { EXPORTABLE_TRUE, EXPORTABLE_FALSE };
enum MACAlgorithm { MAC_NULL, MAC_MD5, MAC_SHA };
enum CompressionMethod { COMPRESSION_NULL };


typedef enum ConnectionEnd ConnectionEnd;
typedef enum BulkCipherAlgorithm BulkCipherAlgorithm;
typedef enum CipherType CipherType;
typedef enum IsExportable IsExportable;
typedef enum MACAlgorithm MACAlgorithm;
typedef enum CompressionMethod CompressionMethod;

typedef struct {
	ConnectionEnd entity;
	BulkCipherAlgorithm bulk_cipher_algorithm;
	CipherType cipher_type;
	uint8 IV_size;   /* not specified in the protocol, but later it
			  * uses it */
	uint8 key_size;
	uint8 key_material_length;
	IsExportable is_exportable;
	MACAlgorithm mac_algorithm;
	uint8 hash_size;
	CompressionMethod compression_algorithm;
	opaque master_secret[48];
	opaque client_random[32];
	opaque server_random[32];
} SecurityParameters;

typedef struct {
	opaque* server_write_mac_secret;
	opaque* client_write_mac_secret;
	opaque* server_write_IV;
	opaque* client_write_IV;
	opaque* server_write_key;
	opaque* client_write_key;
} CipherSpecs;

typedef struct {
	opaque* compression_state;
	GCRY_CIPHER_HD cipher_state;
	opaque* mac_secret;
	uint8   mac_secret_size;
	uint64	read_sequence_number;
	uint64	write_sequence_number;
} ConnectionState;

typedef struct {
	SecurityParameters security_parameters;
	CipherSpecs cipher_specs;
	ConnectionState connection_state;
} GNUTLS_STATE_INT;

typedef GNUTLS_STATE_INT *GNUTLS_STATE;


/* Record Protocol */
enum ContentType { GNUTLS_CHANGE_CIPHER_SPEC=20, GNUTLS_ALERT, GNUTLS_HANDSHAKE,
		GNUTLS_APPLICATION_DATA };
typedef enum ContentType ContentType;

#define GNUTLS_VERSION_MAJOR 3
#define GNUTLS_VERSION_MINOR 1

typedef struct {
	uint8 major;
	uint8 minor;
} ProtocolVersion;

typedef struct {
	ContentType	type;
	ProtocolVersion	version;
	uint16		length;
	opaque*		fragment;
} GNUTLSPlaintext;

typedef struct {
	ContentType	type;
	ProtocolVersion	version;
	uint16		length;
	opaque*		fragment;
} GNUTLSCompressed;

/* This is used for both block ciphers and stream ciphers. In stream ciphers
 * the padding is just ignored.
 */
typedef struct {
	opaque*		content;
	opaque*		MAC;
	uint8*		padding;
	uint8		padding_length;
} GNUTLS_GenericBlockCipher;

typedef struct {
	opaque*		content;
	opaque*		MAC;
} GNUTLS_GenericStreamCipher;

typedef struct {
	ContentType		type;
	ProtocolVersion		version;
	uint16			length;
	void*			fragment; /* points GenericStreamCipher
					   * or GenericBlockCipher
					   */
} GNUTLSCiphertext;


int gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, char* data, int sizeofdata);
#define gnutls_send( x, y, z, w) gnutls_send_int( x, y, GNUTLS_APPLICATION_DATA, z, w)

#define	GNUTLS_E_MAC_FAILED -1
#define	GNUTLS_E_UNKNOWN_CIPHER -2
#define	GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define	GNUTLS_E_UNKNOWN_MAC_ALGORITHM -4
#define	GNUTLS_E_UNKNOWN_ERROR -5
#define	GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define	GNUTLS_E_LARGE_PACKET -7
	
