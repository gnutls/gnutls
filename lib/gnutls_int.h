#include <gcrypt.h>

#define HARD_DEBUG
#define DEBUG

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

/* for message digests */
#define GNUTLS_HASH_HANDLE GCRY_MD_HD
#define GNUTLS_MAC_HANDLE GCRY_MD_HD
#define GNUTLS_HASH_FAILED NULL
#define GNUTLS_MAC_FAILED NULL

/* for symmetric ciphers */
#define GNUTLS_CIPHER_HANDLE GCRY_CIPHER_HD
#define GNUTLS_CIPHER_FAILED NULL

/* for big numbers support */ /* FIXME */
#define GNUTLS_MPI MPI
#define gnutls_mpi_release mpi_release

#define svoid void /* for functions that allocate using secure_free */
#define secure_free(x) if (x!=NULL) free(x)
#define secure_malloc malloc
#define secure_realloc realloc
#define secure_calloc calloc
#define gnutls_malloc malloc
#define gnutls_realloc realloc
#define gnutls_calloc calloc
#define gnutls_free(x) if (x!=NULL) free(x)

typedef struct {
	uint8	pint[3];
} uint24;

#define rotl64(x,n)   (((x) << ((uint16)(n))) | ((x) >> (64 - (uint16)(n))))
#define rotr64(x,n)   (((x) >> ((uint16)(n))) | ((x) << (64 - (uint16)(n))))
#define rotl32(x,n)   (((x) << ((uint16)(n))) | ((x) >> (32 - (uint16)(n))))
#define rotr32(x,n)   (((x) >> ((uint16)(n))) | ((x) << (32 - (uint16)(n))))
#define rotl16(x,n)   (((x) << ((uint16)(n))) | ((x) >> (16 - (uint16)(n))))
#define rotr16(x,n)   (((x) >> ((uint16)(n))) | ((x) << (16 - (uint16)(n))))

#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))
#define byteswap32(x)  ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
#define byteswap64(x)  ((rotl64(x, 8) & 0x00ff00ff00ff00ffLL) | (rotr64(x, 8) & 0xff00ff00ff00ff00LL))

typedef unsigned char opaque;


enum ChangeCipherSpecType { GNUTLS_TYPE_CHANGE_CIPHER_SPEC=1 };
enum AlertLevel { GNUTLS_WARNING, GNUTLS_FATAL };
enum AlertDescription { GNUTLS_CLOSE_NOTIFY, GNUTLS_UNEXPECTED_MESSAGE=10, GNUTLS_BAD_RECORD_MAC=20,
			GNUTLS_DECRYPTION_FAILED, GNUTLS_RECORD_OVERFLOW,  GNUTLS_DECOMPRESSION_FAILURE=30,
			GNUTLS_HANDSHAKE_FAILURE=40, GNUTLS_BAD_CERTIFICATE=42, GNUTLS_UNSUPPORTED_CERTIFICATE,
			GNUTLS_CERTIFICATE_REVOKED, GNUTLS_CERTIFICATE_EXPIRED, GNUTLS_CERTIFICATE_UNKNOWN,
			GNUTLS_ILLEGAL_PARAMETER, GNUTLS_UNKNOWN_CA, GNUTLS_ACCESS_DENIED, GNUTLS_DECODE_ERROR=50,
			GNUTLS_DECRYPT_ERROR, GNUTLS_EXPORT_RESTRICTION=60, GNUTLS_PROTOCOL_VERSION=70,
			GNUTLS_INSUFFICIENT_SECURITY, GNUTLS_INTERNAL_ERROR=80, GNUTLS_USER_CANCELED=90,
			GNUTLS_NO_RENEGOTIATION=100
			};
			
typedef enum AlertDescription AlertDescription;
typedef enum AlertLevel AlertLevel;
typedef enum ChangeCipherSpecType ChangeCipherSpecType;

enum HandshakeType { GNUTLS_HELLO_REQUEST, GNUTLS_CLIENT_HELLO, GNUTLS_SERVER_HELLO,
		     GNUTLS_CERTIFICATE=11, GNUTLS_SERVER_KEY_EXCHANGE,
		     GNUTLS_CERTIFICATE_REQUEST, GNUTLS_SERVER_HELLO_DONE,
		     GNUTLS_CERTIFICATE_VERIFY, GNUTLS_CLIENT_KEY_EXCHANGE,
		     GNUTLS_FINISHED=20 };
			
typedef enum HandshakeType HandshakeType;


typedef struct {
	ChangeCipherSpecType type;
} ChangeCipherSpec;

typedef struct {
	AlertLevel level;
	AlertDescription description;
} Alert;


/* STATE */
enum ConnectionEnd { GNUTLS_SERVER, GNUTLS_CLIENT };
enum BulkCipherAlgorithm { GNUTLS_NULL, GNUTLS_ARCFOUR=1, GNUTLS_3DES = 4 };
enum KXAlgorithm { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DH_DSS, GNUTLS_KX_DH_RSA, GNUTLS_KX_ANON_DH };
enum KeyExchangeAlgorithm { GNUTLS_RSA, GNUTLS_DIFFIE_HELLMAN };
enum CipherType { CIPHER_STREAM, CIPHER_BLOCK };
enum IsExportable { EXPORTABLE_TRUE, EXPORTABLE_FALSE };
enum MACAlgorithm { GNUTLS_MAC_NULL, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA };
enum CompressionMethod { COMPRESSION_NULL };

enum ValidSession { VALID_TRUE, VALID_FALSE };
enum ResumableSession { RESUME_TRUE, RESUME_FALSE };

typedef enum KeyExchangeAlgorithm KeyExchangeAlgorithm;
typedef enum KXAlgorithm KXAlgorithm;
typedef enum ValidSession ValidSession;
typedef enum ResumableSession ResumableSession;
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
	uint8 major;
	uint8 minor;
} GNUTLS_Version;

typedef struct {
	GNUTLS_Version version;
	opaque* read_compression_state;
	opaque* write_compression_state;
	GNUTLS_CIPHER_HANDLE write_cipher_state;
	GNUTLS_CIPHER_HANDLE read_cipher_state;
	opaque* read_mac_secret;
	opaque* write_mac_secret;
	uint8   mac_secret_size;
	uint64	read_sequence_number;
	uint64	write_sequence_number;
} ConnectionState;

typedef struct {
	uint8 CipherSuite[2];
} GNUTLS_CipherSuite;


typedef struct {
	char*			buffer;
	uint32			bufferSize;
	char*			buffer_handshake;
	uint32			bufferSize_handshake;
	ResumableSession	resumable;
	ValidSession		valid_connection;
	AlertDescription	last_alert;
	GNUTLS_CipherSuite	current_cipher_suite;
	CompressionMethod	compression_method;
	/* for the handshake protocol */
	GNUTLS_HASH_HANDLE	client_td_md5;
	GNUTLS_HASH_HANDLE	client_td_sha1;
	void*			client_md_md5;
	void*			client_md_sha1;
	GNUTLS_HASH_HANDLE	server_td_md5;
	GNUTLS_HASH_HANDLE	server_td_sha1;
	void*			server_md_md5;
	void*			server_md_sha1;
	int			server_hash;
	int			client_hash;
	/* For DH KX */
	MPI			KEY;
	MPI			client_Y;
	MPI			client_g;
	MPI			client_p;
	MPI			dh_secret;
} GNUTLS_INTERNALS;

typedef struct {
	SecurityParameters security_parameters;
	CipherSpecs cipher_specs;
	ConnectionState connection_state;
	GNUTLS_INTERNALS gnutls_internals;
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
	uint8	type;
	ProtocolVersion	version;
	uint16		length;
	opaque*		fragment;
} GNUTLSPlaintext;

typedef struct {
	uint8	type;
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
	uint8		type;
	ProtocolVersion		version;
	uint16			length;
	void*			fragment; /* points GenericStreamCipher
					   * or GenericBlockCipher
					   */
} GNUTLSCiphertext;


/* Handshake protocol */


typedef struct {
	HandshakeType	msg_type;
	uint24		length;
	void*		body;
} GNUTLS_Handshake;

typedef struct {
	uint32	gmt_unix_time;
	opaque  random_bytes[28];
} GNUTLS_random;


typedef struct {
	ProtocolVersion		client_version;
	GNUTLS_random		random;
	opaque*			session_id;
	GNUTLS_CipherSuite*	cipher_suites;
	CompressionMethod*	compression_methods;
} GNUTLS_ClientHello;

typedef struct {
	ProtocolVersion		server_version;
	GNUTLS_random		random;
	opaque*			session_id;
	GNUTLS_CipherSuite	cipher_suite;
	CompressionMethod	compression_method;
} GNUTLS_ServerHello;

/* functions */
int _gnutls_send_alert( int cd, GNUTLS_STATE state, AlertLevel level, AlertDescription desc);
int gnutls_close(int cd, GNUTLS_STATE state);
svoid *gnutls_PRF(opaque * secret, int secret_size, uint8 * label,
		  int label_size, opaque * seed, int seed_size,
		  int total_bytes);
int _gnutls_valid_version( GNUTLS_STATE state, int major, int minor);
int _gnutls_set_keys(GNUTLS_STATE state);
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
int _gnutls_send_change_cipher_spec(int cd, GNUTLS_STATE state);
