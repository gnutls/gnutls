#ifndef GNUTLS_INT_H

#define GNUTLS_INT_H

/*
#define HANDSHAKE_DEBUG
#define READ_DEBUG
#define WRITE_DEBUG
#define HARD_DEBUG
#define DEBUG
*/

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

/* the maximum size of encrypted packets */
#define MAX_ENC_LEN 16384
#define HEADER_SIZE 5
#define MAX_RECV_SIZE 18432+HEADER_SIZE 	/* 2^14+2048+HEADER_SIZE */

/* for big numbers support */ /* FIXME */
#include <gcrypt.h>

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

#define GNUTLS_MPI MPI
#define gnutls_mpi_release mpi_release

#define svoid void /* for functions that allocate using secure_free */
#define secure_free gnutls_free
#define secure_malloc malloc
#define secure_realloc realloc
#define secure_calloc calloc
#define gnutls_malloc malloc
#define gnutls_realloc realloc
#define gnutls_calloc calloc

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
enum AlertLevel { GNUTLS_WARNING=1, GNUTLS_FATAL };
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
enum BulkCipherAlgorithm { GNUTLS_NULL_CIPHER, GNUTLS_ARCFOUR=1, GNUTLS_3DES = 4, GNUTLS_RIJNDAEL, GNUTLS_TWOFISH };
enum KXAlgorithm { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DH_DSS, GNUTLS_KX_DH_RSA, GNUTLS_KX_ANON_DH };
enum KeyExchangeAlgorithm { GNUTLS_RSA, GNUTLS_DIFFIE_HELLMAN };
enum CipherType { CIPHER_STREAM, CIPHER_BLOCK };
enum MACAlgorithm { GNUTLS_NULL_MAC, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA };
enum CompressionMethod { GNUTLS_NULL_COMPRESSION, GNUTLS_ZLIB=224 };

enum ValidSession { VALID_TRUE, VALID_FALSE };
enum ResumableSession { RESUME_TRUE, RESUME_FALSE };

typedef enum KeyExchangeAlgorithm KeyExchangeAlgorithm;
typedef enum KXAlgorithm KXAlgorithm;
typedef enum ValidSession ValidSession;
typedef enum ResumableSession ResumableSession;
typedef enum ConnectionEnd ConnectionEnd;
typedef enum BulkCipherAlgorithm BulkCipherAlgorithm;
typedef enum CipherType CipherType;
typedef enum MACAlgorithm MACAlgorithm;
typedef enum CompressionMethod CompressionMethod;

#include <gnutls_hash_int.h>
#include <gnutls_cipher_int.h>

typedef struct {
	ConnectionEnd entity;
	BulkCipherAlgorithm bulk_cipher_algorithm;
	CipherType cipher_type;
	MACAlgorithm mac_algorithm;
	CompressionMethod compression_algorithm;
	uint8 IV_size;
	uint8 key_size;
	uint8 key_material_length;
	uint8 hash_size;
	opaque master_secret[48];
	opaque client_random[32];
	opaque server_random[32];
	opaque session_id[32];
	uint8 session_id_size;
	time_t timestamp;
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
	uint8 local;
	uint8 major;
	uint8 minor;
} GNUTLS_Version;

extern GNUTLS_Version GNUTLS_TLS1;
extern GNUTLS_Version GNUTLS_SSL3;

typedef struct {
	GNUTLS_Version version;
	opaque* 	read_compression_state;
	opaque* 	write_compression_state;
	GNUTLS_CIPHER_HANDLE write_cipher_state;
	GNUTLS_CIPHER_HANDLE read_cipher_state;
	opaque* 	read_mac_secret;
	opaque* 	write_mac_secret;
	uint8   	mac_secret_size;
	uint64	read_sequence_number;
	uint64	write_sequence_number;
} ConnectionState;

typedef struct {
	uint8 CipherSuite[2];
} GNUTLS_CipherSuite;

typedef struct {
	int* algorithm_priority;
	int algorithms;
} GNUTLS_Priority;

#define BulkCipherAlgorithm_Priority GNUTLS_Priority
#define MACAlgorithm_Priority GNUTLS_Priority
#define KXAlgorithm_Priority GNUTLS_Priority
#define CompressionMethod_Priority GNUTLS_Priority

typedef struct {
	char*			buffer;
	uint32			bufferSize;
	char*			hash_buffer; /* used to keep all handshake messages */
	uint32			hash_bufferSize;
	char*			buffer_handshake; /* this is a buffer that holds the current handshake message */
	uint32			bufferSize_handshake;
	ResumableSession	resumable; /* TRUE or FALSE - if we can resume that session */
	ValidSession		valid_connection; /* true or FALSE - if this session is valid */
	AlertDescription	last_alert; /* last alert received */
	/* this is the ciphersuite we are going to use */
	GNUTLS_CipherSuite	current_cipher_suite;
	/* this is the compression method we are going to use */
	CompressionMethod	compression_method;
	/* priorities */
	BulkCipherAlgorithm_Priority	BulkCipherAlgorithmPriority;
	MACAlgorithm_Priority		MACAlgorithmPriority;
	KXAlgorithm_Priority		KXAlgorithmPriority;
	CompressionMethod_Priority	CompressionMethodPriority;
	/* resumed session */
	ResumableSession	resumed; /* TRUE or FALSE - if we are resuming a session */
	SecurityParameters  resumed_security_parameters;
	/* For DH KX */
	MPI				KEY;
	MPI				client_Y;
	MPI				client_g;
	MPI				client_p;
	MPI				dh_secret;
	int				certificate_requested; /* non zero if client certificate was requested */
	int				certificate_verify_needed; /* non zero if we should expect for certificate verify */
	/* sockets internals */
	int				lowat;
	/* gdbm */
	char*				db_name;
	int				expire_time;
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

typedef struct {
	uint8 major;
	uint8 minor;
} ProtocolVersion;

typedef struct {
	uint8		type;
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
	uint8			type;
	ProtocolVersion	version;
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
	ProtocolVersion	client_version;
	GNUTLS_random		random;
	opaque*			session_id;
	GNUTLS_CipherSuite*	cipher_suites;
	CompressionMethod*	compression_methods;
} GNUTLS_ClientHello;

typedef struct {
	ProtocolVersion	server_version;
	GNUTLS_random		random;
	opaque*			session_id;
	GNUTLS_CipherSuite	cipher_suite;
	CompressionMethod	compression_method;
} GNUTLS_ServerHello;

/* functions */
void gnutls_free(void* ptr);
int _gnutls_send_alert( int cd, GNUTLS_STATE state, AlertLevel level, AlertDescription desc);
int gnutls_close(int cd, GNUTLS_STATE state);
svoid *gnutls_PRF( opaque * secret, int secret_size, uint8 * label,
		  int label_size, opaque * seed, int seed_size,
		  int total_bytes);
void gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version);
GNUTLS_Version gnutls_get_current_version(GNUTLS_STATE state);
int _gnutls_set_keys(GNUTLS_STATE state);
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, void* data, size_t sizeofdata, int flags);
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata, int flags);
int _gnutls_send_change_cipher_spec(int cd, GNUTLS_STATE state);
int _gnutls_version_cmp(GNUTLS_Version ver1, GNUTLS_Version ver2);
#define _gnutls_version_ssl3(x) _gnutls_version_cmp(x, GNUTLS_SSL3)

#endif /* GNUTLS_INT_H */
