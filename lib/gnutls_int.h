/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GNUTLS_INT_H

#define GNUTLS_INT_H

#include <defines.h>

/*
#define READ_DEBUG
#define WRITE_DEBUG
#define HARD_DEBUG
#define BUFFERS_DEBUG
#define RECORD_DEBUG*/
#define HANDSHAKE_DEBUG
#define DEBUG


#define SOCKET int
#define LIST ...

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

#define TLS_RANDOM_SIZE 32
#define TLS_MAX_SESSION_ID_SIZE 32
#define TLS_MASTER_SIZE 48
#define MAX_HASH_SIZE 20

#define MAX_X509_CERT_SIZE 10*1024
#define MAX_LOG_SIZE 1024 /* maximum number of log message */

#define MAX_DNSNAME_SIZE 256

/* the default for TCP */
#define DEFAULT_LOWAT 1

/* expire time for resuming sessions */
#define DEFAULT_EXPIRE_TIME 3600

/* the maximum size of encrypted packets */
#define MAX_ENC_LEN 16384
#define HEADER_SIZE 5
#define MAX_RECV_SIZE 18432+HEADER_SIZE 	/* 2^14+2048+HEADER_SIZE */

/* X509 - also in gnutls.h.in */
#define X509_CN_SIZE 256
#define X509_C_SIZE 3
#define X509_O_SIZE 256
#define X509_OU_SIZE 256
#define X509_L_SIZE 256
#define X509_S_SIZE 256

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

#ifdef USE_GCRYPT
# include <gnutls_gcry.h>
#endif

/* these are to be implemented
 */
#define svoid void /* for functions that allocate using secure_free */
#define secure_free gnutls_free
#define secure_malloc malloc
#define secure_realloc realloc
#define secure_calloc calloc
#define gnutls_malloc malloc
#define gnutls_realloc realloc
#define gnutls_calloc calloc
#define gnutls_free free
#define gnutls_strdup strdup

#define DECR_LEN(len, x) len-=x; if (len<0) {gnutls_assert(); return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;}

typedef unsigned char opaque;
typedef struct { opaque pint[3]; } uint24;

typedef enum crypt_algo { SRPSHA1_CRYPT, BLOWFISH_CRYPT=2 } crypt_algo;
typedef enum ChangeCipherSpecType { GNUTLS_TYPE_CHANGE_CIPHER_SPEC=1 } ChangeCipherSpecType;
typedef enum AlertLevel { GNUTLS_WARNING=1, GNUTLS_FATAL } AlertLevel;
typedef enum AlertDescription { GNUTLS_CLOSE_NOTIFY, GNUTLS_UNEXPECTED_MESSAGE=10, GNUTLS_BAD_RECORD_MAC=20,
			GNUTLS_DECRYPTION_FAILED, GNUTLS_RECORD_OVERFLOW,  GNUTLS_DECOMPRESSION_FAILURE=30,
			GNUTLS_HANDSHAKE_FAILURE=40, GNUTLS_BAD_CERTIFICATE=42, GNUTLS_UNSUPPORTED_CERTIFICATE,
			GNUTLS_CERTIFICATE_REVOKED, GNUTLS_CERTIFICATE_EXPIRED, GNUTLS_CERTIFICATE_UNKNOWN,
			GNUTLS_ILLEGAL_PARAMETER, GNUTLS_UNKNOWN_CA, GNUTLS_ACCESS_DENIED, GNUTLS_DECODE_ERROR=50,
			GNUTLS_DECRYPT_ERROR, GNUTLS_EXPORT_RESTRICTION=60, GNUTLS_PROTOCOL_VERSION=70,
			GNUTLS_INSUFFICIENT_SECURITY, GNUTLS_INTERNAL_ERROR=80, GNUTLS_USER_CANCELED=90,
			GNUTLS_NO_RENEGOTIATION=100
			} AlertDescription;
typedef enum CertificateStatus { GNUTLS_CERT_TRUSTED=1, GNUTLS_CERT_NOT_TRUSTED, GNUTLS_CERT_EXPIRED, GNUTLS_CERT_INVALID } CertificateStatus;
		
typedef enum HandshakeType { GNUTLS_HELLO_REQUEST, GNUTLS_CLIENT_HELLO, GNUTLS_SERVER_HELLO,
		     GNUTLS_CERTIFICATE=11, GNUTLS_SERVER_KEY_EXCHANGE,
		     GNUTLS_CERTIFICATE_REQUEST, GNUTLS_SERVER_HELLO_DONE,
		     GNUTLS_CERTIFICATE_VERIFY, GNUTLS_CLIENT_KEY_EXCHANGE,
		     GNUTLS_FINISHED=20 } HandshakeType;
			

typedef struct {
	ChangeCipherSpecType type;
} ChangeCipherSpec;

typedef struct {
	opaque * data;
	int size;
} gnutls_datum;

typedef struct {
	AlertLevel level;
	AlertDescription description;
} Alert;


/* STATE */
typedef enum ConnectionEnd { GNUTLS_SERVER=1, GNUTLS_CLIENT } ConnectionEnd;
typedef enum BulkCipherAlgorithm { GNUTLS_NULL_CIPHER=1, GNUTLS_ARCFOUR, GNUTLS_3DES_CBC, GNUTLS_RIJNDAEL_CBC, GNUTLS_TWOFISH_CBC, GNUTLS_RIJNDAEL256_CBC } BulkCipherAlgorithm;
typedef enum Extensions { GNUTLS_EXTENSION_DNSNAME=0, GNUTLS_EXTENSION_SRP=6 } Extensions;
typedef enum KXAlgorithm { GNUTLS_KX_RSA=1, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DH_DSS, GNUTLS_KX_DH_RSA, GNUTLS_KX_DH_ANON, GNUTLS_KX_SRP } KXAlgorithm;
typedef enum CredType { GNUTLS_X509PKI=1, GNUTLS_ANON, GNUTLS_SRP } CredType;
typedef enum CipherType { CIPHER_STREAM, CIPHER_BLOCK } CipherType;
typedef enum MACAlgorithm { GNUTLS_NULL_MAC=1, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA } MACAlgorithm;
typedef enum CompressionMethod { GNUTLS_NULL_COMPRESSION=1, GNUTLS_ZLIB } CompressionMethod;

typedef enum ValidSession { VALID_TRUE, VALID_FALSE } ValidSession;
typedef enum ResumableSession { RESUME_TRUE, RESUME_FALSE } ResumableSession;


/* STATE (stop) */

typedef struct {
	KXAlgorithm algorithm;
	void* credentials;
	void* next;
} AUTH_CRED;


typedef struct {
	uint8 major;
	uint8 minor;
} ProtocolVersion;

typedef struct {
	/* For DH KX */
	gnutls_datum			key;
	MPI				KEY;
	MPI				client_Y;
	MPI				client_g;
	MPI				client_p;
	MPI				dh_secret;
	/* for SRP */
	MPI				A;
	MPI				B;
	MPI				u;
	MPI				b;
	MPI				a;
	MPI				x;
	/* RSA: 
	 * modulus is A
	 * exponent is B
	 * private key is u;
	 */
	
	/* this is used to hold the peers authentication data 
	 */
	/* AUTH_INFO structures MUST NOT contain malloced 
	 * elements.
	 */
	void*				auth_info;
	int				auth_info_size; /* needed in order to store to db for restoring 
							 */
	uint8				crypt_algo;

	/* These are needed in RSA and DH signature calculation 
	 */
	opaque				server_random[TLS_RANDOM_SIZE];
	opaque				client_random[TLS_RANDOM_SIZE];
	ProtocolVersion			version;
	
	AUTH_CRED*			cred; /* used to specify keys/certificates etc */
} GNUTLS_KEY_A;
typedef GNUTLS_KEY_A* GNUTLS_KEY;


/* STATE (cont) */

#include <gnutls_hash_int.h>
#include <gnutls_cipher_int.h>
#include <gnutls_auth.h>

typedef struct {
	uint8 CipherSuite[2];
} GNUTLS_CipherSuite;

/* This structure holds parameters got from TLS extension
 * mechanism. (some extensions may hold parameters in AUTH_INFO
 * structures instead - see SRP).
 */
typedef struct {
	opaque dnsname[MAX_DNSNAME_SIZE];
} TLSExtensions;

/* AUTH_INFO structures MUST NOT contain malloced 
 * elements.
 */
 
/* This structure and AUTH_INFO, are stored in the resume database,
 * and are restored, in case of resume.
 * Holds all the required parameters to resume the current 
 * state.
 */

/* if you add anything in Security_Parameters struct, then
 * also modify CPY_COMMON in gnutls_constate.c
 */
typedef struct {
	ConnectionEnd entity;
	KXAlgorithm kx_algorithm;
	/* we've got separate write/read bulk/macs because
	 * there is a time in handshake where the peer has
	 * null cipher and we don't
	 */
	BulkCipherAlgorithm read_bulk_cipher_algorithm;
	MACAlgorithm read_mac_algorithm;
	CompressionMethod read_compression_algorithm;

	BulkCipherAlgorithm write_bulk_cipher_algorithm;
	MACAlgorithm write_mac_algorithm;
	CompressionMethod write_compression_algorithm;

	/* this is the ciphersuite we are going to use 
	 * moved here from gnutls_internals in order to be restored
	 * on resume;
	 */
	GNUTLS_CipherSuite	current_cipher_suite;
	opaque 			master_secret[TLS_MASTER_SIZE];
	opaque 			client_random[TLS_RANDOM_SIZE];
	opaque 			server_random[TLS_RANDOM_SIZE];
	opaque 			session_id[TLS_MAX_SESSION_ID_SIZE];
	uint8 			session_id_size;
	time_t 			timestamp;
	TLSExtensions		extensions;
} SecurityParameters;

/* This structure holds the generated keys
 */
typedef struct {
	gnutls_datum server_write_mac_secret;
	gnutls_datum client_write_mac_secret;
	gnutls_datum server_write_IV;
	gnutls_datum client_write_IV;
	gnutls_datum server_write_key;
	gnutls_datum client_write_key;
	int	     generated_keys; /* zero if keys have not
				      * been generated. Non zero
				      * otherwise.
				      */
} CipherSpecs;

/* Versions should be in order of the oldest
 * (eg. SSL3 is before TLS1)
 */
typedef enum GNUTLS_Version { GNUTLS_SSL3=1, GNUTLS_TLS1, GNUTLS_VERSION_UNKNOWN=0xff } GNUTLS_Version;

typedef struct {
	GNUTLS_Version	version;
	GNUTLS_CIPHER_HANDLE write_cipher_state;
	GNUTLS_CIPHER_HANDLE read_cipher_state;
	gnutls_datum 	read_mac_secret;
	gnutls_datum 	write_mac_secret;
	uint64		read_sequence_number;
	uint64		write_sequence_number;
} ConnectionState;


typedef struct {
	int* algorithm_priority;
	int algorithms;
} GNUTLS_Priority;

#define BulkCipherAlgorithm_Priority GNUTLS_Priority
#define MACAlgorithm_Priority GNUTLS_Priority
#define KXAlgorithm_Priority GNUTLS_Priority
#define CompressionMethod_Priority GNUTLS_Priority
#define Protocol_Priority GNUTLS_Priority

typedef struct {
	gnutls_datum			buffer;
	gnutls_datum			hash_buffer; /* used to keep all handshake messages */
	gnutls_datum			buffer_handshake; /* this is a buffer that holds the current handshake message */
	ResumableSession		resumable; /* TRUE or FALSE - if we can resume that session */
	ValidSession			valid_connection; /* true or FALSE - if this session is valid */
	AlertDescription		last_alert; /* last alert received */
	/* this is the compression method we are going to use */
	CompressionMethod		compression_method;
	/* priorities */
	BulkCipherAlgorithm_Priority	BulkCipherAlgorithmPriority;
	MACAlgorithm_Priority		MACAlgorithmPriority;
	KXAlgorithm_Priority		KXAlgorithmPriority;
	CompressionMethod_Priority	CompressionMethodPriority;
	Protocol_Priority		ProtocolPriority;
	
	/* resumed session */
	ResumableSession		resumed; /* TRUE or FALSE - if we are resuming a session */
	SecurityParameters		resumed_security_parameters;

	int				certificate_requested; /* non zero if client certificate was requested */
	/* sockets internals */
	int				lowat;
	/* gdbm */
	char*				db_name;
	int				expire_time;
	MOD_AUTH_STRUCT*		auth_struct; /* used in handshake packets and KX algorithms */
	int				v2_hello; /* set 0 normally - 1 if v2 hello was received - server side only */
#ifdef HAVE_LIBGDBM
	GDBM_FILE			db_reader;
#endif
} GNUTLS_INTERNALS;

typedef struct {
	SecurityParameters security_parameters;
	CipherSpecs cipher_specs;
	ConnectionState connection_state;
	GNUTLS_INTERNALS gnutls_internals;
	GNUTLS_KEY gnutls_key;
} GNUTLS_STATE_INT;

typedef GNUTLS_STATE_INT *GNUTLS_STATE;


/* Record Protocol */
typedef enum ContentType { GNUTLS_CHANGE_CIPHER_SPEC=20, GNUTLS_ALERT, GNUTLS_HANDSHAKE,
		GNUTLS_APPLICATION_DATA } ContentType;


/* functions */
int _gnutls_send_alert( SOCKET cd, GNUTLS_STATE state, AlertLevel level, AlertDescription desc);
int gnutls_close(SOCKET cd, GNUTLS_STATE state);
svoid *gnutls_PRF( opaque * secret, int secret_size, uint8 * label,
		  int label_size, opaque * seed, int seed_size,
		  int total_bytes);
void _gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version);
GNUTLS_Version gnutls_get_current_version(GNUTLS_STATE state);
ssize_t gnutls_send_int(SOCKET cd, GNUTLS_STATE state, ContentType type, HandshakeType htype, const void* data, size_t sizeofdata, int flags);
ssize_t gnutls_recv_int(SOCKET cd, GNUTLS_STATE state, ContentType type, HandshakeType, char* data, size_t sizeofdata, int flags);
int _gnutls_send_change_cipher_spec(SOCKET cd, GNUTLS_STATE state);
int _gnutls_version_cmp(GNUTLS_Version ver1, GNUTLS_Version ver2);
#define _gnutls_version_ssl3(x) _gnutls_version_cmp(x, GNUTLS_SSL3)

#endif /* GNUTLS_INT_H */
