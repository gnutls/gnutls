/*
 *  Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef GNUTLS_INT_H

#define GNUTLS_INT_H

#include <defines.h>

/*
 * They are not needed any more. You can simply enable
 * the gnutls_log callback to get error descriptions.

#define IO_DEBUG 3 // define this to check non blocking behaviour
#define BUFFERS_DEBUG
#define WRITE_DEBUG
#define READ_DEBUG
#define HANDSHAKE_DEBUG // Prints some information on handshake 
#define COMPRESSION_DEBUG
#define DEBUG
*/

/* It might be a good idea to replace int with void*
 * here.
 */
typedef int gnutls_transport_ptr;

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

/* The size of a handshake message should not
 * be larger than this value.
 */
#define MAX_HANDSHAKE_PACKET_SIZE 16*1024

#define TLS_RANDOM_SIZE 32
#define TLS_MAX_SESSION_ID_SIZE 32
#define TLS_MASTER_SIZE 48

/* The maximum digest size of hash algorithms. 
 */
#define MAX_HASH_SIZE 20

#define MAX_LOG_SIZE 1024 /* maximum number of log message */
#define MAX_SRP_USERNAME 128
#define MAX_SERVER_NAME_SIZE 128

/* we can receive up to MAX_EXT_TYPES extensions.
 */
#define MAX_EXT_TYPES 64

/* The initial size of the receive
 * buffer size. This will grow if larger
 * packets are received.
 */
#define INITIAL_RECV_BUFFER_SIZE 256

/* the default for TCP */
#define DEFAULT_LOWAT 1

/* expire time for resuming sessions */
#define DEFAULT_EXPIRE_TIME 3600

/* the maximum size of encrypted packets */
#define DEFAULT_MAX_RECORD_SIZE 16384
#define RECORD_HEADER_SIZE 5
#define MAX_RECORD_SEND_SIZE (size_t)session->security_parameters.max_record_send_size
#define MAX_RECORD_RECV_SIZE (size_t)session->security_parameters.max_record_recv_size
#define MAX_PAD_SIZE 255
#define EXTRA_COMP_SIZE 2048
#define MAX_RECORD_OVERHEAD MAX_PAD_SIZE+EXTRA_COMP_SIZE
#define MAX_RECV_SIZE MAX_RECORD_OVERHEAD+MAX_RECORD_RECV_SIZE+RECORD_HEADER_SIZE

#define HANDSHAKE_HEADER_SIZE 4

#include <gnutls_mem.h>
#include <gnutls_ui.h>

#define DECR_LEN(len, x) len-=x; if (len<0) {gnutls_assert(); return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;}
#define DECR_LENGTH_RET(len, x, RET) len-=x; if (len<0) {gnutls_assert(); return RET;}
#define DECR_LENGTH_COM(len, x, COM) len-=x; if (len<0) {gnutls_assert(); COM;}

typedef unsigned char opaque;
typedef struct { opaque pint[3]; } uint24;

#include <gnutls_mpi.h>

typedef enum ChangeCipherSpecType { GNUTLS_TYPE_CHANGE_CIPHER_SPEC=1 } ChangeCipherSpecType;

typedef enum gnutls_certificate_status { 
	GNUTLS_CERT_NOT_TRUSTED=2, 
	GNUTLS_CERT_INVALID=4, 
	GNUTLS_CERT_CORRUPTED=16,
	GNUTLS_CERT_REVOKED=32
} gnutls_certificate_status;

typedef enum gnutls_certificate_request { GNUTLS_CERT_IGNORE, GNUTLS_CERT_REQUEST=1, GNUTLS_CERT_REQUIRE } gnutls_certificate_request;

typedef enum gnutls_openpgp_key_status { GNUTLS_OPENPGP_KEY, 
	GNUTLS_OPENPGP_KEY_FINGERPRINT
} gnutls_openpgp_key_status;

typedef enum gnutls_close_request { GNUTLS_SHUT_RDWR=0, GNUTLS_SHUT_WR=1 } gnutls_close_request;

typedef enum HandshakeState { STATE0=0, STATE1, STATE2, STATE3, STATE4, STATE5,
	STATE6, STATE7, STATE8, STATE9, STATE20=20, STATE21,
	STATE30=30, STATE31, STATE50=50, STATE60=60, STATE61 } HandshakeState;

typedef enum HandshakeType { GNUTLS_HELLO_REQUEST, GNUTLS_CLIENT_HELLO, GNUTLS_SERVER_HELLO,
		     GNUTLS_CERTIFICATE_PKT=11, GNUTLS_SERVER_KEY_EXCHANGE,
		     GNUTLS_CERTIFICATE_REQUEST, GNUTLS_SERVER_HELLO_DONE,
		     GNUTLS_CERTIFICATE_VERIFY, GNUTLS_CLIENT_KEY_EXCHANGE,
		     GNUTLS_FINISHED=20 } HandshakeType;

typedef HandshakeType gnutls_handshake_description;

typedef struct {
	opaque * data;
	unsigned int size;
} gnutls_datum;

typedef struct {
	const opaque * data;
	unsigned int size;
} gnutls_const_datum;

#include <gnutls_buffer.h>

/* This is the maximum number of algorithms (ciphers or macs etc).
 * keep it synced with GNUTLS_MAX_ALGORITHM_NUM in gnutls.h
 */
#define MAX_ALGOS 10

#define MAX_CIPHERSUITES 256

/* STATE */

typedef enum gnutls_cipher_algorithm { GNUTLS_CIPHER_NULL=1, 
	GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_RIJNDAEL_128_CBC, 
	GNUTLS_CIPHER_TWOFISH_128_CBC, GNUTLS_CIPHER_RIJNDAEL_256_CBC,
	GNUTLS_CIPHER_ARCFOUR_40, 
	
	GNUTLS_CIPHER_RC2_128=90, GNUTLS_CIPHER_RC2_40,
	GNUTLS_CIPHER_DES_CBC
} gnutls_cipher_algorithm;

typedef enum gnutls_kx_algorithm { GNUTLS_KX_RSA=1, GNUTLS_KX_DHE_DSS, 
	GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, GNUTLS_KX_SRP,
	GNUTLS_KX_RSA_EXPORT, GNUTLS_KX_SRP_RSA, GNUTLS_KX_SRP_DSS
} gnutls_kx_algorithm;

typedef enum gnutls_mac_algorithm { GNUTLS_MAC_UNKNOWN=0, GNUTLS_MAC_NULL=1, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA } gnutls_mac_algorithm;
typedef gnutls_mac_algorithm gnutls_digest_algorithm;

typedef enum gnutls_compression_method { GNUTLS_COMP_NULL=1, GNUTLS_COMP_ZLIB,
	GNUTLS_COMP_LZO
} gnutls_compression_method;

typedef enum gnutls_connection_end { GNUTLS_SERVER=1, GNUTLS_CLIENT } gnutls_connection_end;

typedef enum Extensions { GNUTLS_EXTENSION_SERVER_NAME=0, 
   GNUTLS_EXTENSION_MAX_RECORD_SIZE=1, GNUTLS_EXTENSION_SRP=6, 
   GNUTLS_EXTENSION_CERT_TYPE=7 
} Extensions;

typedef enum gnutls_credentials_type { GNUTLS_CRD_CERTIFICATE=1, GNUTLS_CRD_ANON, GNUTLS_CRD_SRP } gnutls_credentials_type;

typedef enum gnutls_certificate_type { GNUTLS_CRT_X509=1, GNUTLS_CRT_OPENPGP 
} gnutls_certificate_type;

typedef enum CipherType { CIPHER_STREAM, CIPHER_BLOCK } CipherType;

typedef enum ValidSession { VALID_TRUE, VALID_FALSE } ValidSession;
typedef enum ResumableSession { RESUME_TRUE, RESUME_FALSE } ResumableSession;

/* Record Protocol */
typedef enum ContentType { GNUTLS_CHANGE_CIPHER_SPEC=20, GNUTLS_ALERT, 
	GNUTLS_HANDSHAKE, GNUTLS_APPLICATION_DATA 
} ContentType;

typedef enum gnutls_x509_crt_fmt { GNUTLS_X509_FMT_DER, 
	GNUTLS_X509_FMT_PEM } gnutls_x509_crt_fmt;

typedef enum gnutls_pk_algorithm { GNUTLS_PK_RSA = 1, GNUTLS_PK_DSA,
	GNUTLS_PK_UNKNOWN = 0xff
} gnutls_pk_algorithm;

/* STATE (stop) */


/* Pull & Push functions defines: 
 */
typedef ssize_t (*gnutls_pull_func)(gnutls_transport_ptr, void*, size_t);
typedef ssize_t (*gnutls_push_func)(gnutls_transport_ptr, const void*, size_t);

/* Store & Retrieve functions defines: 
 */
typedef int (*gnutls_db_store_func)(void*, gnutls_datum key, gnutls_datum data);
typedef int (*gnutls_db_remove_func)(void*, gnutls_datum key);
typedef gnutls_datum (*gnutls_db_retr_func)(void*, gnutls_datum key);

typedef struct AUTH_CRED {
	gnutls_kx_algorithm algorithm;
	/* the type of credentials depends on algorithm */
	void* credentials;
	struct AUTH_CRED* next;
} AUTH_CRED;


struct GNUTLS_KEY_INT {
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
	/* RSA: e, m
	 */
	MPI 				rsa[2];
	
	/* this is used to hold the peers authentication data 
	 */
	/* AUTH_INFO structures MAY contain malloced 
	 * elements. Check gnutls_session_pack.c, and gnutls_auth.c.
	 * Rememember that this should be calloced!
	 */
	void*				auth_info;
	gnutls_credentials_type		auth_info_type;
	int				auth_info_size; /* needed in order to store to db for restoring 
							 */
	uint8				crypt_algo;

	AUTH_CRED*			cred; /* used to specify keys/certificates etc */
	
	int				certificate_requested;
					/* some ciphersuites use this
					 * to provide client authentication.
					 * 1 if client auth was requested
					 * by the peer, 0 otherwise
					 *** In case of a server this
					 * holds 1 if we should wait
					 * for a client certificate verify
					 */
};
typedef struct GNUTLS_KEY_INT* GNUTLS_KEY;


/* STATE (cont) */

#include <gnutls_hash_int.h>
#include <gnutls_cipher_int.h>
#include <gnutls_compress_int.h>
#include <gnutls_cert.h>

typedef struct {
	uint8 CipherSuite[2];
} GNUTLS_CipherSuite;

/* Versions should be in order of the oldest
 * (eg. SSL3 is before TLS1)
 */
typedef enum gnutls_protocol_version { GNUTLS_SSL3=1, GNUTLS_TLS1, GNUTLS_VERSION_UNKNOWN=0xff } 
gnutls_protocol_version;

/* This structure holds parameters got from TLS extension
 * mechanism. (some extensions may hold parameters in AUTH_INFO
 * structures also - see SRP).
 */

typedef enum gnutls_server_name_type { GNUTLS_NAME_DNS=1 
} gnutls_server_name_type;

typedef struct {
   opaque name[MAX_SERVER_NAME_SIZE];
   int name_length;
   gnutls_server_name_type type;
} server_name_st;

#define MAX_SERVER_NAME_EXTENSIONS 3

typedef struct {
	server_name_st  server_names[MAX_SERVER_NAME_EXTENSIONS]; 
	                /* limit server_name extensions */
	int		server_names_size;
	opaque 		srp_username[MAX_SRP_USERNAME];
} TLSExtensions;

/* AUTH_INFO structures now MAY contain malloced 
 * elements.
 */
 
/* This structure and AUTH_INFO, are stored in the resume database,
 * and are restored, in case of resume.
 * Holds all the required parameters to resume the current 
 * session.
 */

/* if you add anything in Security_Parameters struct, then
 * also modify CPY_COMMON in gnutls_constate.c
 */

/* Note that the security parameters structure is set up after the
 * handshake has finished. The only value you may depend on while
 * the handshake is in progress is the cipher suite value.
 */
typedef struct {
	gnutls_connection_end entity;
	gnutls_kx_algorithm kx_algorithm;
	/* we've got separate write/read bulk/macs because
	 * there is a time in handshake where the peer has
	 * null cipher and we don't
	 */
	gnutls_cipher_algorithm read_bulk_cipher_algorithm;
	gnutls_mac_algorithm read_mac_algorithm;
	gnutls_compression_method read_compression_algorithm;

	gnutls_cipher_algorithm write_bulk_cipher_algorithm;
	gnutls_mac_algorithm write_mac_algorithm;
	gnutls_compression_method write_compression_algorithm;

	/* this is the ciphersuite we are going to use 
	 * moved here from internals in order to be restored
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

	/* The send size is the one requested by the programmer.
	 * The recv size is the one negotiated with the peer.
	 */
	uint16			max_record_send_size;
	uint16			max_record_recv_size;
	/* holds the negotiated certificate type */
	gnutls_certificate_type		cert_type;	
	gnutls_protocol_version		version; /* moved here */
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


typedef struct {
	GNUTLS_CIPHER_HANDLE write_cipher_state;
	GNUTLS_CIPHER_HANDLE read_cipher_state;
	GNUTLS_COMP_HANDLE   read_compression_state;
	GNUTLS_COMP_HANDLE   write_compression_state;
	gnutls_datum 	read_mac_secret;
	gnutls_datum 	write_mac_secret;
	uint64		read_sequence_number;
	uint64		write_sequence_number;
} ConnectionState;


typedef struct {
	unsigned int priority[MAX_ALGOS];
	unsigned int algorithms;
} GNUTLS_Priority;

typedef int certificate_client_select_func(struct gnutls_session_int*, 
	const gnutls_datum *, unsigned int, const gnutls_datum *, unsigned int);
typedef int certificate_server_select_func(struct gnutls_session_int*, 
	const gnutls_datum *, unsigned int);
typedef int srp_server_select_func(struct gnutls_session_int*, 
	const char**, const char**, unsigned int);

typedef struct {
	opaque				header[HANDSHAKE_HEADER_SIZE];
	/* this holds the number of bytes in the handshake_header[] */
	size_t				header_size;
	/* this holds the length of the handshake packet */
	size_t				packet_length;
	HandshakeType			recv_type;
} HANDSHAKE_HEADER_BUFFER;

/* Openpgp key retrieval callback */
typedef int (*gnutls_openpgp_recv_key_func)(struct gnutls_session_int*,
	const unsigned char *keyfpr, unsigned int keyfpr_length, gnutls_datum *);

typedef struct {
	gnutls_buffer			application_data_buffer; /* holds data to be delivered to application layer */
	gnutls_buffer			handshake_hash_buffer; /* used to keep the last received handshake 
								* message */
	GNUTLS_MAC_HANDLE		handshake_mac_handle_sha; /* hash of the handshake messages */
	GNUTLS_MAC_HANDLE		handshake_mac_handle_md5; /* hash of the handshake messages */

	gnutls_buffer			handshake_data_buffer; /* this is a buffer that holds the current handshake message */
	ResumableSession		resumable; /* TRUE or FALSE - if we can resume that session */
	HandshakeState			handshake_state; /* holds
					* a number which indicates where
					* the handshake procedure has been
					* interrupted. If it is 0 then
					* no interruption has happened.
					*/
	
	ValidSession			valid_connection; /* true or FALSE - if this session is valid */

	int				may_read; /* if it's 0 then we can read/write, otherwise it's forbiden to read/write
	                                           */
	int				may_write;

	int				last_alert; /* last alert received */

	/* The last handshake messages sent or received.
	 */
	int				last_handshake_in;
	int				last_handshake_out;

	/* this is the compression method we are going to use */
	gnutls_compression_method		compression_method;
	/* priorities */
	GNUTLS_Priority			cipher_algorithm_priority;
	GNUTLS_Priority			mac_algorithm_priority;
	GNUTLS_Priority			kx_algorithm_priority;
	GNUTLS_Priority			compression_method_priority;
	GNUTLS_Priority			protocol_priority;
	GNUTLS_Priority			cert_type_priority;

	/* resumed session */
	ResumableSession		resumed; /* RESUME_TRUE or FALSE - if we are resuming a session */
	SecurityParameters		resumed_security_parameters;

	/* sockets internals */
	int				lowat;

	/* These buffers are used in the handshake
	 * protocol only. freed using _gnutls_handshake_io_buffer_clear();
	 */
	gnutls_buffer 			handshake_send_buffer;
	size_t	 			handshake_send_buffer_prev_size;
	ContentType			handshake_send_buffer_type;
	HandshakeType			handshake_send_buffer_htype;
	ContentType			handshake_recv_buffer_type;
	HandshakeType			handshake_recv_buffer_htype;
	gnutls_buffer 			handshake_recv_buffer;
	
					/* this buffer holds a record packet -mostly used for
					 * non blocking IO.
					 */
	gnutls_buffer			record_recv_buffer;
	gnutls_buffer			record_send_buffer; /* holds cached data
					* for the gnutls_io_write_buffered()
					* function.
					*/ 
	size_t				record_send_buffer_prev_size; /* holds the
	                                * data written in the previous runs.
	                                */
	size_t				record_send_buffer_user_size; /* holds the
	                                * size of the user specified data to
	                                * send.
	                                */

					/* 0 if no peeked data was kept, 1 otherwise.
					 */
	int				have_peeked_data;

	int				expire_time; /* after expire_time seconds this session will expire */
	struct MOD_AUTH_STRUCT_INT*	auth_struct; /* used in handshake packets and KX algorithms */
	int				v2_hello; /* 0 if the client hello is v3+.
						   * non-zero if we got a v2 hello.
						   */
	/* keeps the headers of the handshake packet 
	 */
	HANDSHAKE_HEADER_BUFFER		handshake_header_buffer;

	/* this is the highest version available
	 * to the peer. (advertized version).
	 * This is obtained by the Handshake Client Hello 
	 * message. (some implementations read the Record version)
	 */
	uint8				adv_version_major;
	uint8				adv_version_minor;

	/* if this is non zero a certificate request message
	 * will be sent to the client. - only if the ciphersuite
	 * supports it.
	 */
	int				send_cert_req;

	/* this is a callback function to call if no appropriate
	 * client certificates were found.
	 */
	certificate_client_select_func*	client_cert_callback;
	certificate_server_select_func*	server_cert_callback;

	/* Callback to select the proper password file
	 */
	srp_server_select_func*		server_srp_callback;

	/* bits to use for DHE and DHA 
	 * use _gnutls_dh_get_prime_bits() and gnutls_dh_set_prime_bits() 
	 * to access it.
	 */
	uint16				dh_prime_bits;

	size_t				max_handshake_data_buffer_size;

	/* PUSH & PULL functions.
	 */
	gnutls_pull_func		_gnutls_pull_func;
	gnutls_push_func		_gnutls_push_func;
	/* Holds the first argument of PUSH and PULL
	 * functions;
	 */
	gnutls_transport_ptr		transport_recv_ptr;
	gnutls_transport_ptr		transport_send_ptr;

	/* STORE & RETRIEVE functions. Only used if other
	 * backend than gdbm is used.
	 */
	gnutls_db_store_func db_store_func;
	gnutls_db_retr_func db_retrieve_func;
	gnutls_db_remove_func db_remove_func;
	void* db_ptr;
	
	/* Holds the record size requested by the
	 * user.
	 */
	uint16			proposed_record_size;
	
	/* holds the index of the selected certificate.
	 * -1 if none.
	 */
	int			selected_cert_index; 
	
	/* holds the extensions we sent to the peer
	 * (in case of a client)
	 */
	uint16			extensions_sent[MAX_EXT_TYPES];
	uint16			extensions_sent_size;
	
	/* is 0 if we are to send the whole PGP key, or non zero
	 * if the fingerprint is to be sent.
	 */
	int			pgp_fingerprint;

	/* This holds the default version that our first
	 * record packet will have. */
	opaque			default_record_version[2];

	int			cbc_protection_hack;

	void*			user_ptr;

	int			enable_private;/* non zero to
						* enable cipher suites
						* which have 0xFF status.
						*/
	
	/* Holds 0 if the last called function was interrupted while
	 * receiving, and non zero otherwise.
	 */
	int			direction;
	
	/* This callback will be used (if set) to receive an
	 * openpgp key. (if the peer sends a fingerprint)
	 */
	gnutls_openpgp_recv_key_func openpgp_recv_key_func;
	
	/* If non zero the server will not advertize the CA's he
	 * trusts (do not send an RDN sequence).
	 */
	int			ignore_rdn_sequence;

	/* This is used to set an arbitary version in the RSA
	 * PMS secret. Can be used by clients to test whether the
	 * server checks that version.
	 */
	opaque			rsa_pms_version[2];

	/* If you add anything here, check _gnutls_handshake_internal_state_clear().
	 */
} GNUTLS_INTERNALS;

struct gnutls_session_int {
	SecurityParameters security_parameters;
	CipherSpecs cipher_specs;
	ConnectionState connection_state;
	GNUTLS_INTERNALS internals;
	GNUTLS_KEY key;
};

typedef struct gnutls_session_int *gnutls_session;

typedef struct {
	MPI _prime;
        MPI _generator;
} _gnutls_dh_params;

#define gnutls_dh_params _gnutls_dh_params*

#define gnutls_rsa_params gnutls_x509_privkey


/* functions */
void _gnutls_set_current_version(gnutls_session session, gnutls_protocol_version version);
gnutls_protocol_version gnutls_protocol_get_version(gnutls_session session);
void _gnutls_free_auth_info( gnutls_session session);

/* These two macros return the advertized TLS version of
 * the peer.
 */
#define _gnutls_get_adv_version_major( session) \
	session->internals.adv_version_major

#define _gnutls_get_adv_version_minor( session) \
	session->internals.adv_version_minor

#define set_adv_version( session, major, minor) \
	session->internals.adv_version_major = major; \
	session->internals.adv_version_minor = minor

void _gnutls_set_adv_version( gnutls_session, gnutls_protocol_version);
gnutls_protocol_version _gnutls_get_adv_version( gnutls_session);

int gnutls_fingerprint(gnutls_digest_algorithm algo, const gnutls_datum* data, 
	unsigned char* result, int* result_size);

#endif /* GNUTLS_INT_H */
