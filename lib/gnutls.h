/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

enum ContentType { GNUTLS_APPLICATION_DATA=23 };
typedef enum ContentType ContentType;
#define GNUTLS_AES GNUTLS_RIJNDAEL

enum BulkCipherAlgorithm { GNUTLS_NULL_CIPHER, GNUTLS_ARCFOUR=1, GNUTLS_3DES = 4, GNUTLS_RIJNDAEL, GNUTLS_TWOFISH, GNUTLS_RIJNDAEL256 };
typedef enum BulkCipherAlgorithm BulkCipherAlgorithm;
enum KXAlgorithm { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DH_DSS, GNUTLS_KX_DH_RSA, GNUTLS_KX_ANON_DH };
typedef enum KXAlgorithm KXAlgorithm;
enum MACAlgorithm { GNUTLS_NULL_MAC, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA };
typedef enum MACAlgorithm MACAlgorithm;
enum CompressionMethod { GNUTLS_NULL_COMPRESSION, GNUTLS_ZLIB=224 };
typedef enum CompressionMethod CompressionMethod;
enum ConnectionEnd { GNUTLS_SERVER, GNUTLS_CLIENT };
typedef enum ConnectionEnd ConnectionEnd;

#define GNUTLS_Version int
#define GNUTLS_TLS1 0
#define GNUTLS_SSL3 1

struct GNUTLS_STATE_INT;
typedef struct GNUTLS_STATE_INT* GNUTLS_STATE;

/* internal functions */
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, void* data, size_t sizeofdata, int flags);
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, void* data, size_t sizeofdata, int flags);

int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end);
int gnutls_deinit(GNUTLS_STATE * state);
int gnutls_close(int cd, GNUTLS_STATE state);
int gnutls_handshake(int cd, GNUTLS_STATE state);
int gnutls_check_pending(GNUTLS_STATE state);

/* get information on the current state */
BulkCipherAlgorithm gnutls_get_current_cipher( GNUTLS_STATE state);
MACAlgorithm gnutls_get_current_mac_algorithm( GNUTLS_STATE state);
CompressionMethod gnutls_get_current_compression_method( GNUTLS_STATE state);

/* the name of the specified algorithms */
char *_gnutls_cipher_get_name(BulkCipherAlgorithm);
char *_gnutls_mac_get_name(MACAlgorithm);
char *_gnutls_compression_get_name(CompressionMethod);



int gnutls_is_fatal_error( int error);
void gnutls_perror( int error);
char* gnutls_strerror(int error);

#define gnutls_send( x, y, z, w, e) gnutls_send_int( x, y, GNUTLS_APPLICATION_DATA, z, w, e)
#define gnutls_recv( x, y, z, w, e) gnutls_recv_int( x, y, GNUTLS_APPLICATION_DATA, z, w, e)

#define gnutls_write( x, y, z, w) gnutls_send( x, y, z, w, 0)
#define gnutls_read( x, y, z, w) gnutls_recv( x, y, z, w, 0)

/* functions to set priority of cipher suites */
void gnutls_set_cipher_priority( GNUTLS_STATE state, int num, ...);
void gnutls_set_mac_priority( GNUTLS_STATE state, int num, ...);
void gnutls_set_compression_priority( GNUTLS_STATE state, int num, ...);
void gnutls_set_kx_priority( GNUTLS_STATE state, int num, ...);

/* cred is a structure defined by the kx algorithm */
int gnutls_set_kx_cred( GNUTLS_STATE, int kx, void* cred);

/* set our version - 0 for TLS 1.0 and 1 for SSL3 */
void gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version); 

/* get/set session */
int gnutls_set_current_session( GNUTLS_STATE state, void* session, int session_size);
int gnutls_get_current_session( GNUTLS_STATE state, void* session, int *session_size);
/* returns the session ID */
int gnutls_get_current_session_id( GNUTLS_STATE state, void* session, int *session_size);

int gnutls_set_lowat( GNUTLS_STATE state, int num);
int gnutls_set_cache_expiration( GNUTLS_STATE state, int seconds);
int gnutls_set_db_name( GNUTLS_STATE state, char* filename);	
int gnutls_clean_db( GNUTLS_STATE state);


/* crypt functions */
enum crypt_algo { MD5_CRYPT, BLOWFISH_CRYPT };
typedef enum crypt_algo crypt_algo;

char * gnutls_crypt(const char* username, const char *passwd, crypt_algo algo);
int gnutls_crypt_vrfy(const char* username, const char *passwd, char* salt);

/* these are deprecated must be replaced by gnutls_errors.h */
#define	GNUTLS_E_MAC_FAILED  -1
#define	GNUTLS_E_UNKNOWN_CIPHER -2
#define	GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define	GNUTLS_E_UNKNOWN_MAC_ALGORITHM -4
#define	GNUTLS_E_UNKNOWN_ERROR -5
#define	GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define	GNUTLS_E_LARGE_PACKET -7
#define GNUTLS_E_UNSUPPORTED_VERSION_PACKET -8
#define GNUTLS_E_UNEXPECTED_PACKET_LENGTH -9
#define GNUTLS_E_INVALID_SESSION -10
#define GNUTLS_E_UNABLE_SEND_DATA -11
#define GNUTLS_E_FATAL_ALERT_RECEIVED -12
#define GNUTLS_E_RECEIVED_BAD_MESSAGE -13
#define GNUTLS_E_RECEIVED_MORE_DATA -14
#define GNUTLS_E_UNEXPECTED_PACKET -15
#define GNUTLS_E_WARNING_ALERT_RECEIVED -16
#define GNUTLS_E_CLOSURE_ALERT_RECEIVED -17
#define GNUTLS_E_ERROR_IN_FINISHED_PACKET -18
#define GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET -19
#define GNUTLS_E_UNKNOWN_KX_ALGORITHM -20
#define	GNUTLS_E_UNKNOWN_CIPHER_SUITE -21
#define	GNUTLS_E_UNWANTED_ALGORITHM -22
#define	GNUTLS_E_MPI_SCAN_FAILED -23
#define GNUTLS_E_DECRYPTION_FAILED -24
#define GNUTLS_E_MEMORY_ERROR -25
#define GNUTLS_E_DECOMPRESSION_FAILED -26
#define GNUTLS_E_COMPRESSION_FAILED -27
#define GNUTLS_E_AGAIN -28
#define GNUTLS_E_UNIMPLEMENTED_FEATURE -50
