/*
 *  Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
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

#ifndef GNUTLS_H
# define GNUTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#define LIBGNUTLS_VERSION "0.5.0"

#include <sys/types.h>
#include <time.h>

#define GNUTLS_CIPHER_AES_128_CBC GNUTLS_CIPHER_RIJNDAEL_128_CBC
#define GNUTLS_CIPHER_AES_256_CBC GNUTLS_CIPHER_RIJNDAEL_256_CBC
#define GNUTLS_CIPHER_RIJNDAEL_CBC GNUTLS_CIPHER_RIJNDAEL_128_CBC

typedef enum GNUTLS_BulkCipherAlgorithm { GNUTLS_CIPHER_NULL=1, GNUTLS_CIPHER_ARCFOUR, GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_RIJNDAEL_128_CBC, GNUTLS_CIPHER_TWOFISH_128_CBC, GNUTLS_CIPHER_RIJNDAEL_256_CBC } GNUTLS_BulkCipherAlgorithm;

typedef enum GNUTLS_KXAlgorithm { GNUTLS_KX_RSA=1, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, GNUTLS_KX_SRP } GNUTLS_KXAlgorithm;

typedef enum GNUTLS_CredType { GNUTLS_CRD_CERTIFICATE=1, GNUTLS_CRD_ANON, GNUTLS_CRD_SRP } GNUTLS_CredType;

typedef enum GNUTLS_MACAlgorithm { GNUTLS_MAC_NULL=1, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA } GNUTLS_MACAlgorithm;
typedef enum GNUTLS_DigestAlgorithm { GNUTLS_DIG_NULL=1, GNUTLS_DIG_MD5, GNUTLS_DIG_SHA } GNUTLS_DigestAlgorithm;

/* exported for other gnutls headers. This is the maximum number
 * of algorithms (ciphers, kx or macs). 
 */
#define GNUTLS_MAX_ALGORITHM_NUM 8

typedef enum GNUTLS_CompressionMethod { GNUTLS_COMP_NULL=1, GNUTLS_COMP_ZLIB } GNUTLS_CompressionMethod;
typedef enum GNUTLS_ConnectionEnd { GNUTLS_SERVER=1, GNUTLS_CLIENT } GNUTLS_ConnectionEnd;
typedef enum GNUTLS_AlertLevel { GNUTLS_AL_WARNING=1, GNUTLS_AL_FATAL } GNUTLS_AlertLevel;
typedef enum GNUTLS_AlertDescription { GNUTLS_A_CLOSE_NOTIFY, GNUTLS_A_UNEXPECTED_MESSAGE=10, GNUTLS_A_BAD_RECORD_MAC=20,
			GNUTLS_A_DECRYPTION_FAILED, GNUTLS_A_RECORD_OVERFLOW,  GNUTLS_A_DECOMPRESSION_FAILURE=30,
			GNUTLS_A_HANDSHAKE_FAILURE=40, GNUTLS_A_SSL3_NO_CERTIFICATE=41,
			GNUTLS_A_BAD_CERTIFICATE=42, GNUTLS_A_UNSUPPORTED_CERTIFICATE,
			GNUTLS_A_CERTIFICATE_REVOKED, GNUTLS_A_CERTIFICATE_EXPIRED, GNUTLS_A_CERTIFICATE_UNKNOWN,
			GNUTLS_A_ILLEGAL_PARAMETER, GNUTLS_A_UNKNOWN_CA, GNUTLS_A_ACCESS_DENIED, GNUTLS_A_DECODE_ERROR=50,
			GNUTLS_A_DECRYPT_ERROR, GNUTLS_A_EXPORT_RESTRICTION=60, GNUTLS_A_PROTOCOL_VERSION=70,
			GNUTLS_A_INSUFFICIENT_SECURITY, GNUTLS_A_INTERNAL_ERROR=80, GNUTLS_A_USER_CANCELED=90,
			GNUTLS_A_NO_RENEGOTIATION=100
} GNUTLS_AlertDescription;

typedef enum GNUTLS_CertificateStatus { 
	GNUTLS_CERT_NOT_TRUSTED=2, 
	GNUTLS_CERT_INVALID=4, 
	GNUTLS_CERT_CORRUPTED=16,
	GNUTLS_CERT_REVOKED=32
} GNUTLS_CertificateStatus;

typedef enum GNUTLS_CertificateRequest { GNUTLS_CERT_IGNORE, GNUTLS_CERT_REQUEST=1, GNUTLS_CERT_REQUIRE } GNUTLS_CertificateRequest;

typedef enum GNUTLS_OpenPGPKeyStatus { GNUTLS_OPENPGP_KEY, 
	GNUTLS_OPENPGP_KEY_FINGERPRINT
} GNUTLS_OpenPGPKeyStatus;

typedef enum GNUTLS_CloseRequest { GNUTLS_SHUT_RDWR=0, GNUTLS_SHUT_WR=1 } GNUTLS_CloseRequest;

typedef enum GNUTLS_Version { GNUTLS_SSL3=1, GNUTLS_TLS1 } GNUTLS_Version;

typedef enum GNUTLS_CertificateType { GNUTLS_CRT_X509=1, GNUTLS_CRT_OPENPGP 
} GNUTLS_CertificateType;

typedef enum GNUTLS_X509_CertificateFmt { GNUTLS_X509_FMT_DER, 
	GNUTLS_X509_FMT_PEM } GNUTLS_X509_CertificateFmt;

typedef enum GNUTLS_PKAlgorithm { GNUTLS_PK_RSA = 1, GNUTLS_PK_DSA
} GNUTLS_PKAlgorithm;

/* If you want to change this, then also change the 
 * define in gnutls_int.h, and recompile.
 */
#define GNUTLS_TRANSPORT_PTR int

typedef const int* GNUTLS_LIST;

struct GNUTLS_STATE_INT;
typedef struct GNUTLS_STATE_INT* GNUTLS_STATE;

struct GNUTLS_DH_PARAMS_INT;
typedef struct GNUTLS_DH_PARAMS_INT* GNUTLS_DH_PARAMS;

typedef struct {
	unsigned char * data;
	int size;
} gnutls_datum;

/* internal functions */

int gnutls_init(GNUTLS_STATE * state, GNUTLS_ConnectionEnd con_end);
void gnutls_deinit(GNUTLS_STATE state);
int gnutls_bye( GNUTLS_STATE state, GNUTLS_CloseRequest how);
#define gnutls_close gnutls_bye

int gnutls_handshake( GNUTLS_STATE state);
int gnutls_rehandshake( GNUTLS_STATE state);


GNUTLS_AlertDescription gnutls_alert_get( GNUTLS_STATE state);
int 		 gnutls_alert_send( GNUTLS_STATE, GNUTLS_AlertLevel, GNUTLS_AlertDescription);
int 		 gnutls_alert_send_appropriate(  GNUTLS_STATE state, int err);
const char*	 gnutls_alert_get_name( int alert);

/* get information on the current state */
GNUTLS_BulkCipherAlgorithm	gnutls_cipher_get( GNUTLS_STATE state);
GNUTLS_KXAlgorithm 		gnutls_kx_get( GNUTLS_STATE state);
GNUTLS_MACAlgorithm		gnutls_mac_get( GNUTLS_STATE state);
GNUTLS_CompressionMethod	gnutls_compression_get( GNUTLS_STATE state);
GNUTLS_CertificateType		gnutls_cert_type_get( GNUTLS_STATE state);

size_t gnutls_cipher_get_key_size( GNUTLS_BulkCipherAlgorithm algorithm);

/* the name of the specified algorithms */
const char *gnutls_cipher_get_name( GNUTLS_BulkCipherAlgorithm);
const char *gnutls_mac_get_name( GNUTLS_MACAlgorithm);
const char *gnutls_compression_get_name( GNUTLS_CompressionMethod);
const char *gnutls_kx_get_name( GNUTLS_KXAlgorithm algorithm);
const char *gnutls_cert_type_get_name( GNUTLS_CertificateType type);


/* error functions */
int gnutls_error_is_fatal( int error);

void gnutls_perror( int error);
const char* gnutls_strerror( int error);

/* Semi-internal functions.
 */
void gnutls_handshake_set_private_extensions(GNUTLS_STATE state, int allow);
void gnutls_record_set_cbc_protection(GNUTLS_STATE state, int prot);
void gnutls_handshake_set_rsa_pms_check(GNUTLS_STATE state, int check);

/* Record layer functions.
 */
ssize_t gnutls_record_send( GNUTLS_STATE state, const void *data, size_t sizeofdata);
ssize_t gnutls_record_recv( GNUTLS_STATE state, void *data, size_t sizeofdata);
#define gnutls_read gnutls_record_recv
#define gnutls_write gnutls_record_send

size_t gnutls_record_get_max_size( GNUTLS_STATE state);
ssize_t gnutls_record_set_max_size( GNUTLS_STATE state, size_t size);

size_t gnutls_record_check_pending(GNUTLS_STATE state);

/* functions to set priority of cipher suites 
 */
int gnutls_cipher_set_priority( GNUTLS_STATE state, GNUTLS_LIST);
int gnutls_mac_set_priority( GNUTLS_STATE state, GNUTLS_LIST);
int gnutls_compression_set_priority( GNUTLS_STATE state, GNUTLS_LIST);
int gnutls_kx_set_priority( GNUTLS_STATE state, GNUTLS_LIST);
int gnutls_protocol_set_priority( GNUTLS_STATE state, GNUTLS_LIST);
int gnutls_cert_type_set_priority( GNUTLS_STATE state, GNUTLS_LIST);

/* set our version - 0 for TLS 1.0 and 1 for SSL3 */
GNUTLS_Version gnutls_protocol_get_version(GNUTLS_STATE state);

const char *gnutls_protocol_get_name(GNUTLS_Version version);


/* get/set session 
 */
int gnutls_session_set_data( GNUTLS_STATE state, void* session, int session_size);
int gnutls_session_get_data( GNUTLS_STATE state, void* session, int *session_size);
/* returns the session ID */
int gnutls_session_get_id( GNUTLS_STATE state, void* session, int *session_size);

/* checks if this session is a resumed one 
 */
int gnutls_session_is_resumed(GNUTLS_STATE state);

typedef int (*GNUTLS_DB_STORE_FUNC)(void*, gnutls_datum key, gnutls_datum data);
typedef int (*GNUTLS_DB_REMOVE_FUNC)(void*, gnutls_datum key);
typedef gnutls_datum (*GNUTLS_DB_RETR_FUNC)(void*, gnutls_datum key);

void gnutls_db_set_cache_expiration( GNUTLS_STATE state, int seconds);

void gnutls_db_remove_session( GNUTLS_STATE state);
void gnutls_db_set_retrieve_function( GNUTLS_STATE, GNUTLS_DB_RETR_FUNC);
void gnutls_db_set_remove_function( GNUTLS_STATE, GNUTLS_DB_REMOVE_FUNC);
void gnutls_db_set_store_function( GNUTLS_STATE, GNUTLS_DB_STORE_FUNC);
void gnutls_db_set_ptr( GNUTLS_STATE, void* db_ptr);
void* gnutls_db_get_ptr( GNUTLS_STATE);
int  gnutls_db_check_entry( GNUTLS_STATE state, gnutls_datum session_entry);

void gnutls_handshake_set_max_packet_length( GNUTLS_STATE state, int max);

/* returns libgnutls version */
const char* gnutls_check_version( const char*);

/* Functions for setting/clearing credentials */
int gnutls_clear_creds( GNUTLS_STATE state);
/* cred is a structure defined by the kx algorithm */
int gnutls_cred_set( GNUTLS_STATE, GNUTLS_CredType type, void* cred);

/* Credential structures for SRP - used in gnutls_set_cred(); */

struct DSTRUCT;
typedef struct DSTRUCT* GNUTLS_CERTIFICATE_CREDENTIALS;
typedef GNUTLS_CERTIFICATE_CREDENTIALS GNUTLS_CERTIFICATE_CLIENT_CREDENTIALS;
typedef GNUTLS_CERTIFICATE_CREDENTIALS GNUTLS_CERTIFICATE_SERVER_CREDENTIALS;

typedef struct DSTRUCT* GNUTLS_ANON_SERVER_CREDENTIALS;
typedef struct DSTRUCT* GNUTLS_ANON_CLIENT_CREDENTIALS;

void gnutls_anon_free_server_sc( GNUTLS_ANON_SERVER_CREDENTIALS sc);
int gnutls_anon_allocate_server_sc( GNUTLS_ANON_SERVER_CREDENTIALS *sc);
int gnutls_anon_set_server_cred( GNUTLS_ANON_SERVER_CREDENTIALS res);
void gnutls_anon_set_server_dh_params( GNUTLS_ANON_SERVER_CREDENTIALS res, GNUTLS_DH_PARAMS);

void gnutls_anon_free_client_sc( GNUTLS_ANON_SERVER_CREDENTIALS sc);
int gnutls_anon_allocate_client_sc( GNUTLS_ANON_SERVER_CREDENTIALS *sc);
int gnutls_anon_set_client_cred( GNUTLS_ANON_SERVER_CREDENTIALS res);


/* CERTFILE is an x509 certificate in PEM form.
 * KEYFILE is a pkcs-1 private key in PEM form (for RSA keys).
 */
void gnutls_certificate_free_sc( GNUTLS_CERTIFICATE_CREDENTIALS sc);
int gnutls_certificate_allocate_sc( GNUTLS_CERTIFICATE_CREDENTIALS *sc);

int gnutls_certificate_set_dh_params(GNUTLS_CERTIFICATE_CREDENTIALS res, GNUTLS_DH_PARAMS);

int gnutls_certificate_set_x509_trust_file( GNUTLS_CERTIFICATE_CREDENTIALS res, char* CAFILE, 
	GNUTLS_X509_CertificateFmt);
int gnutls_certificate_set_x509_trust_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, 
	const gnutls_datum *CA, GNUTLS_X509_CertificateFmt);

int gnutls_certificate_set_x509_key_file( GNUTLS_CERTIFICATE_CREDENTIALS res, 
	char *CERTFILE, char* KEYFILE, GNUTLS_X509_CertificateFmt);
int gnutls_certificate_set_x509_key_mem(GNUTLS_CERTIFICATE_CREDENTIALS res, 
	const gnutls_datum* CERT, const gnutls_datum* KEY,
	GNUTLS_X509_CertificateFmt);

/* global state functions 
 */
/* In this version global_init accepts two files (pkix.asn, pkcs1.asn).
 * This will not be the case in the final version. These files 
 * are located in the src/ directory of gnutls distribution.
 */
int gnutls_global_init(void);
void gnutls_global_deinit(void);

void gnutls_global_set_mem_functions( 
	void *(*gnutls_alloc_func)(size_t), void* (*gnutls_secure_alloc_func)(size_t),
	int (*gnutls_is_secure_func)(const void*), void *(*gnutls_realloc_func)(void *, size_t),
	void (*gnutls_free_func)(void*));

typedef void (*GNUTLS_LOG_FUNC)( const char*);
void gnutls_global_set_log_function( GNUTLS_LOG_FUNC log_func);

int gnutls_dh_params_set( GNUTLS_DH_PARAMS, gnutls_datum prime, gnutls_datum generator, int bits);
int gnutls_dh_params_init( GNUTLS_DH_PARAMS*);
void gnutls_dh_params_deinit( GNUTLS_DH_PARAMS);
int gnutls_dh_params_generate( gnutls_datum* prime, gnutls_datum* generator, int bits);

typedef ssize_t (*GNUTLS_PULL_FUNC)(GNUTLS_TRANSPORT_PTR, void*, size_t);
typedef ssize_t (*GNUTLS_PUSH_FUNC)(GNUTLS_TRANSPORT_PTR, const void*, size_t);
void gnutls_transport_set_ptr(GNUTLS_STATE state, GNUTLS_TRANSPORT_PTR ptr);
GNUTLS_TRANSPORT_PTR gnutls_transport_get_ptr(GNUTLS_STATE state);

void gnutls_transport_set_lowat( GNUTLS_STATE state, int num);


void gnutls_transport_set_push_function( GNUTLS_STATE, GNUTLS_PUSH_FUNC push_func);
void gnutls_transport_set_pull_function( GNUTLS_STATE, GNUTLS_PULL_FUNC pull_func);

/* state specific 
 */
void gnutls_state_set_ptr(GNUTLS_STATE state, void* ptr);
void* gnutls_state_get_ptr(GNUTLS_STATE state);

void gnutls_openpgp_send_key(GNUTLS_STATE state, GNUTLS_OpenPGPKeyStatus status);

int gnutls_x509_fingerprint(GNUTLS_DigestAlgorithm algo, const gnutls_datum* data, char* result, size_t* result_size);
#ifndef GNUTLS_UI_H
# define GNUTLS_UI_H


/* Extra definitions */

#define GNUTLS_X509_CN_SIZE 256
#define GNUTLS_X509_C_SIZE 3
#define GNUTLS_X509_O_SIZE 256
#define GNUTLS_X509_OU_SIZE 256
#define GNUTLS_X509_L_SIZE 256
#define GNUTLS_X509_S_SIZE 256
#define GNUTLS_X509_EMAIL_SIZE 256

typedef struct {
	char common_name[GNUTLS_X509_CN_SIZE];
	char country[GNUTLS_X509_C_SIZE];
	char organization[GNUTLS_X509_O_SIZE];
	char organizational_unit_name[GNUTLS_X509_OU_SIZE];
	char locality_name[GNUTLS_X509_L_SIZE];
	char state_or_province_name[GNUTLS_X509_S_SIZE];
	char email[GNUTLS_X509_EMAIL_SIZE];
} gnutls_x509_dn;
#define gnutls_DN gnutls_x509_dn

typedef struct {
	char name[GNUTLS_X509_CN_SIZE];
	char email[GNUTLS_X509_CN_SIZE];
} gnutls_openpgp_name;	

typedef enum GNUTLS_X509_SUBJECT_ALT_NAME {
	GNUTLS_SAN_DNSNAME=1, GNUTLS_SAN_RFC822NAME,
	GNUTLS_SAN_URI, GNUTLS_SAN_IPADDRESS
} GNUTLS_X509_SUBJECT_ALT_NAME;

/* For key Usage, test as:
 * if (st.keyUsage & X509KEY_DIGITAL_SIGNATURE) ...
 */
#define GNUTLS_X509KEY_DIGITAL_SIGNATURE 	256
#define GNUTLS_X509KEY_NON_REPUDIATION		128
#define GNUTLS_X509KEY_KEY_ENCIPHERMENT		64
#define GNUTLS_X509KEY_DATA_ENCIPHERMENT	32
#define GNUTLS_X509KEY_KEY_AGREEMENT		16
#define GNUTLS_X509KEY_KEY_CERT_SIGN		8
#define GNUTLS_X509KEY_CRL_SIGN			4
#define GNUTLS_X509KEY_ENCIPHER_ONLY		2
#define GNUTLS_X509KEY_DECIPHER_ONLY		1


# ifdef LIBGNUTLS_VERSION /* These are defined only in gnutls.h */

typedef int gnutls_certificate_client_select_function(GNUTLS_STATE, const gnutls_datum *, int, const gnutls_datum *, int);
typedef int gnutls_certificate_server_select_function(GNUTLS_STATE, const gnutls_datum *, int);

/* Functions that allow AUTH_INFO structures handling
 */

GNUTLS_CredType gnutls_auth_get_type( GNUTLS_STATE state);

/* DH */

void gnutls_dh_set_prime_bits( GNUTLS_STATE state, int bits);
int gnutls_dh_get_prime_bits( GNUTLS_STATE);
int gnutls_dh_get_secret_bits( GNUTLS_STATE);
int gnutls_dh_get_peers_public_bits( GNUTLS_STATE);

/* X509PKI */

void gnutls_certificate_client_set_select_function( GNUTLS_STATE, gnutls_certificate_client_select_function *);
void gnutls_certificate_server_set_select_function( GNUTLS_STATE, gnutls_certificate_server_select_function *);

void gnutls_certificate_server_set_request( GNUTLS_STATE, GNUTLS_CertificateRequest);

/* X.509 certificate handling functions */
int gnutls_x509_get_certificate_xml(const gnutls_datum * cert, int detail, gnutls_datum* res);

int gnutls_x509_extract_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_certificate_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_certificate_issuer_dn(  const gnutls_datum*, gnutls_x509_dn *);
int gnutls_x509_extract_certificate_version( const gnutls_datum*);
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size);
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);
int gnutls_x509_extract_certificate_subject_alt_name( const gnutls_datum*, int seq, char*, int*);
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits);

int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length);


/* get data from the state */
const gnutls_datum* gnutls_certificate_get_peers( GNUTLS_STATE, int* list_size);
const gnutls_datum *gnutls_certificate_get_ours( GNUTLS_STATE state);

time_t gnutls_certificate_activation_time_peers(GNUTLS_STATE state);
time_t gnutls_certificate_expiration_time_peers(GNUTLS_STATE state);

int gnutls_certificate_client_get_request_status(  GNUTLS_STATE);
int gnutls_certificate_verify_peers( GNUTLS_STATE);

int gnutls_b64_encode_fmt( const char* msg, const gnutls_datum *data, char* result, int* result_size);
int gnutls_b64_decode_fmt( const gnutls_datum *b64_data, char* result, int* result_size);

int gnutls_b64_encode_fmt2( const char* msg, const gnutls_datum *data, const gnutls_datum * result);
int gnutls_b64_decode_fmt2( const gnutls_datum *b64_data, const gnutls_datum* result);

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */

/* Gnutls error codes. The mapping to a TLS alert is also shown in
 * comments.
 */

#define GNUTLS_E_SUCCESS 0
#define	GNUTLS_E_UNKNOWN_CIPHER -2
#define	GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define	GNUTLS_E_UNKNOWN_MAC_ALGORITHM -4
#define	GNUTLS_E_UNKNOWN_ERROR -5
#define	GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define	GNUTLS_E_LARGE_PACKET -7
#define GNUTLS_E_UNSUPPORTED_VERSION_PACKET -8 /* GNUTLS_A_PROTOCOL_VERSION */
#define GNUTLS_E_UNEXPECTED_PACKET_LENGTH -9 /* GNUTLS_A_RECORD_OVERFLOW */
#define GNUTLS_E_INVALID_SESSION -10
#define GNUTLS_E_UNABLE_SEND_DATA -11
#define GNUTLS_E_FATAL_ALERT_RECEIVED -12
#define GNUTLS_E_RECEIVED_BAD_MESSAGE -13
#define GNUTLS_E_RECEIVED_MORE_DATA -14
#define GNUTLS_E_UNEXPECTED_PACKET -15 /* GNUTLS_A_UNEXPECTED_MESSAGE */
#define GNUTLS_E_WARNING_ALERT_RECEIVED -16
#define GNUTLS_E_ERROR_IN_FINISHED_PACKET -18
#define GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET -19
#define GNUTLS_E_UNKNOWN_KX_ALGORITHM -20
#define	GNUTLS_E_UNKNOWN_CIPHER_SUITE -21 /* GNUTLS_A_HANDSHAKE_FAILURE */
#define	GNUTLS_E_UNWANTED_ALGORITHM -22
#define	GNUTLS_E_MPI_SCAN_FAILED -23
#define GNUTLS_E_DECRYPTION_FAILED -24 /* GNUTLS_A_DECRYPTION_FAILED, GNUTLS_A_BAD_RECORD_MAC */
#define GNUTLS_E_MEMORY_ERROR -25
#define GNUTLS_E_DECOMPRESSION_FAILED -26 /* GNUTLS_A_DECOMPRESSION_FAILURE */
#define GNUTLS_E_COMPRESSION_FAILED -27
#define GNUTLS_E_AGAIN -28
#define GNUTLS_E_EXPIRED -29
#define GNUTLS_E_DB_ERROR -30
#define GNUTLS_E_PWD_ERROR -31
#define GNUTLS_E_INSUFICIENT_CRED -32
#define GNUTLS_E_HASH_FAILED -33
#define GNUTLS_E_PARSING_ERROR -34
#define	GNUTLS_E_MPI_PRINT_FAILED -35
#define GNUTLS_E_REHANDSHAKE -37 /* GNUTLS_A_NO_RENEGOTIATION */
#define GNUTLS_E_GOT_APPLICATION_DATA -38
#define GNUTLS_E_RECORD_LIMIT_REACHED -39
#define GNUTLS_E_ENCRYPTION_FAILED -40
#define GNUTLS_E_X509_CERTIFICATE_ERROR -43
#define GNUTLS_E_PK_ENCRYPTION_FAILED -44
#define GNUTLS_E_PK_DECRYPTION_FAILED -45
#define GNUTLS_E_PK_SIGNATURE_FAILED -46
#define GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION -47
#define GNUTLS_E_X509_KEY_USAGE_VIOLATION -48
#define GNUTLS_E_NO_CERTIFICATE_FOUND -49 /* GNUTLS_A_BAD_CERTIFICATE */
#define GNUTLS_E_INVALID_PARAMETERS -50
#define GNUTLS_E_INVALID_REQUEST -51
#define GNUTLS_E_INTERRUPTED -52
#define GNUTLS_E_PUSH_ERROR -53
#define GNUTLS_E_PULL_ERROR -54
#define GNUTLS_E_ILLEGAL_PARAMETER -55  /* GNUTLS_A_ILLEGAL_PARAMETER */
#define GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE -56
#define GNUTLS_E_PKCS1_WRONG_PAD -57
#define GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION -58
#define GNUTLS_E_INTERNAL_ERROR -59
#define GNUTLS_E_CERTIFICATE_KEY_MISMATCH -60
#define GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE -61 /* GNUTLS_A_UNSUPPORTED_CERTIFICATE */
#define GNUTLS_E_X509_UNKNOWN_SAN -62
#define GNUTLS_E_DH_PRIME_UNACCEPTABLE -63
#define GNUTLS_E_FILE_ERROR -64
#define GNUTLS_E_ASCII_ARMOR_ERROR -65
#define GNUTLS_E_ASN1_ELEMENT_NOT_FOUND -67
#define GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND -68
#define GNUTLS_E_ASN1_DER_ERROR -69
#define GNUTLS_E_ASN1_VALUE_NOT_FOUND -70
#define GNUTLS_E_ASN1_GENERIC_ERROR -71
#define GNUTLS_E_ASN1_VALUE_NOT_VALID -72
#define GNUTLS_E_ASN1_TAG_ERROR -73
#define GNUTLS_E_ASN1_TAG_IMPLICIT -74
#define GNUTLS_E_ASN1_TYPE_ANY_ERROR -75
#define GNUTLS_E_ASN1_SYNTAX_ERROR -76
#define GNUTLS_E_ASN1_DER_OVERFLOW -77
#define GNUTLS_E_TOO_MANY_EMPTY_PACKETS -78
#define GNUTLS_E_OPENPGP_UID_REVOKED -79
#define GNUTLS_E_UNKNOWN_PK_ALGORITHM -80
#define GNUTLS_E_OPENPGP_TRUSTDB_VERSION_UNSUPPORTED -81

#define GNUTLS_E_UNIMPLEMENTED_FEATURE -250



#ifdef __cplusplus
}
#endif
#endif /* GNUTLS_H */

