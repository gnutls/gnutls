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
enum BulkCipherAlgorithm { GNUTLS_NULL, GNUTLS_ARCFOUR=1, GNUTLS_DES=3, GNUTLS_3DES = 4, GNUTLS_AES };
typedef enum BulkCipherAlgorithm BulkCipherAlgorithm;
enum KXAlgorithm { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DH_DSS, GNUTLS_KX_DH_RSA, GNUTLS_KX_ANON_DH };
typedef enum KXAlgorithm KXAlgorithm;
enum MACAlgorithm { GNUTLS_MAC_NULL, GNUTLS_MAC_MD5, GNUTLS_MAC_SHA };
typedef enum MACAlgorithm MACAlgorithm;
enum CompressionMethod { COMPRESSION_NULL };
typedef enum CompressionMethod CompressionMethod;
enum ConnectionEnd { GNUTLS_SERVER, GNUTLS_CLIENT };
typedef enum ConnectionEnd ConnectionEnd;

struct GNUTLS_STATE_INT;
typedef struct GNUTLS_STATE_INT* GNUTLS_STATE;

int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end);
int gnutls_deinit(GNUTLS_STATE * state);
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
int gnutls_close(int cd, GNUTLS_STATE state);
int gnutls_handshake(int cd, GNUTLS_STATE state);

int gnutls_is_fatal_error( int error);
void gnutls_perror( int error);

#define gnutls_send( x, y, z, w) gnutls_send_int( x, y, GNUTLS_APPLICATION_DATA, z, w)
#define gnutls_recv( x, y, z, w) gnutls_recv_int( x, y, GNUTLS_APPLICATION_DATA, z, w)

/* functions to set priority of cipher suites */
void gnutls_set_cipher_priority( int num, ...);
void gnutls_set_kx_priority( int num, ...);
void gnutls_set_mac_priority( int num, ...);

/* set our version - local is 0x00 for TLS 1.0 and SSL3 */
void gnutls_set_current_version(GNUTLS_STATE state, int local, int major, int minor); 

#define	GNUTLS_E_MAC_FAILED -1
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
