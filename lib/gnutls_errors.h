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

#include "gnutls_int.h"

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
#define GNUTLS_E_EXPIRED -29
#define GNUTLS_E_DB_ERROR -30
#define GNUTLS_E_PWD_ERROR -31
#define GNUTLS_E_INSUFICIENT_CRED -32
#define GNUTLS_E_HASH_FAILED -33
#define GNUTLS_E_PARSING_ERROR -34
#define	GNUTLS_E_MPI_PRINT_FAILED -35
#define GNUTLS_E_UNIMPLEMENTED_FEATURE -50


#ifdef DEBUG
# ifdef __FILE__
#  ifdef __LINE__
#   define gnutls_assert() fprintf(stderr, "GNUTLS_ASSERT: %s:%d\n", __FILE__,__LINE__);
#  else
#   define gnutls_assert() 
#  endif
# else /* __FILE__ defined */
#  define gnutls_assert() 
# endif
#else /* no debug */
# define gnutls_assert() 
#endif

char* gnutls_strerror(int error);
void gnutls_perror(int error);
int gnutls_is_fatal_error( int error);
