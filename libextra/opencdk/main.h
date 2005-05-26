/* main.h
 *       Copyright (C) 2002, 2003, 2004 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenCDK; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CDK_MAIN_H
#define CDK_MAIN_H

#include <config.h>
#include <gcrypt.h>
#include "md.h"
#include "types.h"
#include "context.h"

#define MAX_MPI_BITS 8192
#define MAX_MPI_BYTES (MAX_MPI_BITS/8)

#define IS_UID_SIG(s) (((s)->sig_class & ~3) == 0x10)
#define IS_UID_REV(s) ((s)->sig_class == 0x30)

#define DEBUG_PKT (_cdk_get_log_level () == (CDK_LOG_DEBUG+1))

#define PK_USAGE_SIGN 1
#define PK_USAGE_ENCR 2

#define KEY_CAN_ENCRYPT(a) (_cdk_pk_algo_usage((a)) & PK_USAGE_ENCR)
#define KEY_CAN_SIGN(a)    (_cdk_pk_algo_usage((a)) & PK_USAGE_SIGN)

#define wipemem(_ptr,_len) \
do \
{ \
  volatile char *_vptr = (volatile char *)(_ptr); \
  size_t _vlen = (_len); \
  while (_vlen) \
    { \
      *_vptr = 0; \
      _vptr++; \
      _vlen--; \
    } \
} while (0)

/*-- armor.c --*/
const char * _cdk_armor_get_lineend (void);
     
/*-- main.c --*/
int _cdk_get_log_level (void);
void _cdk_log_info (const char * fmt, ...);
void _cdk_log_debug (const char * fmt, ...);
char * _cdk_passphrase_get( cdk_ctx_t hd, const char * prompt );
void _cdk_passphrase_free (char * pw, size_t size);
int _cdk_is_idea_available (void);
void _cdk_sec_free( void * ptr, size_t size );

/*-- misc.c --*/
int _cdk_check_file( const char * file );
u32 _cdk_timestamp (void);
int _cdk_strcmp (const char * a, const char * b);
u32 _cdk_buftou32 (const byte * buf);
void _cdk_u32tobuf (u32 u, byte * buf);
const char * _cdk_memistr (const char * buf, size_t buflen, const char * sub);
void _cdk_vasprintf_free (void * p);

#ifndef HAVE_VASPRINTF
int _cdk_vasprintf ( char **result, const char *format, va_list args);
#else
# define _cdk_vasprintf vasprintf
#endif

/*-- pubkey.c --*/
u32 _cdk_pkt_get_keyid( cdk_packet_t pkt, u32 * keyid );
int _cdk_pkt_get_fingerprint( cdk_packet_t pkt, byte * fpr );
int _cdk_pk_algo_usage( int algo );
int _cdk_pk_test_algo( int algo, unsigned int usage );
int _cdk_sk_get_csum( cdk_pkt_seckey_t sk );

/*-- cipher.c --*/
int _cdk_cipher_test_algo (int algo);

/*-- new-packet.c --*/
byte * _cdk_subpkt_get_array (cdk_subpkt_t s, int count, size_t * r_nbytes);
cdk_error_t _cdk_subpkt_copy (cdk_subpkt_t * r_dst, cdk_subpkt_t src);
cdk_error_t _cdk_subpkt_hash (cdk_subpkt_t hashed, size_t * r_nbytes,
                              cdk_md_hd_t hd);

/*-- sig-check.c --*/
int _cdk_sig_check (cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig,
                    cdk_md_hd_t digest, int * r_expired);
void _cdk_hash_sig_data (cdk_pkt_signature_t sig, cdk_md_hd_t hd);
void _cdk_hash_userid( cdk_pkt_userid_t uid, int sig_version, cdk_md_hd_t md);
void _cdk_hash_pubkey (cdk_pkt_pubkey_t pk, cdk_md_hd_t md, int use_fpr);
int _cdk_pk_check_sig(cdk_keydb_hd_t hd, cdk_kbnode_t knode,
                       cdk_kbnode_t snode, int * is_selfsig);
    

/*-- kbnode.c --*/
void _cdk_kbnode_add (cdk_kbnode_t root, cdk_kbnode_t node);
void _cdk_kbnode_clone (cdk_kbnode_t node);

/*-- sesskey.c --*/
int _cdk_digest_encode_pkcs1( byte ** r_md, size_t * r_mdlen, int pk_algo,
                              const byte * md, int digest_algo, unsigned nbits );
int _cdk_sk_unprotect_auto( cdk_ctx_t hd, cdk_pkt_seckey_t sk );

/*-- keydb.c --*/
int _cdk_keydb_get_pk_byusage (cdk_keydb_hd_t hd, const char * name,
                              cdk_pkt_pubkey_t* ret_pk, int usage);
int _cdk_keydb_get_sk_byusage (cdk_keydb_hd_t hd, const char * name,
                              cdk_pkt_seckey_t* ret_sk, int usage);
char * _cdk_keydb_get_importres_as_xml( int result[4] );

/*-- sign.c --*/
int _cdk_sig_create (cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig);
int _cdk_sig_hash_for (int pubkey_algo, int pkt_version);
void _cdk_trim_string (char * s, int canon);
int _cdk_sig_complete (cdk_pkt_signature_t sig, cdk_pkt_seckey_t sk,
                       cdk_md_hd_t hd);     

/*-- stream.c --*/
void * _cdk_stream_get_opaque( cdk_stream_t s, int fid );
const char * _cdk_stream_get_fname( cdk_stream_t s );
FILE * _cdk_stream_get_fp( cdk_stream_t s );
int _cdk_stream_gets( cdk_stream_t s, char * buf, size_t count );
cdk_error_t _cdk_stream_append( const char * file, cdk_stream_t * ret_s );
int _cdk_stream_get_errno( cdk_stream_t s );
int _cdk_stream_set_blockmode( cdk_stream_t s, size_t nbytes );
int _cdk_stream_get_blockmode( cdk_stream_t s );
int _cdk_stream_puts( cdk_stream_t s, const char * buf );
cdk_stream_t _cdk_stream_fpopen (FILE * fp, unsigned write_mode);

/*-- verify.c --*/
void _cdk_result_verify_free (_cdk_verify_result_t res);
_cdk_verify_result_t _cdk_result_verify_new (void);

/*-- encrypt.c --*/
int _cdk_check_args( int overwrite, const char * in, const char * out );
int _cdk_proc_packets( cdk_ctx_t hd, cdk_stream_t inp, const char * output,
                       cdk_stream_t outstream, cdk_md_hd_t md );

/*-- read-packet.c --*/
size_t _cdk_pkt_read_len( FILE * inp, int * ret_partial );

/** write-packet.c --*/
int _cdk_pkt_write_fp( FILE * out, cdk_packet_t pkt );    

#endif /* CDK_MAIN_H */
