/* -*- Mode: C; c-file-style: "bsd" -*-
 * verify.c - Verify signatures
 *        Copyright (C) 2001, 2002, 2003 Timo Schulz 
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "packet.h"


struct {
    const char *name;
    int algo;
} digest_table[] = {
    {"MD5",       CDK_MD_MD5},
    {"SHA1",      CDK_MD_SHA1},
    {"RIPEMD160", CDK_MD_RMD160},
    {"MD2",       CDK_MD_MD2},
    {"SHA256",    CDK_MD_SHA256},
    {NULL, 0}
};


static int file_verify_clearsign( cdk_ctx_t, const char *, const char * );


cdk_error_t
cdk_stream_verify( cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out )
{
    if( cdk_armor_filter_use( inp ) )
        cdk_stream_set_armor_flag( inp, 0 );
    return _cdk_proc_packets( hd, inp, NULL, NULL, NULL );
}
    

/**
 * cdk_file_verify:
 * @hd: the session handle
 * @file: the input file
 * @output: the output file
 *
 * Verify a signature.
 **/
cdk_error_t
cdk_file_verify( cdk_ctx_t hd, const char * file, const char * output )
{
    cdk_stream_t inp;
    char buf[2048];
    int rc, n;

    if( !hd || !file )
        return CDK_Inv_Value;
    if( output && !hd->opt.overwrite && _cdk_check_file( output ) )
        return CDK_Inv_Mode;
  
    rc = cdk_stream_open ( file, &inp );
    if( rc )
        return rc;
    if( cdk_armor_filter_use( inp ) ) {
        n = cdk_stream_peek( inp, buf, sizeof buf-1 );
        if( !n )
            return CDK_EOF;
        buf[n] = '\0';
        if( strstr( buf, "BEGIN PGP SIGNED MESSAGE" ) ) {
            cdk_stream_close( inp );
            return file_verify_clearsign( hd, file, output );
        }
        cdk_stream_set_armor_flag( inp, 0 );
    }
    rc = _cdk_proc_packets( hd, inp, NULL, NULL, NULL );
    cdk_stream_close( inp );
    return rc;
}


void
_cdk_result_verify_free( _cdk_verify_result_t res )
{
    if( res ) {
        cdk_free( res->sig_data );
        cdk_free( res->notation );
        cdk_free( res );
    }
}


_cdk_verify_result_t
_cdk_result_verify_new( void )
{
    _cdk_verify_result_t res;

    res = cdk_calloc( 1, sizeof *res );
    if( !res )
        return NULL;
    return res;
}


/**
 * cdk_sig_get_ulong_attr:
 * @hd: session handle
 * @idx: index of the signature
 * @what: attribute id
 *
 * Extract the requested attribute of the signature. The returned value
 * is always an integer (max. 32-bit).
 **/
unsigned long
cdk_sig_get_ulong_attr( cdk_ctx_t hd, int idx, int what )
{
    _cdk_verify_result_t res;
    u32 val = 0;
  
    if( !hd || !hd->result.verify )
        return 0;

    assert( idx == 0 );
    res = hd->result.verify;
    switch( what ) {
    case CDK_ATTR_CREATED: val = res->created; break;
    case CDK_ATTR_EXPIRE : val = res->expires; break;
    case CDK_ATTR_KEYID  : val = res->keyid[1]; break;
    case CDK_ATTR_STATUS : val = res->sig_status; break;
    case CDK_ATTR_ALGO_PK: val = res->pubkey_algo; break;
    case CDK_ATTR_ALGO_MD: val = res->digest_algo; break;
    case CDK_ATTR_VERSION: val = res->sig_ver; break;
    case CDK_ATTR_LEN    : val = res->sig_len; break;
    case CDK_ATTR_FLAGS  : val = res->sig_flags; break;
    default              : val = 0; break;
    }
    
    return val;
}


/**
 * cdk_sig_get_data_attr:
 * @hd: session handle
 * @idx: index of the signature
 * @what: attribute id.
 *
 * Extract the requested attribute of the signature. The returned value
 * is always a constant object to the data.
 **/
const void *
cdk_sig_get_data_attr( cdk_ctx_t hd, int idx, int what )
{
    _cdk_verify_result_t res;
    const void * val;
  
    if( !hd || !hd->result.verify )
        return NULL;

    assert( idx == 0 );
    res = hd->result.verify;
    switch( what ) {
    case CDK_ATTR_KEYID   : val = res->keyid; break;
    case CDK_ATTR_NOTATION: val = res->notation; break;
    case CDK_ATTR_MPI     : val = res->sig_data; break;
    default               : val = NULL;
    }

    return val;
}


static int
file_verify_clearsign( cdk_ctx_t hd, const char * file, const char * output )
{
    cdk_stream_t inp = NULL, out = NULL, tmp = NULL;
    cdk_md_hd_t md = NULL;
    char buf[512], chk[512];
    const char * s;
    int rc = 0;
    int i, is_signed = 0, nbytes;
    int digest_algo = 0;

    if( output ) {
        rc = cdk_stream_create( output, &out );
        if( rc )
            return rc;
    }
  
    rc = cdk_stream_open( file, &inp );
    if( rc )
        return rc;  

    s = "-----BEGIN PGP SIGNED MESSAGE-----";
    while( !cdk_stream_eof( inp ) ) {
        nbytes = _cdk_stream_gets( inp, buf, sizeof buf-1 );
        if( !nbytes )
            break;
        if( !strncmp( buf, s, strlen( s ) ) ) {
            is_signed = 1;
            break;
        }
    }
    if( cdk_stream_eof( inp ) && !is_signed ) {
        rc = CDK_Armor_Error;
        goto leave;
    }
  
    while( !cdk_stream_eof( inp ) ) {
        nbytes = _cdk_stream_gets( inp, buf, sizeof buf-1 );
        if( !nbytes )
            break;
        if( nbytes == 1 ) /* empty line */
            break;
        else if( !strncmp( buf, "Hash: ", 6 ) ) {
            for( i = 0; (s = digest_table[i].name); i++ ) {
                if( !strcmp( buf + 6, s ) ) {
                    digest_algo = digest_table[i].algo;
                    break;
                }
            }
        }
    }

    if( digest_algo && cdk_md_test_algo( digest_algo ) ) {
        rc = CDK_Inv_Algo;
        goto leave;
    }
    if( !digest_algo )
        digest_algo = CDK_MD_MD5;
    md = cdk_md_open( digest_algo, 0 );
    if( !md ) {
        rc = CDK_Inv_Algo;
        goto leave;
    }

    s = "-----BEGIN PGP SIGNATURE-----";
    while( !cdk_stream_eof( inp ) ) {
        nbytes = _cdk_stream_gets( inp, buf, sizeof buf-1 );
        if( !nbytes )
            break;
        if( !strncmp( buf, s, strlen( s ) ) )
            break;
        else {
            cdk_stream_peek( inp, chk, sizeof chk-1 );
            i = strncmp( chk, s, strlen( s ) );
            if( strlen( buf ) == 0 && i == 0 )
                continue; /* skip last '\n' */
            _cdk_trim_string( buf, i == 0? 0 : 1 );
            cdk_md_write( md, buf, strlen( buf ) );
        }
        if( !strncmp( buf, "- ", 2 ) )
            memmove( buf, buf + 2, nbytes - 2 );
        if( out ) {
            buf[strlen( buf ) - 1] = 0;
            buf[strlen( buf ) - 1] = '\n';
            cdk_stream_write( out, buf, strlen( buf ) );
        }
    }

    tmp = cdk_stream_tmp( );
    if( !tmp ) {
        rc = CDK_Out_Of_Core;
        goto leave;
    }

    /* xxx revamp this part of the function */
    s = "-----BEGIN PGP SIGNATURE-----\n";
    _cdk_stream_puts( tmp, s );
    while( !cdk_stream_eof( inp ) ) {
        nbytes = _cdk_stream_gets( inp, buf, sizeof buf-1 );
        if( !nbytes )
            break;
        if( nbytes < (sizeof buf -3) ) {
            buf[nbytes-1] = '\n';
            buf[nbytes] = '\0';
        }
        cdk_stream_write( tmp, buf, nbytes );
    }
    cdk_stream_tmp_set_mode( tmp, STREAMCTL_READ );
    cdk_stream_seek( tmp, 0 );
    cdk_stream_set_armor_flag( tmp, 0 );
    cdk_stream_read( tmp, NULL, 0 );

    rc = _cdk_proc_packets( hd, tmp, NULL, NULL, md );

 leave:
    cdk_stream_close( out );
    cdk_stream_close( tmp );
    cdk_stream_close( inp );
    return rc;
}
