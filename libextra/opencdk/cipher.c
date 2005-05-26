/* -*- Mode: C; c-file-style: "bsd" -*-
 * cipher.c - Cipher filters
 *        Copyright (C) 2002, 2003 Timo Schulz
 *        Copyright (C) 1998-2001 Free Software Foundation
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
#include <assert.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "cipher.h"


static void (*progress_cb)( void * hd, unsigned off, unsigned len );
static void * progress_cb_value = NULL;


static off_t
fp_get_length( FILE * fp )
{
    struct stat statbuf;
    
    if( fstat( fileno( fp ), &statbuf ) )
        return (off_t)-1;
    return statbuf.st_size;
}


static int
hash_encode( void * opaque, FILE * in, FILE * out )
{
    md_filter_t * mfx = opaque;
    byte buf[8192];
    int nread;

    if( !mfx )
        return CDK_Inv_Value;

    _cdk_log_debug( "hash filter: encode (algo=%d)\n", mfx->digest_algo );
    
    if( !mfx->md ) {
        mfx->md = cdk_md_open( mfx->digest_algo, 0 );
        if( !mfx->md )
            return CDK_Inv_Algo;
    }
  
    while( !feof( in ) ) {
        nread = fread( buf, 1, sizeof buf-1, in );
        if( !nread )
            break;
        cdk_md_write( mfx->md, buf, nread );
    }
    
    wipemem( buf, sizeof buf );
    return 0;
}


int
_cdk_filter_hash( void * opaque, int ctl, FILE * in, FILE * out )
{
    if( ctl == STREAMCTL_READ )
        return hash_encode( opaque, in, out );
    else if( ctl == STREAMCTL_FREE ) {
        md_filter_t * mfx = opaque;
        if( mfx ) {
            _cdk_log_debug( "free hash filter\n" );
            cdk_md_close( mfx->md );
            mfx->md = NULL;
            return 0;
        }   
    }
    return CDK_Inv_Mode;
}


static int
write_header( cipher_filter_t * cfx, FILE * out )
{
    struct cdk_pkt_encrypted_s ed;
    CDK_PACKET pkt;
    cdk_dek_t dek = cfx->dek;
    byte temp[18];
    size_t blocksize = 0;
    int use_mdc = 0, nprefix;
    int rc = 0;

    blocksize = cdk_cipher_get_algo_blklen( dek->algo );
    if( blocksize < 8 || blocksize > 16 )
        return CDK_Inv_Algo;

    use_mdc = dek->use_mdc;
    if( blocksize != 8 )
        use_mdc = 1; /* enabled by default for all 128-bit block cipher */

    if( use_mdc && cfx->datalen )
        cfx->datalen += 22;
  
    memset( &ed, 0, sizeof ed );
    if( !cfx->blkmode.on ) {
        ed.len = cfx->datalen;
        ed.extralen = blocksize + 2;
    }
    
    if( use_mdc ) {
        ed.mdc_method = CDK_MD_SHA1;
        cfx->mdc = cdk_md_open( CDK_MD_SHA1, 0 );
        if( !cfx->mdc )
            return CDK_Inv_Algo;
    }

    cdk_pkt_init( &pkt );
    pkt.old_ctb = cfx->dek->rfc1991 && !cfx->blkmode.on? 1 : 0;
    pkt.pkttype = use_mdc ? CDK_PKT_ENCRYPTED_MDC : CDK_PKT_ENCRYPTED;
    pkt.pkt.encrypted = &ed;
    rc = _cdk_pkt_write_fp( out, &pkt );
    if( rc )
        return rc;
    nprefix = blocksize;
    gcry_randomize( temp, nprefix, GCRY_STRONG_RANDOM );
    temp[nprefix] = temp[nprefix - 2];
    temp[nprefix + 1] = temp[nprefix - 1];
    cfx->hd = cdk_cipher_open( dek->algo, use_mdc==0? 1 : 0,
                               dek->key, dek->keylen, NULL, 0 );
    if( !cfx->hd )
        return CDK_Inv_Algo;
    if( cfx->mdc )
        cdk_md_write( cfx->mdc, temp, nprefix + 2 );
    rc = cdk_cipher_encrypt( cfx->hd, temp, temp, nprefix + 2 );
    cdk_cipher_sync( cfx->hd );
    if( !rc )
        fwrite( temp, 1, nprefix+2, out );
    return rc;
}


static int
write_mdc_packet( FILE * out, cipher_filter_t * cfx )
{
    byte pktdata[22];
    int dlen = cdk_md_get_algo_dlen( CDK_MD_SHA1 );
    int rc;

    if( !out || !cfx )
        return CDK_Inv_Value;
  
    if( dlen != 20 )
        return CDK_Inv_Algo;
    /* we must hash the prefix of the MDC packet here */
    pktdata[0] = 0xd3;
    pktdata[1] = 0x14;
    cdk_md_putc( cfx->mdc, pktdata[0] );
    cdk_md_putc( cfx->mdc, pktdata[1] );
    cdk_md_final( cfx->mdc );
    memcpy( pktdata + 2, cdk_md_read( cfx->mdc, CDK_MD_SHA1 ), dlen );
    rc = cdk_cipher_encrypt( cfx->hd, pktdata, pktdata, dlen+2 );
    if( !rc )
        fwrite( pktdata, 1, dlen+2, out );
    wipemem( pktdata, sizeof pktdata );
    return rc;
}
  

static int
num2bits( size_t n )
{
    int i;
    if( !n )
        return -1;
    for( i = 0; n > 1; i++ )
        n >>= 1;
    return i;
}


static size_t
pow2( size_t y )
{
    size_t x = 1, i;
    for( i = 0; i < y; i++ )
        x <<= 1;
    return x; 
}


static int
write_partial_block( FILE * in, FILE * out, size_t * r_len,
                     cipher_filter_t * cfx )
{
    size_t n, nbytes;
    int nread, rc;
    byte buf[8193];

    if( !out || !cfx )
        return CDK_Inv_Value;

    if( *r_len > 512 ) {
        n = num2bits( *r_len );
        nbytes = pow2( n );
        fputc( 0xe0 | n, out );
        (*r_len) -= nbytes;
    }
    else {
        size_t pktlen = nbytes = *r_len;
        if( pktlen < 192 )
            fputc( pktlen, out );
        else if( pktlen < 8384 ) {
            pktlen -= 192;
            fputc( (pktlen/256) + 192, out );
            fputc( pktlen % 256, out );
        }
        (*r_len) -= nbytes;
    }
    while( nbytes > 0 ) {
        nread = fread( buf, 1, sizeof buf-1, in );
        if( !nread )
            break;
        if( cfx->mdc )
            cdk_md_write( cfx->mdc, buf, nread );
        rc = cdk_cipher_encrypt( cfx->hd, buf, buf, nread );
        if( rc )
            break;
        nbytes -= nread;
        fwrite( buf, 1, nread, out );
    }
    return 0;
}


static int
cipher_encode_file( void * opaque, FILE * in, FILE * out )
{
    struct stat statbuf;
    cipher_filter_t * cfx = opaque;
    byte buf[8192];
    size_t len, len2;
    int rc = 0, nread;

    if( !cfx || !in || !out )
        return CDK_Inv_Value;

    if( fstat( fileno( in ), &statbuf ) )
        return CDK_File_Error;
    len = len2 = statbuf.st_size;
    while( !feof( in ) ) {
        if( cfx->blkmode.on ) {
            rc = write_partial_block( in, out, &len2, cfx );
            if( rc )
                break;
            continue;
        }
        nread = fread( buf, 1, sizeof buf -1, in );
        if( !nread )
            break;
        if( cfx->mdc )
            cdk_md_write( cfx->mdc, buf, nread );
        rc = cdk_cipher_encrypt( cfx->hd, buf, buf, nread );
        if( rc )
            break;
        if( progress_cb )
            progress_cb( progress_cb_value, ftell( in ), len );
        fwrite( buf, 1, nread, out );
    }
    wipemem( buf, sizeof buf );
    if( !rc && cfx->mdc )
        rc = write_mdc_packet( out, cfx );
    return rc;
}


static int
read_header( cipher_filter_t * cfx, FILE * in )
{
    cdk_dek_t dek;
    byte temp[32];
    int blocksize, nprefix;
    int i = 0, c = 0, rc = 0;

    if( !cfx || !in )
        return CDK_Inv_Value;

    dek = cfx->dek;
    blocksize = cdk_cipher_get_algo_blklen( dek->algo );
    if( blocksize < 8 || blocksize > 16 )
        return CDK_Inv_Algo;
  
    nprefix = blocksize;
    if( cfx->datalen && cfx->datalen < (nprefix + 2) )
        return CDK_Inv_Value;
    if( cfx->mdc_method ) {
        cfx->mdc = cdk_md_open( cfx->mdc_method, 0 );
        if( !cfx->mdc )
            return CDK_Inv_Algo;
    }
    cfx->hd = cdk_cipher_open( dek->algo, cfx->mdc_method==0? 1 : 0,
                               dek->key, dek->keylen, NULL, 0 );
    if( !cfx->hd )
        return CDK_Inv_Algo;
    for( i = 0; i < (nprefix + 2); i++ ) {
        c = fgetc( in );
        if( c == EOF )
            return CDK_File_Error;
        temp[i] = c;
    }
    rc = cdk_cipher_decrypt( cfx->hd, temp, temp, nprefix + 2 );
    if( rc )
        return rc;
    cdk_cipher_sync( cfx->hd );
    i = nprefix;
    if( temp[i - 2] != temp[i] || temp[i - 1] != temp[i + 1] )
        rc = CDK_Chksum_Error;
    if( cfx->mdc )
        cdk_md_write( cfx->mdc, temp, nprefix + 2 );
    if( cfx->blkmode.on )
        cfx->blkmode.size -= (nprefix + 2);
    return rc;
}


static int
finalize_mdc( cdk_md_hd_t md, const byte * buf, size_t nread )
{
    byte mdcbuf[20];
    int dlen = cdk_md_get_algo_dlen( CDK_MD_SHA1 );
    int rc = 0;

    if( cdk_md_get_algo( md ) != CDK_MD_SHA1 || dlen != 20 )
        return CDK_Inv_Algo;
    
    if( buf[nread - dlen - 2] == 0xd3 && buf[nread - dlen - 1] == 0x14 ) {
        cdk_md_write( md, buf, nread - dlen );
        cdk_md_final( md );
        memcpy( mdcbuf, cdk_md_read( md, 0 ), dlen );
        if( memcmp( mdcbuf, buf + nread - dlen, dlen ) )
            rc = CDK_Bad_MDC;
        return rc;
    }
    wipemem( mdcbuf, sizeof mdcbuf );
    return CDK_Inv_Packet;
}

  
static int
cipher_decode_file( void * opaque, FILE * in, FILE * out )
{
    cipher_filter_t * cfx = opaque;
    byte buf[8192];
    int rc = 0, nread, nreq;

    if( !cfx || !in || !out )
        return CDK_Inv_Value;

    while( !feof( in ) ) {
        _cdk_log_debug( "partial on=%d size=%lu\n",
                        cfx->blkmode.on, cfx->blkmode.size );
        nreq = cfx->blkmode.on? cfx->blkmode.size: sizeof buf-1;
        nread = fread( buf, 1, nreq, in );
        if( !nread )
            break;
        rc = cdk_cipher_decrypt( cfx->hd, buf, buf, nread );
        if( rc )
            break;
        if( feof( in ) && cfx->mdc )
            rc = finalize_mdc( cfx->mdc, buf, nread );
        else if( cfx->mdc )
            cdk_md_write( cfx->mdc, buf, nread );
        fwrite( buf, 1, nread, out );
        if( cfx->blkmode.on ) {
            cfx->blkmode.size = _cdk_pkt_read_len( in, &cfx->blkmode.on );
            if( cfx->blkmode.size == (size_t)EOF )
                return CDK_Inv_Packet;
        }
    }
    wipemem( buf, sizeof buf );
    return rc;
}


int
cipher_decode( void * opaque, FILE * in, FILE * out )
{
    cipher_filter_t * cfx = opaque;
    int rc;

    _cdk_log_debug( "cipher filter: decode\n" );
  
    if( !cfx || !in || !out )
        return CDK_Inv_Value;
  
    rc = read_header( cfx, in );
    if( !rc )
        rc = cipher_decode_file( cfx, in, out );
    return rc;
}
    

int
cipher_encode( void * opaque, FILE * in, FILE * out )
{
    cipher_filter_t * cfx = opaque;
    int rc;

    _cdk_log_debug( "cipher filter: encode\n" );
  
    if( !cfx || !in || !out )
        return CDK_Inv_Value;

    cfx->datalen = fp_get_length( in );
    if( cfx->datalen < 8192 && cfx->blkmode.on )
        cfx->blkmode.on = 0;
    rc = write_header( cfx, out );
    if( !rc )
        rc = cipher_encode_file( cfx, in, out );
    return rc;
}


int
_cdk_filter_cipher( void * opaque, int ctl, FILE * in, FILE * out )
{
    if( ctl == STREAMCTL_READ )
        return cipher_decode( opaque, in, out );
    else if( ctl == STREAMCTL_WRITE )
        return cipher_encode( opaque, in, out );
    else if( ctl == STREAMCTL_FREE ) {
        cipher_filter_t * cfx = opaque;
        if( cfx ) {
            _cdk_log_debug( "free cipher filter\n" );
            cdk_md_close( cfx->mdc );
            cfx->mdc = NULL;
            cdk_cipher_close( cfx->hd );
            cfx->hd = NULL;
        }
    }
    return CDK_Inv_Mode;
}


void
cdk_set_progress_handler( void (*cb)(void * hd, unsigned off, unsigned size),
                          void * cb_value )
{
    progress_cb = cb;
    progress_cb_value = cb_value;
}

