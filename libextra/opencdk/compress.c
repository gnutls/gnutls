/* -*- Mode: C; c-file-style: "bsd" -*-
 * compress.c - Compression filters
 *        Copyright (C) 2002, 2003 Timo Schulz
 *        Copyright (C) 1998-2002 Free Software Foundation
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
#include <time.h>
#ifdef HAVE_LIBZ
# include <zlib.h>
#endif

#include "opencdk.h"
#include "main.h"
#include "filters.h"

#ifdef HAVE_LIBZ
static int
compress_data( z_stream * zs, int flush,
               byte * inbuf, size_t insize, FILE * out )
{
    int nbytes, zrc;
    byte buf[4096];
  
    zs->next_in = inbuf;
    zs->avail_in = insize;

    do {
        zs->next_out = buf;
        zs->avail_out = sizeof buf;
      
        zrc = deflate( zs, flush );
        if( zrc == Z_STREAM_END && flush == Z_FINISH )
            ;
        else if( zrc != Z_OK )
            break;
        nbytes = sizeof( buf ) - zs->avail_out;
        fwrite( buf, 1, nbytes, out );
    }
    while( zs->avail_out == 0 || (flush == Z_FINISH && zrc != Z_STREAM_END) );
    return zrc;    
}


static int
decompress_data( compress_filter_t * zfx, z_stream * zs,
                 FILE * in, size_t * ret_len )
{
    int nread = 0, nold;
    int rc = 0, zrc = 0;

    while( zs->avail_out != 0 ) {
        if( !zs->avail_in ) {
            nread = fread( zfx->inbuf, 1, zfx->inbufsize, in );
            zs->next_in = zfx->inbuf;
            zs->avail_in = nread;
        }
        nold = zs->avail_out;
        zrc = inflate( zs, Z_SYNC_FLUSH );
        if( zrc != Z_OK && zrc != Z_STREAM_END ) {
            rc = CDK_Zlib_Error;
            break;
        }
        *ret_len = zfx->outbufsize - zs->avail_out;
        if( nold == zs->avail_out )
            break;
        if( zrc == Z_STREAM_END ) {
            rc = EOF; /* eof */
            break;
        }
    }
    if( !nread && feof( in ) )
        rc = -1;
    return rc;
}


/* in some cases it might be possible that the packet header was not
   readed, so we do it here. but we assume the the algo was already set. */
static void
skip_pktheader( FILE * in )
{
    int ctb, pkttype, pos;

    pos = ftell (in);
    ctb = fgetc (in);
    if (ctb & 0x80) {
        pkttype = ctb & 0x40 ? (ctb & 0x3f) : ((ctb >> 2) & 0xf);
        if (pkttype == CDK_PKT_COMPRESSED) {
            fgetc (in);
            return;
        }
    }
    fseek (in, pos, SEEK_SET);
}

  
static int
compress_decode( void * opaque, FILE * in, FILE * out )
{
    compress_filter_t * zfx = opaque;
    z_stream * zs;
    int zrc, rc = 0;
    size_t nbytes;

    _cdk_log_debug ("compress filter: decode (algo=%d)\n", zfx->algo);
  
    if (!zfx || !in || !out)
        return CDK_Inv_Value;
  
    zs = cdk_calloc (1, sizeof *zs);
    if (!zs)
        return CDK_Out_Of_Core;

    if (zfx->algo == CDK_COMPRESS_ZIP)
        zrc = inflateInit2 (zs, -13);
    else
        zrc = inflateInit (zs);
    if (zrc != Z_OK)
        return CDK_Zlib_Error;

    zfx->outbufsize = 8192;
    zfx->inbufsize = 2048;
    memset (zfx->inbuf, 0, sizeof zfx->inbuf);
    zs->avail_in = 0;  

    skip_pktheader (in);
    while (rc != -1) {
        zs->next_out = zfx->outbuf;
        zs->avail_out = 8192;
        rc = decompress_data (zfx, zs, in, &nbytes);
        fwrite (zfx->outbuf, 1, nbytes, out);
    }
    inflateEnd (zs);
    cdk_free (zs);
    if (rc == CDK_EOF)
        rc = 0;
    return rc;
}
  

static int
compress_encode( void * opaque, FILE * in, FILE * out )
{
    compress_filter_t * zfx = opaque;
    z_stream * zs;
    struct cdk_pkt_compressed_s cd;
    CDK_PACKET pkt;
    clock_t start, end;
    int rc, zrc, nread;

    _cdk_log_debug ("compress filter: encode\n");
  
    if( !zfx || !in || !out )
        return CDK_Inv_Value;

    if( !zfx->algo )
        zfx->algo = CDK_COMPRESS_ZIP;

    memset( &cd, 0, sizeof cd );
    cd.len = 0;
    cd.algorithm = zfx->algo;
    pkt.pkttype = CDK_PKT_COMPRESSED;
    pkt.pkt.compressed = &cd;
    rc = _cdk_pkt_write_fp( out, &pkt );
    if( rc )
        return rc;

    zs = cdk_calloc( 1, sizeof *zs );
    if( !zs )
        return CDK_Out_Of_Core;
    if( zfx->algo == CDK_COMPRESS_ZIP )
        rc = deflateInit2( zs, zfx->level, Z_DEFLATED, -13, 8,
                           Z_DEFAULT_STRATEGY );
    else
        rc = deflateInit( zs, zfx->level );
    if( rc != Z_OK ) {
        cdk_free( zs );
        return CDK_Zlib_Error;
    }
    zfx->outbufsize = 8192;
    memset( zfx->outbuf, 0, sizeof zfx->outbuf );

    start = clock ();
    while (!feof (in)) {
        nread = fread (zfx->outbuf, 1, zfx->outbufsize, in);
        if (!nread)
            break;
        zrc = compress_data (zs, Z_NO_FLUSH, zfx->outbuf, nread, out);
        if (zrc) {
            rc = CDK_Zlib_Error;
            break;
        }
    }
    if (!rc) {
        nread = 0;
        zrc = compress_data (zs, Z_FINISH, zfx->outbuf, nread, out);
        if (zrc != Z_STREAM_END)
            rc = CDK_Zlib_Error;
    }
    end = clock ();
    /*printf ("compress encode: elapsed time %d\n", end - start);*/
    deflateEnd (zs);
    cdk_free (zs);
    return rc;
}


int
_cdk_filter_compress( void * opaque, int ctl, FILE * in, FILE * out )
{
    if( ctl == STREAMCTL_READ )
        return compress_decode( opaque, in, out );
    else if( ctl == STREAMCTL_WRITE )
        return compress_encode( opaque, in, out );
    else if( ctl == STREAMCTL_FREE ) {
        compress_filter_t * zfx = opaque;
        if( zfx ) {
            _cdk_log_debug( "free compress filter\n" );
            zfx->level = 0;
            zfx->algo = 0;
        }
    }
    return CDK_Inv_Mode;
}
#else
int
_cdk_filter_compress( void * opaque, int ctl, FILE * in, FILE * out )
{
    return CDK_Not_Implemented;    
}
#endif /* HAVE_LIBZ */


