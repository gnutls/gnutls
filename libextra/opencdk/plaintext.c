/* -*- Mode: C; c-file-style: "bsd" -*-
 * plaintext.c - Literal packet filters
 *       Copyright (C) 2002, 2003 Timo Schulz
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"


static int
literal_decode( void * opaque, FILE * in, FILE * out )
{
    literal_filter_t * pfx = opaque;
    cdk_stream_t si, so;
    CDK_PACKET pkt;
    cdk_pkt_literal_t pt;
    byte buf[8192];
    size_t nread;
    int rc, bufsize;

    _cdk_log_debug( "literal filter: decode\n" );
  
    if (!pfx || !in || !out)
        return CDK_Inv_Value;

    si = _cdk_stream_fpopen( in, STREAMCTL_READ );
    if (!si)
        return CDK_Out_Of_Core;
    so = _cdk_stream_fpopen( out, STREAMCTL_WRITE );
    if( !so ) {
        cdk_stream_close( si );
        return CDK_Out_Of_Core;
    }
    cdk_pkt_init( &pkt );
    rc = cdk_pkt_read( si, &pkt );
    if( pkt.pkttype != CDK_PKT_LITERAL ) {
        if( pkt.pkttype )
            cdk_pkt_free( &pkt );
        return rc;
    }
    pt = pkt.pkt.literal;
    pfx->mode = pt->mode;
    pfx->filename = cdk_strdup( pt->name? pt->name : " " );
    if( !pfx->filename ) {
        cdk_pkt_free( &pkt );
        return CDK_Out_Of_Core;
    }
    while( !feof( in ) ) {
        _cdk_log_debug( "partial on=%d size=%lu\n",
                        pfx->blkmode.on, pfx->blkmode.size );
        if( pfx->blkmode.on )
            bufsize = pfx->blkmode.size;
        else
            bufsize = pt->len < sizeof buf-1? pt->len : sizeof buf-1;
        nread = cdk_stream_read( pt->buf, buf, bufsize );
        if( nread == EOF ) {
            rc = CDK_File_Error;
            break;
        }
        if( pfx->md )
            cdk_md_write (pfx->md, buf, nread);
        cdk_stream_write( so, buf, nread );
        pt->len -= nread;
        if( pfx->blkmode.on ) {
            pfx->blkmode.size = _cdk_pkt_read_len( in, &pfx->blkmode.on );
            if( pfx->blkmode.size == (size_t)EOF )
                return CDK_Inv_Packet;
        }
        if( pt->len <= 0 && !pfx->blkmode.on )
            break;
    }
    cdk_stream_close( si );
    cdk_stream_close( so );
    cdk_pkt_free( &pkt );
    return rc;
}


static int
literal_encode (void * opaque, FILE * in, FILE * out)
{
    literal_filter_t * pfx = opaque;
    cdk_pkt_literal_t pt;
    cdk_stream_t si;
    CDK_PACKET pkt;
    size_t filelen;
    int rc;

    _cdk_log_debug ("literal filter: encode\n");
  
    if (!pfx || !in || !out)
        return CDK_Inv_Value;
  
    if (!pfx->filename) {
        pfx->filename = cdk_strdup ("_CONSOLE");
        if( !pfx->filename )
            return CDK_Out_Of_Core;
    }

    si = _cdk_stream_fpopen (in, STREAMCTL_READ);
    if (!si)
        return CDK_Out_Of_Core;

    filelen = strlen (pfx->filename);
    pt = cdk_calloc (1, sizeof *pt + filelen - 1);
    if (!pt)
        return CDK_Out_Of_Core;
    memcpy (pt->name, pfx->filename, filelen);
    pt->namelen = filelen;
    pt->name[pt->namelen] = '\0';
    pt->timestamp = _cdk_timestamp ();
    pt->mode = pfx->mode ? 't' : 'b';
    pt->len = cdk_stream_get_length (si);
    pt->buf = si;
    cdk_pkt_init (&pkt);
    pkt.old_ctb = pfx->rfc1991? 1 : 0;
    pkt.pkttype = CDK_PKT_LITERAL;
    pkt.pkt.literal = pt;
    rc = _cdk_pkt_write_fp (out, &pkt);

    cdk_free (pt);
    cdk_stream_close (si);
    return rc;
}


int
_cdk_filter_literal( void * opaque, int ctl, FILE * in, FILE * out )
{
    if( ctl == STREAMCTL_READ )
        return literal_decode( opaque, in, out );
    else if( ctl == STREAMCTL_WRITE )
        return literal_encode( opaque, in, out );
    else if( ctl == STREAMCTL_FREE ) {
        literal_filter_t * pfx = opaque;
        if( pfx ) {
            cdk_free( pfx->filename );
            pfx->filename = NULL;
        }
    }
    return CDK_Inv_Mode;
}


static int
text_encode( void * opaque, FILE * in, FILE * out )
{
    const char * s;
    char buf[1024];

    if( !in || !out )
        return CDK_Inv_Value;
  
    while( !feof( in ) ) {
        s = fgets( buf, sizeof buf-1, in );
        if( !s )
            break;
        _cdk_trim_string( buf, 1 );
        fwrite( buf, 1, strlen( buf ), out );
    }
    
    return 0;
}

      
static int
text_decode( void * opaque, FILE * in, FILE * out )
{
    text_filter_t * tfx = opaque;
    const char * s;
    char buf[1024];

    if( !tfx || !in || !out )
        return CDK_Inv_Value;

    while( !feof( in ) ) {
        s = fgets( buf, sizeof buf-1, in );
        if( !s )
            break;
        _cdk_trim_string( buf, 0 );
        fwrite( buf, 1, strlen( buf ), out );
        fwrite( tfx->lf, 1, strlen( tfx->lf ), out );
    }
    
    return 0;
}


int
_cdk_filter_text( void * opaque, int ctl, FILE * in, FILE * out )
{
    if( ctl == STREAMCTL_READ )
        return text_encode( opaque, in, out );
    else if( ctl == STREAMCTL_WRITE )
        return text_decode( opaque, in, out );
    else if( ctl == STREAMCTL_FREE ) {
        text_filter_t * tfx = opaque;
        if( tfx ) {
            _cdk_log_debug( "free text filter\n" );
            tfx->lf = NULL;
        }
    }
    return CDK_Inv_Mode;
}



