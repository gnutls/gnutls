/* -*- Mode: C; c-file-style: "bsd" -*-
 * write-packet.c - Write OpenPGP packets
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <string.h>
#include <stdio.h>

#include "opencdk.h"
#include "main.h"


static int
stream_write( cdk_stream_t s, const void * buf, size_t count )
{
    int nwritten = cdk_stream_write( s, buf, count );
    if( nwritten == EOF )
        return CDK_File_Error;
    return 0;  
}


static int
stream_read( cdk_stream_t s, void * buf, size_t count, size_t * r_nread )
{
    int nread;
    
    if( !r_nread )
        return CDK_Inv_Value;
    nread = cdk_stream_read( s, buf, count );
    if( nread == EOF )
        return CDK_File_Error;
    *r_nread = nread;
    return 0;
}


static int
stream_putc( cdk_stream_t s, int c )
{
    int nwritten = cdk_stream_putc( s, c );
    if( nwritten == EOF )
        return CDK_File_Error;
    return 0;
}


static int
write_32( cdk_stream_t out, u32 u )
{
    byte buf[4];
    buf[0] = u >> 24;
    buf[1] = u >> 16;
    buf[2] = u >> 8;
    buf[3] = u;
    return stream_write( out, buf, 4 );
}


static int
write_16( cdk_stream_t out, u16 u )
{
    byte buf[2];
    buf[0] = u >> 8;
    buf[1] = u;
    return stream_write( out, buf, 2 );
}


static size_t
calc_mpisize( cdk_mpi_t mpi[4], int ncount )
{
    size_t nbytes, size = 0;
    int i;

    for( i = 0; i < ncount; i++ ) {
        nbytes = (mpi[i]->bits + 7) / 8 + 2;
        size += nbytes;
    }
    return size;
}


static int
write_mpi( cdk_stream_t out, cdk_mpi_t m )
{
    if( !out || !m )
        return CDK_Inv_Value;
    if( m->bits > MAX_MPI_BITS || !m->bits )
        return CDK_MPI_Error;
    if( !m->bytes )
        m->bytes = (m->bits + 7) / 8;
    return stream_write( out, m->data, m->bytes + 2 );
}


static int
write_mpibuf( cdk_stream_t out, cdk_mpi_t mpi[4], int count )
{
    int i, rc = 0;
  
    for( i = 0; i < count; i++ ) {
        rc = write_mpi( out, mpi[i] );
        if( rc )
            break;
    }
    return rc;
}


static int
pkt_encode_len( cdk_stream_t out, size_t pktlen )
{
    int rc = 0;

    if( !out )
        return CDK_Inv_Value;
    if( !pktlen )
        return 0;
    else if( pktlen < 192 )
        rc = stream_putc( out, pktlen );
    else if( pktlen < 8384 ) {
        pktlen -= 192;
        rc = stream_putc( out, (pktlen / 256) + 192 );
        if( !rc )
            rc = stream_putc( out, (pktlen % 256) );
    }
    else {
        rc = stream_putc( out, 255 );
        if( !rc )
            rc = write_32( out, pktlen );
    }
    return rc;
}


static int
write_head_new( cdk_stream_t out, size_t size, int type )
{
    int rc = 0;

    if( !out )
        return CDK_Inv_Value;
    if( type < 0 || type > 63 )
        return CDK_Inv_Packet;
    rc = stream_putc( out, (0xC0 | type) );
    if( !rc )
        rc = pkt_encode_len( out, size );
    return rc;
}


static int
write_head_old( cdk_stream_t out, size_t size, int type )
{
    int ctb;
    int rc;

    if( !out )
        return CDK_Inv_Value;
    if( type < 0 || type > 16 )
        return CDK_Inv_Packet;
    ctb = 0x80 | (type << 2);
    if( !size )
        ctb |= 3;
    else if( size < 256 )
        ;
    else if( size < 65536 )
        ctb |= 1;
    else
        ctb |= 2;
    rc = stream_putc( out, ctb );
    if( !size )
        return rc;
    if( !rc ) {
        if( size < 256 )
            rc = stream_putc( out, size );
        else if( size < 65536 )
            rc = write_16( out, size );
        else
            rc = write_32( out, size );
    }
    return rc;
}


/* write special PGP2 packet header. PGP2 (wrongly) uses two byte header
   length for signatures and keys even if the size is < 256. */
static int
pkt_write_head2( cdk_stream_t out, size_t size, int type )
{
    int rc = cdk_stream_putc( out, 0x80 | (type << 2) | 1 );
    if( !rc )
        rc = cdk_stream_putc( out, size >> 8 );
    if( !rc )
        rc = cdk_stream_putc( out, size & 0xff );
    return rc;
}


static int
pkt_write_head( cdk_stream_t out, int old_ctb, size_t size, int type )
{
    return old_ctb?
        write_head_old( out, size, type ) :
        write_head_new( out, size, type );
}


static int
write_encrypted( cdk_stream_t out, cdk_pkt_encrypted_t enc, int old_ctb )
{
    size_t nbytes;
    int rc = 0;

    if( !out || !enc )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug ("** write encrypted packet %lu bytes\n", enc->len);

    nbytes = enc->len ? (enc->len + enc->extralen) : 0;
    rc = pkt_write_head( out, old_ctb, nbytes, CDK_PKT_ENCRYPTED );
    /* rest of the packet is ciphertext */
    return rc;
}


static int
write_encrypted_mdc( cdk_stream_t out, cdk_pkt_encrypted_t enc )
{
    size_t nbytes;
    int rc = 0;

    if( !out || !enc )
        return CDK_Inv_Value;
    if( !enc->mdc_method )
        return CDK_Inv_Packet;

    if( DEBUG_PKT )
        _cdk_log_debug ("** write encrypted mdc packet %lu bytes\n", enc->len);

    nbytes = enc->len ? (enc->len + enc->extralen + 1) : 0;
    rc = pkt_write_head( out, 0, nbytes, CDK_PKT_ENCRYPTED_MDC );
    if( !rc )
        rc = stream_putc( out, 1 ); /* version */
    /* rest of the packet is ciphertext */
    return rc;
}


static int
write_symkey_enc( cdk_stream_t out, cdk_pkt_symkey_enc_t ske )
{
    cdk_s2k_t s2k;
    size_t size = 0, s2k_size = 0;
    int rc = 0;

    if( !out || !ske )
        return CDK_Inv_Value;
    if( ske->version != 4 )
        return CDK_Inv_Packet;

    if( DEBUG_PKT )
        _cdk_log_debug ("** write symmetric key encrypted packet\n");

    s2k = ske->s2k;
    if( s2k->mode == 1 || s2k->mode == 3 )
        s2k_size = 8;
    if( s2k->mode == 3 )
        s2k_size++;
    size = 4 + s2k_size + ske->seskeylen;
    rc = pkt_write_head( out, 0, size, CDK_PKT_SYMKEY_ENC );
    if( !rc )
        rc = stream_putc( out, ske->version );
    if( !rc )
        rc = stream_putc( out, ske->cipher_algo );
    if( !rc )
        rc = stream_putc( out, s2k->mode );
    if( !rc )
        rc = stream_putc( out, s2k->hash_algo );
    if( s2k->mode == 1 || s2k->mode == 3 ) {
        rc = stream_write( out, s2k->salt, 8 );
        if( !rc && s2k->mode == 3 )
            rc = stream_putc( out, s2k->count );
    }
    return rc;
}


static int
write_pubkey_enc( cdk_stream_t out, cdk_pkt_pubkey_enc_t pke, int old_ctb )
{
    size_t size;
    int rc = 0, nenc = 0;

    if( !out || !pke )
        return CDK_Inv_Value;
    if( pke->version < 2 || pke->version > 3 )
        return CDK_Inv_Packet;
    if( !KEY_CAN_ENCRYPT( pke->pubkey_algo ) )
        return CDK_Inv_Algo;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write public key encrypted packet\n");

    nenc = cdk_pk_get_nenc( pke->pubkey_algo );
    size = 10 + calc_mpisize( pke->mpi, nenc );
    rc = pkt_write_head( out, old_ctb, size, CDK_PKT_PUBKEY_ENC );
    if( !rc )
        rc = stream_putc( out, pke->version );
    if( !rc )
        rc = write_32( out, pke->keyid[0] );
    if( !rc )
        rc = write_32( out, pke->keyid[1] );
    if( !rc )
        rc = stream_putc( out, pke->pubkey_algo );
    if( !rc )
        rc = write_mpibuf( out, pke->mpi, nenc );
    return rc;
}


static int
write_mdc( cdk_stream_t out, cdk_pkt_mdc_t mdc )
{
    int rc = 0;

    if( !out || !mdc )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug ("** write_mdc\n");

    /* This packet requires a fixed header encoding */
    rc = stream_putc (out, 0xD3); /* packet ID and 1 byte length */
    if( !rc )
        rc = stream_putc( out, 0x14 );
    if( !rc )
        rc = stream_write( out, mdc->hash, sizeof mdc->hash );
    return rc;
}


static size_t
calc_subpktsize( cdk_subpkt_t s )
{
    size_t nbytes;

    if( !s )
        return 0;
    _cdk_subpkt_get_array( s, 1, &nbytes );
    return nbytes;
}


static int
write_signature( cdk_stream_t out, cdk_pkt_signature_t sig, int old_ctb )
{
    byte * buf;
    size_t nbytes, size;
    int nsig = 0, rc = 0;

    if( !out || !sig )
        return CDK_Inv_Value;

    if( !KEY_CAN_SIGN( sig->pubkey_algo ) )
        return CDK_Inv_Algo;
    if( sig->version < 3 || sig->version > 4 )
        return CDK_Inv_Packet;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write signature packet\n");

    nsig = cdk_pk_get_nsig( sig->pubkey_algo );
    if( !nsig )
        return CDK_Inv_Algo;
    if( sig->version < 4 ) {
        size = 19 + calc_mpisize( sig->mpi, nsig );
        if( is_RSA( sig->pubkey_algo ) )
            rc = pkt_write_head2( out, size, CDK_PKT_SIGNATURE );
        else
            rc = pkt_write_head( out, old_ctb, size, CDK_PKT_SIGNATURE );
        if( !rc )
            rc = stream_putc( out, sig->version );
        if( !rc )
            rc = stream_putc( out, 5 );
        if( !rc )
            rc = stream_putc( out, sig->sig_class );
        if( !rc )
            rc = write_32( out, sig->timestamp );
        if( !rc )
            rc = write_32( out, sig->keyid[0] );
        if( !rc )
            rc = write_32( out, sig->keyid[1] );
        if( !rc )
            rc = stream_putc( out, sig->pubkey_algo );
        if( !rc )
            rc = stream_putc( out, sig->digest_algo );
        if( !rc )
            rc = stream_putc( out, sig->digest_start[0] );
        if( !rc )
            rc = stream_putc( out, sig->digest_start[1] );
    }
    else {
        size = 10 + calc_subpktsize( sig->hashed )
            + calc_subpktsize( sig->unhashed )
            + calc_mpisize( sig->mpi, nsig );
        rc = pkt_write_head( out, 0, size, CDK_PKT_SIGNATURE );
        if( !rc )
            rc = stream_putc( out, 4 );
        if( !rc )
            rc = stream_putc( out, sig->sig_class );
        if( !rc )
            rc = stream_putc( out, sig->pubkey_algo );
        if( !rc )
            rc = stream_putc( out, sig->digest_algo );
        if( !rc )
            rc = write_16( out, sig->hashed_size );
        if( !rc ) {
            buf = _cdk_subpkt_get_array( sig->hashed, 0, &nbytes );
            if( !buf )
                return CDK_Out_Of_Core;
            rc = stream_write( out, buf, nbytes );
            cdk_free( buf );
        }
        if( !rc )
            rc = write_16( out, sig->unhashed_size );
        if( !rc ) {
            buf = _cdk_subpkt_get_array( sig->unhashed, 0, &nbytes );
            if( !buf )
                return CDK_Out_Of_Core;
            rc = stream_write( out, buf, nbytes );
            cdk_free( buf );
        }
        if( !rc )
            rc = stream_putc( out, sig->digest_start[0] );
        if( !rc )
            rc = stream_putc( out, sig->digest_start[1] );
    }
    if( !rc )
        rc = write_mpibuf( out, sig->mpi, nsig );
    return rc;
}


static int
write_public_key( cdk_stream_t out, cdk_pkt_pubkey_t pk,
                  int is_subkey, int old_ctb )
{
    int rc = 0;
    int pkttype, ndays = 0;
    size_t npkey = 0, size = 6;

    if( !out || !pk )
        return CDK_Inv_Value;
    if( pk->version < 2 || pk->version > 4 )
        return CDK_Inv_Packet;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write public key packet\n");

    pkttype = is_subkey? CDK_PKT_PUBLIC_SUBKEY : CDK_PKT_PUBLIC_KEY;
    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    if( pk->version < 4 )
        size += 2; /* expire date */
    if( is_subkey )
        old_ctb = 0;
    size += calc_mpisize( pk->mpi, npkey );
    if( old_ctb )
        rc = pkt_write_head2( out, size, pkttype );
    else
        rc = pkt_write_head( out, old_ctb, size, pkttype );
    if( !rc )
        rc = stream_putc( out, pk->version );
    if( !rc )
        rc = write_32( out, pk->timestamp );
    if( !rc && pk->version < 4 ) {
        if( pk->expiredate )
            ndays = (u16) ((pk->expiredate - pk->timestamp) / 86400L);
        rc = write_16( out, ndays );
    }
    if( !rc )
        rc = stream_putc( out, pk->pubkey_algo );
    if( !rc )
        rc = write_mpibuf( out, pk->mpi, npkey );
    return rc;
}


static int
calc_s2ksize( cdk_pkt_seckey_t sk )
{
    size_t nbytes = 0;
    cdk_s2k_t s2k;
  
    if( !sk->is_protected )
        return 0;
    s2k = sk->protect.s2k;
    switch( s2k->mode ) {
    case 0: nbytes = 2; break;
    case 1: nbytes = 10; break;
    case 3: nbytes = 11; break;
    }
    nbytes += sk->protect.ivlen;
    nbytes++; /* single cipher byte */
    return nbytes;
}

  
static int
write_secret_key( cdk_stream_t out, cdk_pkt_seckey_t sk,
                  int is_subkey, int old_ctb )
{
    cdk_pkt_pubkey_t pk = NULL;
    size_t size = 6, npkey, nskey;
    int pkttype, s2k_mode;
    int rc = 0;

    if( !out || !sk || !sk->pk )
        return CDK_Inv_Value;

    pk = sk->pk;
    if( pk->version < 2 || pk->version > 4 )
        return CDK_Inv_Packet;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write secret key packet\n");

    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    nskey = cdk_pk_get_nskey( pk->pubkey_algo );
    if( !npkey || !nskey )
        return CDK_Inv_Algo;
    if( pk->version < 4 )
        size += 2;
    /* if the key is unprotected, the 3 extra bytes are:
       1 octet  - cipher algorithm byte (0x00)
       2 octets - simple checksum */ 
    size = !sk->is_protected? size + 3 : size + 1 + calc_s2ksize( sk );
    size += calc_mpisize( pk->mpi, npkey );
    if( sk->version == 3 || !sk->is_protected ) {
        if( sk->version == 3 ) {            
            size += 2; /* force simple checksum */
            sk->protect.sha1chk = 0;
        }
        else
            size += sk->protect.sha1chk? 20 : 2;
        size += calc_mpisize( sk->mpi, nskey );
    }
    else /* we do not know anything about the encrypted mpi's so we
            treat the data as opaque. */
        size += sk->enclen;

    pkttype = is_subkey? CDK_PKT_SECRET_SUBKEY : CDK_PKT_SECRET_KEY;
    rc = pkt_write_head( out, old_ctb, size, pkttype );
    if( !rc )
        rc = stream_putc( out, pk->version );
    if( !rc )
        rc = write_32( out, pk->timestamp );
    if( !rc && pk->version < 4 ) {
        u16 ndays = 0;
        if( pk->expiredate )
            ndays = (u16) ((pk->expiredate - pk->timestamp) / 86400L);
        rc = write_16( out, ndays );
    }
    if( !rc )
        rc = stream_putc( out, pk->pubkey_algo );
    if( !rc )
        rc = write_mpibuf( out, pk->mpi, npkey );
    if( sk->is_protected == 0 )
        rc = stream_putc( out, 0x00 );
    else {
        if( is_RSA( pk->pubkey_algo ) && pk->version < 4 )
            stream_putc( out, sk->protect.algo );
        else if( sk->protect.s2k ) {
            s2k_mode = sk->protect.s2k->mode;
            rc = stream_putc( out, sk->protect.sha1chk? 0xFE : 0xFF );
            if( !rc )
                rc = stream_putc( out, sk->protect.algo );
            if( !rc )
                rc = stream_putc( out, sk->protect.s2k->mode );
            if( !rc )
                rc = stream_putc( out, sk->protect.s2k->hash_algo );
            if( !rc && (s2k_mode == 1 || s2k_mode == 3) ) {
                rc = stream_write( out, sk->protect.s2k->salt, 8 );
                if( !rc && s2k_mode == 3 )
                    rc = stream_putc( out, sk->protect.s2k->count );
	    }
	}
        else
            return CDK_Inv_Value;
        rc = stream_write( out, sk->protect.iv, sk->protect.ivlen );
    }
    if( !rc && sk->is_protected && pk->version == 4 ) {
        if( sk->encdata && sk->enclen )
            rc = stream_write( out, sk->encdata, sk->enclen );
    }
    else {
        if( !rc )
            rc = write_mpibuf( out, sk->mpi, nskey );
        if( !rc ) {
            if( !sk->csum )
                sk->csum = _cdk_sk_get_csum( sk );
            rc = write_16( out, sk->csum );
        }
    }
    return rc;
}


static int
write_compressed( cdk_stream_t out, cdk_pkt_compressed_t cd )
{
    int rc;

    if( !out || !cd )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write compressed packet\n");

    rc = pkt_write_head( out, 1, 0, CDK_PKT_COMPRESSED );
    if( !rc )
        rc = stream_putc( out, cd->algorithm );
    return rc;
}


static int
write_literal( cdk_stream_t out, cdk_pkt_literal_t pt, int old_ctb )
{
    byte buf[8192];
    size_t size;
    int rc;

    if( !out || !pt )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write literal packet\n");

    size = 6 + pt->namelen + pt->len;
    rc = pkt_write_head( out, old_ctb, size, CDK_PKT_LITERAL );
    if( !rc )
        rc = stream_putc( out, pt->mode );
    if( !rc )
        rc = stream_putc( out, pt->namelen );
    if( !rc && pt->namelen )
        rc = stream_write( out, pt->name, pt->namelen );
    if( !rc )
        rc = write_32( out, pt->timestamp );
    if( !rc ) {
        while( pt->len && !cdk_stream_eof( pt->buf ) && !rc ) {
            rc = stream_read( pt->buf, buf, sizeof buf-1, &size );
            if( !rc )
                rc = stream_write( out, buf, size );
        }
        wipemem( buf, sizeof buf );
    }
    return rc;
}

  
static int
write_onepass_sig( cdk_stream_t out, cdk_pkt_onepass_sig_t sig )
{
    size_t size = 0;
    int rc = 0;

    if( !out || !sig )
        return CDK_Inv_Value;
    if( sig->version != 3 )
        return CDK_Inv_Packet;

    if (DEBUG_PKT)
        _cdk_log_debug ("** write one pass signature packet\n");

    size = 13;
    rc = pkt_write_head( out, 0, size, CDK_PKT_ONEPASS_SIG );
    if( !rc )
        rc = stream_putc( out, sig->version );
    if( !rc )
        rc = stream_putc( out, sig->sig_class );
    if( !rc )
        rc = stream_putc( out, sig->digest_algo );
    if (!rc)
        rc = stream_putc( out, sig->pubkey_algo );
    if( !rc )
        rc = write_32( out, sig->keyid[0] );
    if( !rc )
        rc = write_32( out, sig->keyid[1] );
    if( !rc )
        rc = stream_putc( out, sig->last );
    return rc;
}


static int
write_user_id( cdk_stream_t out, cdk_pkt_userid_t id, int old_ctb )
{
    int rc = 0;

    if( !out || !id || !id->name )
        return CDK_Inv_Value;

    if( id->attrib_img )
        ;/* todo */
    else {
        rc = pkt_write_head( out, old_ctb, id->len, CDK_PKT_USER_ID );
        if( !rc )
            rc = stream_write( out, id->name, id->len );
    }
    return rc;
}


/**
 * cdk_pkt_write:
 * @out: the output stream handle
 * @pkt: the packet itself
 *
 * Write the contents of @pkt into the @out stream.
 **/
cdk_error_t
cdk_pkt_write( cdk_stream_t out, cdk_packet_t pkt )
{
    int rc;

    if( !out || !pkt )
        return CDK_Inv_Value;

    switch( pkt->pkttype ) {
    case CDK_PKT_LITERAL:
        rc = write_literal( out, pkt->pkt.literal, pkt->old_ctb );
        break;
    case CDK_PKT_ONEPASS_SIG:
        rc = write_onepass_sig( out, pkt->pkt.onepass_sig );
        break;
    case CDK_PKT_MDC:
        rc = write_mdc( out, pkt->pkt.mdc );
        break;
    case CDK_PKT_SYMKEY_ENC:
        rc = write_symkey_enc( out, pkt->pkt.symkey_enc );
        break;
    case CDK_PKT_ENCRYPTED:
        rc = write_encrypted( out, pkt->pkt.encrypted, pkt->old_ctb );
        break;
    case CDK_PKT_ENCRYPTED_MDC:
        rc = write_encrypted_mdc( out, pkt->pkt.encrypted );
        break;
    case CDK_PKT_PUBKEY_ENC:
        rc = write_pubkey_enc( out, pkt->pkt.pubkey_enc, pkt->old_ctb );
        break;
    case CDK_PKT_SIGNATURE:
        rc = write_signature( out, pkt->pkt.signature, pkt->old_ctb );
        break;
    case CDK_PKT_PUBLIC_KEY:
        rc = write_public_key( out, pkt->pkt.public_key, 0, pkt->old_ctb );
        break;
    case CDK_PKT_PUBLIC_SUBKEY:
        rc = write_public_key( out, pkt->pkt.public_key, 1, pkt->old_ctb );
        break;
    case CDK_PKT_COMPRESSED:
        rc = write_compressed( out, pkt->pkt.compressed );
        break;
    case CDK_PKT_SECRET_KEY:
        rc = write_secret_key( out, pkt->pkt.secret_key, 0, pkt->old_ctb );
        break;
    case CDK_PKT_SECRET_SUBKEY:
        rc = write_secret_key( out, pkt->pkt.secret_key, 1, pkt->old_ctb );
        break;
    case CDK_PKT_USER_ID:
        rc = write_user_id( out, pkt->pkt.user_id, pkt->old_ctb );
        break;
    default:
        rc = CDK_Inv_Packet;
        break;
    }
    return rc;
}


int
_cdk_pkt_write_fp( FILE * out, cdk_packet_t pkt )
{
    cdk_stream_t so;
    int rc;

    so = _cdk_stream_fpopen( out, 1 );
    rc = cdk_pkt_write( so, pkt );
    cdk_stream_close( so );
    return rc;
}

    
