/* -*- Mode: C; c-file-style: "bsd" -*-
 * read-packet.c - Read OpenPGP packets
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
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"


static int
stream_getc( cdk_stream_t s )
{
    return cdk_stream_getc( s );
}



static int
stream_read (cdk_stream_t s, void * buf, size_t count, size_t * r_nread)
{
    int nread = cdk_stream_read (s, buf, count);
    if( !nread )
        return CDK_File_Error;
    if( r_nread )
        *r_nread = nread;
    return 0;
}


static u32
read_32 (cdk_stream_t buf)
{
    u32 u = 0;
    int c;

    if( !buf )
        return (u32) -1;

    if( (c = stream_getc( buf )) == EOF )
        return (u32)-1;
    u |= c << 24;
    if( (c = stream_getc( buf )) == EOF )
        return (u32)-1;
    u |= c << 16;
    if( (c = stream_getc( buf )) == EOF )
        return (u32)-1;
    u |= c <<  8;
    if( (c = stream_getc( buf )) == EOF )
        return (u32)-1;
    u |= c;
    return u;
}


static u16
read_16 (cdk_stream_t buf)
{
    u16 u = 0;
    int c;

    if( !buf )
        return (u16)-1;

    if( (c = stream_getc( buf )) == EOF )
        return (u16)-1;
    u |= c << 8;
    if( (c = stream_getc( buf )) == EOF )
        return (u16)-1;
    u |= c;
    return u;
}


#define check_s2k_mode( mode ) ( \
    (mode) == CDK_S2K_SIMPLE \
 || (mode) == CDK_S2K_SALTED \
 || (mode) == CDK_S2K_ITERSALTED \
)

static int
read_s2k( cdk_stream_t inp, cdk_s2k_t s2k )
{
    size_t nread = 0;
    int rc = 0;

    if( !inp || !s2k )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read S2K part\n" );

    s2k->mode = stream_getc( inp );
    if( s2k->mode == EOF || !check_s2k_mode( s2k->mode ) )
        return CDK_Inv_Packet;
    s2k->hash_algo = stream_getc( inp );
    if( s2k->mode == CDK_S2K_SIMPLE ) {
        memset( s2k->salt, 0, sizeof s2k->salt );
        /* nothing else to do */
    }
    else if( s2k->mode == CDK_S2K_SALTED || s2k->mode == CDK_S2K_ITERSALTED ) {
        rc = stream_read( inp, s2k->salt, sizeof s2k->salt, &nread );
        if( !rc && nread != sizeof s2k->salt )
            return CDK_Inv_Packet;
        if( !rc && s2k->mode == CDK_S2K_ITERSALTED ) {
            s2k->count = stream_getc( inp );
            if( s2k->count == EOF )
                return CDK_Inv_Packet;
	}
    }
    else
        return CDK_Inv_Mode;
    return rc;
}


static int
read_mpi (cdk_stream_t inp, cdk_mpi_t * ret_m, int secure)
{
    cdk_mpi_t m = NULL;
    size_t nread = 0, nbits = 0, nbytes = 0;
    int rc = 0;

    if( !inp || !ret_m )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read MPI part\n");

    nbits = read_16 (inp);
    nbytes = (nbits + 7) / 8;
    if( nbits > MAX_MPI_BITS || nbits == 0 )
        return CDK_MPI_Error; /* sanity check */
    m = secure ? cdk_salloc( sizeof *m + nbytes + 2, 1 ) :
                 cdk_calloc( 1, sizeof *m + nbytes + 2 );
    if( !m )
        return CDK_Out_Of_Core;
    m->bytes = nbytes;
    m->bits = nbits;

    /* the prefix encodes the length of the MPI data */
    m->data[0] = nbits >> 8;
    m->data[1] = nbits;
    rc = stream_read( inp, m->data + 2, nbytes, &nread );
    if( !rc && nread != nbytes )
        rc = CDK_MPI_Error;
    *ret_m = m;
    return rc;
}


size_t
_cdk_pkt_read_len( FILE * inp, int * ret_partial )
{
    int c1 = 0, c2 = 0;
    size_t pktlen = 0;

    if( (c1 = fgetc (inp)) == EOF )
        return (size_t)EOF;
    if( c1 < 224 || c1 == 255 )
        *ret_partial = 0; /* end of partial data */
    if( c1 < 192 )
        pktlen = c1;
    else if( c1 >= 192 && c1 <= 223 ) {
        if( (c2 = fgetc( inp )) == EOF )
            return (size_t)EOF;
        pktlen = ((c1 - 192) << 8) + c2 + 192;
    }
    else if( c1 == 255 ) {
        pktlen  = fgetc( inp ) << 24;
        pktlen |= fgetc( inp ) << 16;
        pktlen |= fgetc( inp ) <<  8;
        pktlen |= fgetc( inp );
        if( !pktlen )
            return (size_t)EOF;
    }
    else
        pktlen = 1 << (c1 & 0x1f);
    return pktlen;
}


static int
read_encrypted( cdk_stream_t inp, size_t pktlen, cdk_pkt_encrypted_t enc,
		int partial, int mdc )
{
    int rc = 0, version;

    if( !inp || !enc )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read encrypted packet %d bytes\n", pktlen );

    if( mdc ) {
        version = stream_getc( inp );
        if( version != 1 )
            return CDK_Inv_Packet;
        enc->mdc_method = CDK_MD_SHA1;
        pktlen--;
    }
    if( pktlen < 10 )
        return CDK_Inv_Packet; /* we need at least blocksize + 2 bytes */
    if( partial )
        _cdk_stream_set_blockmode( inp, pktlen );
    enc->len = pktlen;
    enc->buf = inp;
    return rc;
}


static int
read_symkey_enc( cdk_stream_t inp, size_t pktlen, cdk_pkt_symkey_enc_t ske )
{
    cdk_s2k_t s2k;
    size_t nread = 0, minlen = 0;
    int rc = 0;

    if( !inp || !ske )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read symmetric key encrypted packet\n" );

    ske->version = stream_getc( inp );
    if( ske->version != 4 )
        return CDK_Inv_Packet;

    s2k = ske->s2k = cdk_calloc( 1, sizeof *ske->s2k );
    if( !ske->s2k )
        return CDK_Out_Of_Core;
  
    ske->cipher_algo = stream_getc( inp );
    s2k->mode = stream_getc( inp );
    switch( s2k->mode ) {
    case 0: minlen = 0; break;
    case 1: minlen = 8; break;
    case 3: minlen = 9; break;
    }
    s2k->hash_algo = stream_getc( inp );
    if( s2k->mode == 0 )
        ; /* nothing to do */
    else if( s2k->mode == 1 || s2k->mode == 3 ) {
        rc = stream_read( inp, s2k->salt, DIM (s2k->salt), &nread);
        if( !rc && nread != DIM( s2k->salt ) )
            return CDK_Inv_Packet;
        if( !rc && s2k->mode == 3 )
            s2k->count = stream_getc( inp );
    }
    else
        return CDK_Inv_Packet;
    ske->seskeylen = pktlen - 4 - minlen;
    if( ske->seskeylen > sizeof ske->seskey )
        return CDK_Inv_Packet;
    for( nread = 0; nread < ske->seskeylen; nread++ ) {
        ske->seskey[nread] = stream_getc( inp );
        if( cdk_stream_eof( inp ) )
            break;
    }
    return rc;
}


static int
read_pubkey_enc( cdk_stream_t inp, size_t pktlen, cdk_pkt_pubkey_enc_t pke )
{
    int rc = 0;
    int i, nenc = 0;

    if( !inp || !pke )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read public key encrypted packet\n" );

    if( pktlen < 10 )
        return CDK_Inv_Packet;
    pke->version = stream_getc( inp );
    if( pke->version < 2 || pke->version > 3 )
        return CDK_Inv_Packet;
    pke->keyid[0] = read_32( inp );
    pke->keyid[1] = read_32( inp );
    if( !pke->keyid[0] && !pke->keyid[1] )
        pke->throw_keyid = 1; /* RFC2440 "speculative" keyID */
    pke->pubkey_algo = stream_getc( inp );
    nenc = cdk_pk_get_nenc( pke->pubkey_algo );
    if( !nenc )
        return CDK_Inv_Algo;
    for( i = 0; i < nenc; i++ ) {
        rc = read_mpi( inp, &pke->mpi[i], 0 );
        if( rc )
            break;
    }
    return rc;
}


static int
read_mdc( cdk_stream_t inp, cdk_pkt_mdc_t mdc )
{
    size_t n = 0;
    int rc = 0;

    if( !inp || !mdc )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read MDC packet\n");

    rc = stream_read( inp, mdc->hash, 20, &n );
    if( !rc && n != 20 )
        rc = CDK_Inv_Packet;
    return rc;
}


static int
read_compressed( cdk_stream_t inp, size_t pktlen, cdk_pkt_compressed_t c )
{
    if (!inp || !c)
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read compressed packet\n");

    c->algorithm = stream_getc( inp );
    if( c->algorithm > 2 )
        return CDK_Inv_Packet;

    /* don't know the size, so we read until EOF */
    if( !pktlen ) {
        c->len = 0;
        c->buf = inp;
    }

    return 0;
}


static int
read_public_key( cdk_stream_t inp, cdk_pkt_pubkey_t pk )
{
    int i = 0, ndays, npkey;
    int rc = 0;

    if (!inp || !pk)
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read public key packet\n" );

    pk->is_invalid = 1; /* default to detect missing self signatures */
    pk->is_revoked = 0;
    pk->has_expired = 0;

    pk->version = stream_getc( inp );
    if( pk->version < 2 || pk->version > 4 )
        return CDK_Inv_Packet_Ver;
    pk->timestamp = read_32( inp );
    if( pk->version < 4 ) {
        ndays = read_16( inp );
        if( ndays ) 
            pk->expiredate = pk->timestamp + ndays * 86400L;
    }
    pk->pubkey_algo = stream_getc( inp );
    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    if( !npkey )
        return CDK_Inv_Algo;
    for( i = 0; i < npkey; i++ ) {
        rc = read_mpi( inp, &pk->mpi[i], 0 );
        if ( rc )
            break;
    }
    pk->pubkey_usage = _cdk_pk_algo_usage( pk->pubkey_algo );
    return rc;
}


static int
read_public_subkey( cdk_stream_t inp, cdk_pkt_pubkey_t pk )
{
    if( !inp || !pk )
        return CDK_Inv_Value;
    return read_public_key( inp, pk );
}


static int
read_secret_key( cdk_stream_t inp, size_t pktlen, cdk_pkt_seckey_t sk )
{
    size_t p1 = 0, p2 = 0, nread = 0;
    int i = 0, blklen = 0, nskey = 0;
    int rc = 0;

    if( !inp || !sk || !sk->pk )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read secret key\n");

    p1 = cdk_stream_tell( inp );
    rc = read_public_key( inp, sk->pk );
    if( rc )
        return rc;

    sk->s2k_usage = stream_getc( inp );
    sk->protect.sha1chk = 0;
    if( sk->s2k_usage == 254 || sk->s2k_usage == 255 ) {
        sk->protect.sha1chk = (sk->s2k_usage == 254);
        sk->protect.algo = stream_getc( inp );
        sk->protect.s2k = cdk_calloc( 1, sizeof *sk->protect.s2k );
        if( !sk->protect.s2k )
            return CDK_Out_Of_Core;
        rc = read_s2k( inp, sk->protect.s2k );
        if( rc )
            return rc;
        blklen = cdk_cipher_get_algo_blklen( sk->protect.algo );
        if( !blklen )
            return CDK_Inv_Packet;
        sk->protect.ivlen = blklen;
        rc = stream_read( inp, sk->protect.iv, sk->protect.ivlen, &nread );
        if( !rc && nread != sk->protect.ivlen )
            return CDK_Inv_Packet;
    }
    else
        sk->protect.algo = sk->s2k_usage;
    if( sk->protect.algo == CDK_CIPHER_NONE ) {
        sk->csum = 0;
        nskey = cdk_pk_get_nskey( sk->pk->pubkey_algo );
        if( !nskey )
            return CDK_Inv_Algo;
        for( i = 0; i < nskey; i++ ) {
            rc = read_mpi( inp, &sk->mpi[i], 1 );
            if( rc )
                break;
	}
        if( !rc ) {
            sk->csum = read_16( inp );
            sk->is_protected = 0;
	}
    }
    else if( sk->pk->version < 4 ) {
        /* mpi size isn't encrypted! */
        nskey = cdk_pk_get_nskey( sk->pk->pubkey_algo );
        if( !nskey )
            return CDK_Inv_Algo;
        for( i = 0; i < nskey; i++ ) {
            rc = read_mpi( inp, &sk->mpi[i], 1 );
            if( rc )
                break;
	}
        if( !rc ) {
            sk->csum = read_16( inp );
            sk->is_protected = 1;
	}
    }
    else {
        /* we need to read the rest of the packet because we don't
           have any information how long the encrypted mpi's are */
        p2 = cdk_stream_tell( inp );
        p2 -= p1;
        sk->enclen = pktlen - p2;
        if( sk->enclen < 2 )
            return CDK_Inv_Packet; /* at least 16 bits for the checksum! */
        sk->encdata = cdk_calloc( 1, sk->enclen + 1 );
        if( !sk->encdata )
            return CDK_Out_Of_Core;
        rc = stream_read( inp, sk->encdata, sk->enclen, &nread );
        if( rc )
            return CDK_Inv_Packet;
        nskey = cdk_pk_get_nskey( sk->pk->pubkey_algo );
        if( !nskey )
            return CDK_Inv_Algo;
        for( i = 0; i < nskey; i++ )
            sk->mpi[i] = NULL;
        sk->is_protected = 1;
    }
    sk->is_primary = 1;
    _cdk_copy_pk_to_sk( sk->pk, sk );
    return rc;
}


static int
read_secret_subkey( cdk_stream_t inp, size_t pktlen, cdk_pkt_seckey_t sk )
{
    int rc = 0;

    if( !inp || !sk || !sk->pk )
        return CDK_Inv_Value;

    rc = read_secret_key( inp, pktlen, sk );
    sk->is_primary = 0;
    return rc;
}


static int
read_attribute (cdk_stream_t inp, size_t pktlen, cdk_pkt_userid_t attr)
{
    size_t nread = 0;
    byte * buf;
    const byte * p;
    int len = 0;
    int rc = 0;

    if( !inp || !attr || !pktlen )
        return CDK_Inv_Value;

    strcpy( attr->name, "[attribute]" );
    attr->len = strlen( attr->name );
    buf = cdk_calloc( 1, pktlen );
    if( !buf )
        return CDK_Out_Of_Core;
    rc = stream_read( inp, buf, pktlen, &nread );
    if( rc ) {
        cdk_free( buf );
        return CDK_Inv_Packet;
    }
    p = buf;
    len = *p++;
    if (len == 255) {
        len = _cdk_buftou32( p );
        p += 4;
        pktlen -= 4;
    }
    else if (len >= 192) {
        if( pktlen < 2 ) {
            cdk_free( buf );
            return CDK_Inv_Packet;
	}
        len = ((len - 192) << 8) + *p + 192;
        p++;
        pktlen--;
    }
    if( *p != 1 ) { /* ATTRIBUTE IMAGE */
        cdk_free( buf );
        return CDK_Inv_Packet;
    }
    p++;

    attr->attrib_img = cdk_calloc( 1, len );
    if( !attr->attrib_img )
        return CDK_Out_Of_Core;
    attr->attrib_len = len;
    memcpy( attr->attrib_img, p, len );
    cdk_free( buf );
    return rc;
}


static int
read_user_id( cdk_stream_t inp, size_t pktlen, cdk_pkt_userid_t user_id )
{
    size_t nread = 0;
    int rc = 0;

    if( !inp || !user_id )
        return CDK_Inv_Value;
    if( !pktlen )
        return CDK_Inv_Packet;
  
    if (DEBUG_PKT)
        _cdk_log_debug ("** read user ID packet\n");

    user_id->len = pktlen;
    rc = stream_read( inp, user_id->name, pktlen, &nread );
    if( !rc && nread != pktlen )
        return CDK_Inv_Packet;
    user_id->name[nread] = '\0';
    return rc;
}


static int
read_subpkt( cdk_stream_t inp, cdk_subpkt_t * r_ctx, size_t * r_nbytes )
{
    byte c, c1;
    size_t size = 0, nread, n = 0;
    cdk_subpkt_t node;
    int rc = 0;

    if( !inp || !r_nbytes )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read sub packet");
  
    *r_nbytes = 0;
    c = stream_getc( inp );
    n++;
    if( c == 255 ) {
        size = read_32( inp );
        n += 4;
        node = cdk_subpkt_new( size );
    }
    else if( c >= 192 && c < 255 ) {
        c1 = stream_getc( inp );
        n++;
        if( c1 == 0 )
            return 0;
        size = ((c - 192) << 8) + c1 + 192;
        node = cdk_subpkt_new( size );
    }
    else if( c < 192 ) {
        size = c;
        node = cdk_subpkt_new( size );
    }
    else
        return CDK_Inv_Packet;

    if (DEBUG_PKT)
        _cdk_log_debug (" `%d' bytes\n", size);

    if( !node )
        return CDK_Out_Of_Core;
    node->size = size;
    node->type = stream_getc( inp );
    n++;
    node->size--;
    rc = stream_read( inp, node->d, node->size, &nread );
    n += nread;
    if( rc )
        return rc;
    *r_nbytes = n;
    if( !*r_ctx )
        *r_ctx = node;
    else
        cdk_subpkt_add( *r_ctx, node );
    return rc;
}


static int
read_onepass_sig( cdk_stream_t inp, size_t pktlen, cdk_pkt_onepass_sig_t sig )
{
    if( !inp || !sig )
        return CDK_Inv_Value;

    if (DEBUG_PKT)
        _cdk_log_debug ("** read one pass signature packet\n");

    if( pktlen < 13 )
        return CDK_Inv_Packet;
    sig->version = stream_getc( inp );
    if( sig->version != 3 )
        return CDK_Inv_Packet_Ver;
    sig->sig_class = stream_getc( inp );
    sig->digest_algo = stream_getc( inp );
    sig->pubkey_algo = stream_getc( inp );
    sig->keyid[0] = read_32( inp );
    sig->keyid[1] = read_32( inp );
    sig->last = stream_getc( inp );
    return 0;
}


static int
read_signature( cdk_stream_t inp, size_t pktlen, cdk_pkt_signature_t sig )
{
    cdk_subpkt_t node = NULL;
    size_t nbytes;
    int i, size, nsig;
    int rc = 0;

    if( !inp || !sig )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read signature packet\n" );

    if( pktlen < 10 )
        return CDK_Inv_Packet;
    sig->version = stream_getc( inp );
    if( sig->version < 2 || sig->version > 4 )
        return CDK_Inv_Packet_Ver;

    sig->flags.exportable = 1;
    sig->flags.revocable = 1;
  
    if( sig->version < 4 ) {
        if( stream_getc( inp ) != 5 )
            return CDK_Inv_Packet;
        sig->sig_class = stream_getc( inp );
        sig->timestamp = read_32( inp );
        sig->keyid[0] = read_32( inp );
        sig->keyid[1] = read_32( inp );
        sig->pubkey_algo = stream_getc( inp );
        sig->digest_algo = stream_getc( inp );
        sig->digest_start[0] = stream_getc( inp );
        sig->digest_start[1] = stream_getc( inp );
        nsig = cdk_pk_get_nsig( sig->pubkey_algo );
        if( !nsig )
            return CDK_Inv_Algo;
        for( i = 0; i < nsig; i++ ) {
            rc = read_mpi( inp, &sig->mpi[i], 0 );
            if( rc )
                break;
	}
    }
    else {
        sig->sig_class = stream_getc( inp );
        sig->pubkey_algo = stream_getc( inp );
        sig->digest_algo = stream_getc( inp );
        sig->hashed_size = read_16( inp );
        size = sig->hashed_size;
        sig->hashed = NULL;
        while( size > 0 ) {
            rc = read_subpkt( inp, &sig->hashed, &nbytes );
            if( rc )
                break;
            size -= nbytes;
        }
        sig->unhashed_size = read_16( inp );
        size = sig->unhashed_size;
        sig->unhashed = NULL;
        while( size > 0 ) {
            rc = read_subpkt( inp, &sig->unhashed, &nbytes );
            if( rc )
                break;
            size -= nbytes;
	}

        /* Setup the standard packet entries, so we can use V4
           signatures similar to V3. */
        for( node = sig->unhashed; node; node = node->next ) {
            if( node->type == CDK_SIGSUBPKT_ISSUER ) {
                sig->keyid[0] = _cdk_buftou32( node->d     );
                sig->keyid[1] = _cdk_buftou32( node->d + 4 );
	    }
            else if( node->type == CDK_SIGSUBPKT_EXPORTABLE
                     && node->d[0] == 0 ) {
                /* this packet might be also placed in the unhashed area */
                sig->flags.exportable = 0;
	    }
	}
        for( node = sig->hashed; node; node = node->next ) {
            if( node->type == CDK_SIGSUBPKT_SIG_CREATED )
                sig->timestamp = _cdk_buftou32( node->d );
            else if( node->type == CDK_SIGSUBPKT_SIG_EXPIRE ) {
                sig->expiredate = _cdk_buftou32( node->d );
                if( sig->expiredate > 0
                    && sig->expiredate < _cdk_timestamp() )
                    sig->flags.expired = 1;
	    }
            else if( node->type == CDK_SIGSUBPKT_POLICY )
                sig->flags.policy_url = 1;
            else if( node->type == CDK_SIGSUBPKT_NOTATION )
                sig->flags.notation = 1;
            else if( node->type == CDK_SIGSUBPKT_REVOCABLE && node->d[0] == 0 )
                sig->flags.revocable = 0;
            else if( node->type == CDK_SIGSUBPKT_EXPORTABLE
                     && node->d[0] == 0 )
                sig->flags.exportable = 0;
	}
        if( sig->sig_class == 0x1F ) {
            cdk_desig_revoker_t r, rnode;
            for( node = sig->hashed; node; node = node->next ) {
                if( node->type == CDK_SIGSUBPKT_REV_KEY ) {
                    rnode = cdk_calloc( 1, sizeof * rnode );
                    if( !rnode )
                        return CDK_Out_Of_Core;
                    rnode->class = node->d[0];
                    rnode->algid = node->d[1];
                    memcpy( rnode->fpr, node->d+2, 20 );
                    if( !sig->revkeys )
                        sig->revkeys = rnode;
                    else {
                        for( r = sig->revkeys; r->next; r = r->next )
                            ;
                        r->next = rnode;
                    }
                }
            }
        }
        sig->digest_start[0] = stream_getc( inp );
        sig->digest_start[1] = stream_getc( inp );
        nsig = cdk_pk_get_nsig( sig->pubkey_algo );
        if( !nsig )
            return CDK_Inv_Algo;
        for( i = 0; i < nsig; i++ ) {
            rc = read_mpi( inp, &sig->mpi[i], 0 );
            if( rc )
                break;
	}
    }
    return rc;
}


static int
read_literal( cdk_stream_t inp, size_t pktlen, cdk_pkt_literal_t * ret_pt,
              int partial )
{
    cdk_pkt_literal_t pt = *ret_pt;
    size_t nread = 0;
    int rc = 0;

    if( !inp || !pt )
        return CDK_Inv_Value;

    if( DEBUG_PKT )
        _cdk_log_debug( "** read literal packet\n" );

    pt->mode = stream_getc( inp );
    if( pt->mode != 0x62 && pt->mode != 0x74 )
        return CDK_Inv_Packet;
    pt->namelen = stream_getc( inp );
    if( pt->namelen ) {
        *ret_pt = pt = cdk_realloc( pt, sizeof * pt + pt->namelen + 1 );
        if( !pt )
            return CDK_Out_Of_Core;
        rc = stream_read( inp, pt->name, pt->namelen, &nread );
        if( !rc && nread != pt->namelen )
            return CDK_Inv_Packet;
        pt->name[pt->namelen] = '\0';
    }
    pt->timestamp = read_32( inp );
    pktlen = pktlen - 6 - pt->namelen;
    if( partial )
        _cdk_stream_set_blockmode( inp, pktlen );
    pt->buf = inp;
    pt->len = pktlen;
    return rc;
}


static void
read_old_length( cdk_stream_t inp, int ctb, size_t *r_len, size_t *r_size )
{
    int llen = ctb & 0x03;
    
    if( llen == 0 ) {
        *r_len = stream_getc( inp );
        (*r_size)++;
    }
    else if( llen == 1 ) {
        *r_len = read_16( inp );
        (*r_size) += 2;
    }
    else if( llen == 2 ) {
        *r_len = read_32( inp );
        (*r_size) += 4;
    }
    else {
        *r_len = 0;
        *r_size = 0;
    }
}


static void
read_new_length( cdk_stream_t inp,
                 size_t *r_len, size_t *r_size, size_t *r_partial )
{
    int c, c1;
  
    c = stream_getc( inp );
    (*r_size)++;
    if( c < 192 )
        *r_len = c;
    else if( c >= 192 && c <= 223 ) {
        c1 = stream_getc( inp );
        (*r_size)++;
        *r_len = ((c - 192) << 8) + c1 + 192;
    }
    else if( c == 255 ) {
        *r_len = read_32( inp );
        (*r_size) += 4; 
    }
    else {
        *r_len = 1 << (c & 0x1f);
        *r_partial = 1;
    }  
}


/* we use a buffer to make it faster to skip larger unknown packets. */
static void
skip_packet( cdk_stream_t inp, size_t pktlen )
{
    byte buf[4096];
    size_t nread;
  
    while( pktlen > 4095 ) {
        stream_read( inp, buf, sizeof buf-1, &nread );
        pktlen -= nread;
    }
    stream_read( inp, buf, pktlen, &nread );
    pktlen -= nread;
    assert( pktlen == 0 );
}


/**
 * cdk_pkt_read:
 * @inp: the input stream
 * @pkt: allocated packet handle to store the packet
 *
 * Parse the next packet on the @inp stream and return its contents in @pkt.
 **/
cdk_error_t
cdk_pkt_read( cdk_stream_t inp, cdk_packet_t pkt )
{
    int use_mdc = 0;
    int ctb = 0, is_newctb = 0, is_partial = 0;
    int rc = 0, pkttype = 0;
    size_t pktlen = 0, pktsize = 0;

    if( !inp || !pkt )
        return CDK_Inv_Value;

    ctb = stream_getc( inp );
    if( cdk_stream_eof( inp ) || ctb == EOF )
        return CDK_EOF;
    else if( !ctb )
        return CDK_Inv_Packet;

    pktsize++;
    if( !(ctb & 0x80) ) {
        _cdk_log_info ("no valid openpgp data found. "
                       "(ctb=%02X; fpos=%02X)\n",ctb, cdk_stream_tell( inp ) );
        return CDK_Inv_Packet;
    }
    if( ctb & 0x40 ) { /* RFC2440 */
        pkttype = ctb & 0x3f;
        is_newctb = 1;
    }
    else { /* RFC1991 */
        pkttype = ctb & 0x3f;
        pkttype >>= 2;
    }
    if( pkttype > 63 ) {
        _cdk_log_info ("unknown packet type (%d)\n", pkttype);
        return CDK_Inv_Packet;
    }
    if( is_newctb )
        read_new_length( inp, &pktlen, &pktsize, &is_partial );
    else
        read_old_length( inp, ctb, &pktlen, &pktsize );

    pkt->pkttype = pkttype;
    pkt->pktlen = pktlen;
    pkt->pktsize = pktsize + pktlen;
    pkt->old_ctb = is_newctb? 0 : 1;

    switch( pkt->pkttype ) {
    case CDK_PKT_ATTRIBUTE:
        pkt->pkt.user_id = cdk_calloc (1,
                                       sizeof *pkt->pkt.user_id + pkt->pktlen);
        if (!pkt->pkt.user_id)
            return CDK_Out_Of_Core;
        rc = read_attribute (inp, pktlen, pkt->pkt.user_id);
        pkt->pkttype = CDK_PKT_USER_ID; /* treated as an user id */
        break;

    case CDK_PKT_USER_ID:
        pkt->pkt.user_id = cdk_calloc (1,
                                       sizeof *pkt->pkt.user_id + pkt->pktlen);
        if (!pkt->pkt.user_id)
            return CDK_Out_Of_Core;
        rc = read_user_id (inp, pktlen, pkt->pkt.user_id);
        break;

    case CDK_PKT_PUBLIC_KEY:
        pkt->pkt.public_key = cdk_calloc (1, sizeof *pkt->pkt.public_key);
        if (!pkt->pkt.public_key)
            return CDK_Out_Of_Core;
        rc = read_public_key (inp, pkt->pkt.public_key);
        break;

    case CDK_PKT_PUBLIC_SUBKEY:
        pkt->pkt.public_key = cdk_calloc (1, sizeof *pkt->pkt.public_key);
        if (!pkt->pkt.public_key)
            return CDK_Out_Of_Core;
        rc = read_public_subkey (inp, pkt->pkt.public_key);
        break;

    case CDK_PKT_SECRET_KEY:
        pkt->pkt.secret_key = cdk_calloc (1, sizeof *pkt->pkt.secret_key);
        if (!pkt->pkt.secret_key)
            return CDK_Out_Of_Core;
        pkt->pkt.secret_key->pk =cdk_calloc (1,
                                             sizeof *pkt->pkt.secret_key->pk);
        if (!pkt->pkt.secret_key->pk)
            return CDK_Out_Of_Core;
        rc = read_secret_key (inp, pktlen, pkt->pkt.secret_key);
        break;

    case CDK_PKT_SECRET_SUBKEY:
        pkt->pkt.secret_key = cdk_calloc (1, sizeof *pkt->pkt.secret_key);
        if (!pkt->pkt.secret_key)
            return CDK_Out_Of_Core;
        pkt->pkt.secret_key->pk =
            cdk_calloc (1, sizeof *pkt->pkt.secret_key->pk);
        if (!pkt->pkt.secret_key->pk)
            return CDK_Out_Of_Core;
        rc = read_secret_subkey (inp, pktlen, pkt->pkt.secret_key);
        break;

    case CDK_PKT_LITERAL:
        pkt->pkt.literal = cdk_calloc( 1, sizeof *pkt->pkt.literal );
        if (!pkt->pkt.literal)
            return CDK_Out_Of_Core;
        rc = read_literal( inp, pktlen, &pkt->pkt.literal, is_partial);
        break;

    case CDK_PKT_ONEPASS_SIG:
        pkt->pkt.onepass_sig = cdk_calloc (1, sizeof *pkt->pkt.onepass_sig);
        if (!pkt->pkt.onepass_sig)
            return CDK_Out_Of_Core;
        rc = read_onepass_sig (inp, pktlen, pkt->pkt.onepass_sig);
        break;

    case CDK_PKT_SIGNATURE:
        pkt->pkt.signature = cdk_calloc (1, sizeof *pkt->pkt.signature);
        if (!pkt->pkt.signature)
            return CDK_Out_Of_Core;
        rc = read_signature (inp, pktlen, pkt->pkt.signature);
        break;

    case CDK_PKT_ENCRYPTED_MDC:
    case CDK_PKT_ENCRYPTED:
        pkt->pkt.encrypted = cdk_calloc (1, sizeof *pkt->pkt.encrypted);
        if (!pkt->pkt.encrypted)
            return CDK_Out_Of_Core;
        use_mdc = (pkt->pkttype == CDK_PKT_ENCRYPTED_MDC) ? 1 : 0;
        rc = read_encrypted( inp, pktlen, pkt->pkt.encrypted,
                             is_partial, use_mdc );
        break;

    case CDK_PKT_SYMKEY_ENC:
        pkt->pkt.symkey_enc = cdk_calloc (1, sizeof *pkt->pkt.symkey_enc);
        if (!pkt->pkt.symkey_enc)
            return CDK_Out_Of_Core;
        rc = read_symkey_enc (inp, pktlen, pkt->pkt.symkey_enc);
        break;

    case CDK_PKT_PUBKEY_ENC:
        pkt->pkt.pubkey_enc = cdk_calloc (1, sizeof *pkt->pkt.pubkey_enc);
        if (!pkt->pkt.pubkey_enc)
            return CDK_Out_Of_Core;
        rc = read_pubkey_enc (inp, pktlen, pkt->pkt.pubkey_enc);
        break;

    case CDK_PKT_COMPRESSED:
        pkt->pkt.compressed = cdk_calloc (1, sizeof *pkt->pkt.compressed);
        if (!pkt->pkt.compressed)
            return CDK_Out_Of_Core;
        rc = read_compressed (inp, pktlen, pkt->pkt.compressed);
        break;

    case CDK_PKT_MDC:
        pkt->pkt.mdc = cdk_calloc (1, sizeof *pkt->pkt.mdc);
        if (!pkt->pkt.mdc)
            return CDK_Out_Of_Core;
        rc = read_mdc (inp, pkt->pkt.mdc);
        break;

    default:
        /* skip all packets we don't understand */
        skip_packet( inp, pktlen );
        break;
    }

    return rc;
}
