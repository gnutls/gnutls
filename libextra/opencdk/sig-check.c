/* -*- Mode: C; c-file-style: "bsd" -*-
 * sig-check.c - Check signatures
 *        Copyright (C) 2001, 2002, 2003 Timo Schulz
 *        Copyright (C) 1998,1999,2000,2001,2002 Free Software Foundation, Inc.
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
#include <time.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


static void
hash_mpibuf( cdk_pkt_pubkey_t pk, cdk_md_hd_t md )
{
    cdk_mpi_t a;
    int i, npkey;

    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    for( i = 0; i < npkey; i++ ) {
        a = pk->mpi[i];
        if( pk->version == 4 ) {
            cdk_md_putc( md, a->bits >> 8 );
            cdk_md_putc( md, a->bits );
        }
        cdk_md_write( md, a->data + 2, a->bytes );
    }
}


void
_cdk_hash_pubkey( cdk_pkt_pubkey_t pk, cdk_md_hd_t md, int usefpr )
{
    byte buf[4];
    u16 n;
    int i, npkey;

    if( !pk || !md )
        return;

    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    if( usefpr && pk->version < 4 && is_RSA( pk->pubkey_algo ) ) {
        hash_mpibuf( pk, md );
        return;
    }
    n = pk->version < 4 ? 8 : 6;
    for( i = 0; i < npkey; i++ ) {
        n += pk->mpi[i]->bytes;
        n += 2;
    }
  
    cdk_md_putc( md, 0x99 );
    cdk_md_putc( md, n >> 8 );
    cdk_md_putc( md, n );
    cdk_md_putc( md, pk->version );
  
    buf[0] = pk->timestamp >> 24;
    buf[1] = pk->timestamp >> 16;
    buf[2] = pk->timestamp >> 8;
    buf[3] = pk->timestamp;
    cdk_md_write( md, buf, 4 );

    if( pk->version < 4 ) {
        u16 a = 0;
        if( pk->expiredate )
            a = (u16)((pk->expiredate - pk->timestamp) / 86400L);
        cdk_md_putc( md, a >> 8 );
        cdk_md_putc( md, a );
    }
    cdk_md_putc( md, pk->pubkey_algo );
    hash_mpibuf( pk, md );
}


void
_cdk_hash_userid( cdk_pkt_userid_t uid, int is_v4, cdk_md_hd_t md )
{
    const byte * data;
    byte buf[5];
    u32 dlen;

    if( !uid || !md )
        return;

    if( is_v4 ) {
        if( uid->attrib_img ) {
            buf[0] = 0xD1;
            buf[1] = uid->attrib_len >> 24;
            buf[2] = uid->attrib_len >> 16;
            buf[3] = uid->attrib_len >> 8;
            buf[4] = uid->attrib_len;
	}
        else {
            buf[0] = 0xB4;
            buf[1] = uid->len >> 24;
            buf[2] = uid->len >> 16;
            buf[3] = uid->len >> 8;
            buf[4] = uid->len;
	}
        cdk_md_write( md, buf, 5 );
    }
    data = uid->attrib_img ? uid->attrib_img : (byte *) uid->name;
    dlen = uid->attrib_img ? uid->attrib_len : uid->len;
    cdk_md_write( md, data, dlen );
}


void
_cdk_hash_sig_data( cdk_pkt_signature_t sig, cdk_md_hd_t md )
{
    byte buf[4];
    size_t n = 0;

    if( !sig || !md )
        return;

    if( sig->version == 4 )
        cdk_md_putc( md, sig->version );
    cdk_md_putc( md, sig->sig_class );
    if( sig->version < 4 ) {
        buf[0] = sig->timestamp >> 24;
        buf[1] = sig->timestamp >> 16;
        buf[2] = sig->timestamp >> 8;
        buf[3] = sig->timestamp;
        cdk_md_write( md, buf, 4 );
    }
    else {
        cdk_md_putc( md, sig->pubkey_algo );
        cdk_md_putc( md, sig->digest_algo );
        if( sig->hashed ) {
            _cdk_subpkt_hash( sig->hashed, &n, md );
            sig->hashed_size = n;
            n = sig->hashed_size + 6;
	}
        else {
            cdk_md_putc( md, 0 );
            cdk_md_putc( md, 0 );
            n = 6;
	}
        cdk_md_putc( md, sig->version );
        cdk_md_putc( md, 0xff );
        buf[0] = n >> 24;
        buf[1] = n >> 16;
        buf[2] = n >> 8;
        buf[3] = n;
        cdk_md_write( md, buf, 4 );
    }
}


static void
cache_sig_result( cdk_pkt_signature_t sig, int res )
{
    if( !res ) {
        sig->flags.checked = 1;
        sig->flags.valid = 1;
    }
    else if( res == CDK_Bad_Sig ) {
        sig->flags.checked = 1;
        sig->flags.valid = 0;
    }
    else {
        sig->flags.checked = 0;
        sig->flags.valid = 0;
    }
}


int
_cdk_sig_check( cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig,
                cdk_md_hd_t digest, int * r_expired )
{
    byte md[24];
    time_t cur_time = _cdk_timestamp( );
    int digest_algo;
    int rc;

    if( !pk || !sig || !digest )
        return CDK_Inv_Value;

    if( sig->flags.checked )
        return sig->flags.valid ? 0 : CDK_Bad_Sig;

    if( !KEY_CAN_SIGN( pk->pubkey_algo ) )
        return CDK_Inv_Algo;
    if( pk->timestamp > sig->timestamp || pk->timestamp > cur_time )
        return CDK_Time_Conflict;

    digest_algo = sig->digest_algo;
    if( r_expired && pk->expiredate
        && (pk->expiredate + pk->timestamp) > cur_time )
        *r_expired = 1;

    _cdk_hash_sig_data( sig, digest );
    cdk_md_final( digest );
    memcpy( md, cdk_md_read (digest, sig->digest_algo ),
            cdk_md_get_algo_dlen( sig->digest_algo ) );
    if( md[0] != sig->digest_start[0] || md[1] != sig->digest_start[1] )
        return CDK_Bad_Sig;

    rc = cdk_pk_verify( pk, sig, md );
    cache_sig_result( sig, rc );
    return rc;
}


int
_cdk_pk_check_sig( cdk_keydb_hd_t hd, cdk_kbnode_t knode, cdk_kbnode_t snode )
{
    cdk_md_hd_t md;
    cdk_pkt_pubkey_t pk = NULL, sig_pk = NULL;
    cdk_pkt_signature_t sig = NULL;
    cdk_kbnode_t node;
    int digest_algo, is_expired = 0;
    int rc = 0;

    if( !knode || !snode )
        return CDK_Inv_Value;

    if( knode->pkt->pkttype != CDK_PKT_PUBLIC_KEY
        || snode->pkt->pkttype != CDK_PKT_SIGNATURE )
        return CDK_Inv_Value;
    pk = knode->pkt->pkt.public_key;
    sig = snode->pkt->pkt.signature;
    digest_algo = sig->digest_algo;

    md = cdk_md_open( digest_algo, 0 );
    if( !md )
        return CDK_Out_Of_Core;

    if( sig->sig_class == 0x20 ) { /* key revocation */
        cdk_kbnode_hash( knode, md, 0, 0, 0 );
        rc = _cdk_sig_check( pk, sig, md, &is_expired );
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
        node = cdk_kbnode_find_prev( knode, snode, CDK_PKT_PUBLIC_SUBKEY );
        if( !node ) { /* no subkey for subkey revocation packet */
            rc = CDK_Error_No_Key;
            goto fail;
        }
        cdk_kbnode_hash( knode, md, 0, 0, 0 );
        cdk_kbnode_hash( node, md, 0, 0, 0 );
        rc = _cdk_sig_check( pk, sig, md, &is_expired );
    }
    else if( sig->sig_class == 0x18 ) { /* key binding */
        node = cdk_kbnode_find_prev( knode, snode, CDK_PKT_PUBLIC_SUBKEY );
        if( !node ) { /* no subkey for subkey binding packet */
            rc = CDK_Error_No_Key;
            goto fail;
        }
        cdk_kbnode_hash( knode, md, 0, 0, 0 );
        cdk_kbnode_hash( node, md, 0, 0, 0 );
        rc = _cdk_sig_check( pk, sig, md, &is_expired );
    }
    else if( sig->sig_class == 0x1f ) { /* direct key signature */
        cdk_kbnode_hash( knode, md, 0, 0, 0 );
        rc = _cdk_sig_check( pk, sig, md, &is_expired );
    }
    else { /* all other classes */
        node = cdk_kbnode_find_prev( knode, snode, CDK_PKT_USER_ID );
        if( !node ) { /* no user ID for key signature packet */
            rc = CDK_Error_No_Key;
            goto fail;
        }
        cdk_kbnode_hash( knode, md, 0, 0, 0 );
        cdk_kbnode_hash( node, md, sig->version==4, 0, 0 );
        if( pk->keyid[0] == sig->keyid[0] && pk->keyid[1] == sig->keyid[1] )
            rc = _cdk_sig_check( pk, sig, md, &is_expired );
        else if( hd ) {
            rc = cdk_keydb_get_pk( hd, sig->keyid, &sig_pk );
            if( !rc )
                rc = _cdk_sig_check( sig_pk, sig, md, &is_expired );
            _cdk_free_pubkey( sig_pk );
	}
    }
 fail:
    cdk_md_close( md );
    return rc;
}


/**
 * cdk_pk_check_sigs:
 * @knode: the key node
 * @hd: the session handle
 * @r_status: variable to store the status of the key
 *
 * Check all signatures. When no key is available for checking, the
 * sigstat is marked as 'NOKEY'. The @r_status contains the key flags
 * which are or-ed or zero when there are no flags.
 **/
cdk_error_t
cdk_pk_check_sigs( cdk_kbnode_t knode, cdk_keydb_hd_t hd, int * r_status )
{
    cdk_pkt_signature_t sig = NULL;
    cdk_kbnode_t k;
    u32 keyid = 0;
    int key_status = 0;
    int rc = 0;

    if( !knode || !r_status )
        return CDK_Inv_Value;

    k = cdk_kbnode_find( knode, CDK_PKT_PUBLIC_KEY );
    if( !k )
        return CDK_Error_No_Key;
    if( k->pkt->pkt.public_key->is_revoked )
        key_status |= CDK_KEY_REVOKED;
    if( k->pkt->pkt.public_key->has_expired )
        key_status |= CDK_KEY_EXPIRED;
    if( key_status ) {
        *r_status = key_status;
        return CDK_General_Error;
    }
    keyid = cdk_pk_get_keyid( k->pkt->pkt.public_key, NULL );

    for( k = knode; k && k->pkt->pkttype; k = k->next ) {
        if( k->pkt->pkttype != CDK_PKT_SIGNATURE )
            continue;
        sig = k->pkt->pkt.signature;
        rc = _cdk_pk_check_sig( hd, knode, k );
        if( rc && IS_UID_SIG( sig ) && rc == CDK_Error_No_Key ) {
            sig->flags.missing_key = 1;
            continue;
        }
        else if( rc && rc != CDK_Error_No_Key ) {
            *r_status = CDK_KEY_INVALID;
            break; /* invalid self signature or key signature */
        }
        _cdk_log_debug( "signature %s: signer %08lX keyid %08lX\n",
                        rc==CDK_Bad_Sig? "BAD" : "good", sig->keyid[1],
                        keyid );
    }
    if( !rc || rc == CDK_Error_No_Key )
        *r_status = CDK_KEY_VALID;
    return rc;
}
