/* -*- Mode: C; c-file-style: "bsd" -*-
 * kbnode.c -  keyblock node utility functions
 *        Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *        Copyright (C) 2002, 2003 Timo Schulz
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
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
/* X-TODO-STATUS: OK */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"

#define is_deleted_kbnode(a)  ((a)->private_flag & 1)
#define is_cloned_kbnode(a)   ((a)->private_flag & 2)


/**
 * cdk_kbnode_new:
 * @pkt: the packet to add
 *
 * Allocate a new key node and add the packet.
 **/
cdk_kbnode_t
cdk_kbnode_new( cdk_packet_t pkt )
{
    cdk_kbnode_t n;
    n = cdk_calloc( 1, sizeof * n );
    if( !n )
        return NULL;
    n->pkt = pkt;
    return n;
}


void
_cdk_kbnode_clone( cdk_kbnode_t node )
{
    if( node )
        node->private_flag |= 2; /* mark cloned */
}


/**
 * cdk_kbnode_release:
 * @n: the key node
 *
 * Release the memory of the node.
 **/
void
cdk_kbnode_release( cdk_kbnode_t node )
{
    cdk_kbnode_t n2;

    while( node ) {
        n2 = node->next;
        node->pkt->pkttype = 0;
        if( !is_cloned_kbnode( node ) )
            cdk_pkt_release( node->pkt );
        cdk_free( node );
        node = n2;
    }
}


/**
 * cdk_kbnode_delete:
 * @node: the ke keynode.
 *
 * Delete @node.
 **/
void
cdk_kbnode_delete( cdk_kbnode_t node )
{
    if( node )
        node->private_flag |= 1;
}


/****************
 * Append NODE to ROOT.  ROOT must exist!
 */
void
_cdk_kbnode_add( cdk_kbnode_t root, cdk_kbnode_t node )
{
    cdk_kbnode_t n1;

    for( n1 = root; n1->next; n1 = n1->next )
        ;
    n1->next = node;
}


/**
 * cdk_kbnode_insert:
 * @root: the root key node
 * @node: the node to add
 * @pkttype: packet type
 *
 * Insert @node into the list after @root but before a packet which is not of
 * type @pkttype (only if @pkttype != 0).
 **/
void
cdk_kbnode_insert( cdk_kbnode_t root, cdk_kbnode_t node, int pkttype )
{
    if( !pkttype ) {
        node->next = root->next;
        root->next = node;
    }
    else {
        cdk_kbnode_t n1;
        for( n1 = root; n1->next; n1 = n1->next )
            if( pkttype != n1->next->pkt->pkttype ) {
                node->next = n1->next;
                n1->next = node;
                return;
            }
        /* no such packet, append */
        node->next = NULL;
        n1->next = node;
    }
}


/**
 * cdk_kbnode_find_prev:
 * @root: the root key node
 * @node: the key node
 * @pkttype: packet type
 *
 * Find the previous node (if @pkttype = 0) or the previous node
 * with pkttype @pkttype in the list starting with @root of @node.
 **/
cdk_kbnode_t
cdk_kbnode_find_prev( cdk_kbnode_t root, cdk_kbnode_t node, int pkttype )
{
    cdk_kbnode_t n1;

    for( n1 = NULL; root && root != node; root = root->next ) {
        if( !pkttype || root->pkt->pkttype == pkttype )
            n1 = root;
    }
    return n1;
}


/**
 * cdk_kbnode_find_next:
 * @node: the key node
 * @pkttype: packet type
 *
 * Ditto, but find the next packet.  The behaviour is trivial if
 * @pkttype is 0 but if it is specified, the next node with a packet
 * of this type is returned.  The function has some knowledge about
 * the valid ordering of packets: e.g. if the next signature packet
 * is requested, the function will not return one if it encounters
 * a user-id.
 **/
cdk_kbnode_t
cdk_kbnode_find_next( cdk_kbnode_t node, int pkttype )
{
    for( node = node->next; node; node = node->next ) {
        if( !pkttype )
            return node;
        else if( pkttype == CDK_PKT_USER_ID
                 && (node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
                     || node->pkt->pkttype == CDK_PKT_SECRET_KEY))
            return NULL;
        else if (pkttype == CDK_PKT_SIGNATURE
                 && (node->pkt->pkttype == CDK_PKT_USER_ID
                     || node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
                     || node->pkt->pkttype == CDK_PKT_SECRET_KEY))
            return NULL;
        else if (node->pkt->pkttype == pkttype)
            return node;
    }
    return NULL;
}


/**
 * cdk_kbnode_find:
 * @node: the key node
 * @pkttype: packet type
 *
 * Try to find the next node with the packettype @pkttype.
 **/
cdk_kbnode_t
cdk_kbnode_find( cdk_kbnode_t node, int pkttype )
{
    for( ; node; node = node->next ) {
        if( node->pkt->pkttype == pkttype )
            return node;
    }
    return NULL;
}


/**
 * cdk_kbnode_find_packet:
 * @node: the key node
 * @pkttype: packet type
 *
 * Same as cdk_kbnode_find but it returns the packet instead of the node.
 **/
cdk_packet_t
cdk_kbnode_find_packet( cdk_kbnode_t node, int pkttype )
{
    cdk_kbnode_t res;
  
    res = cdk_kbnode_find( node, pkttype );
    if( res )
        return res->pkt;
    return NULL;
}


/****************
 * Walk through a list of kbnodes. This function returns
 * the next kbnode for each call; before using the function the first
 * time, the caller must set CONTEXT to NULL (This has simply the effect
 * to start with ROOT).
 */
cdk_kbnode_t
cdk_kbnode_walk( cdk_kbnode_t root, cdk_kbnode_t * context, int all )
{
    cdk_kbnode_t n;

    do {
        if( !*context ) {
            *context = root;
            n = root;
	}
        else {
            n = (*context)->next;
            *context = n;
	}
    }
    while( !all && n && is_deleted_kbnode( n ) );
    return n;
}


/****************
 * Commit changes made to the kblist at ROOT. Note that ROOT my change,
 * and it is therefore passed by reference.
 * The function has the effect of removing all nodes marked as deleted.
 * returns true if any node has been changed
 */
int
cdk_kbnode_commit( cdk_kbnode_t * root )
{
    cdk_kbnode_t n, nl;
    int changed = 0;

    for( n = *root, nl = NULL; n; n = nl->next ) {
        if (is_deleted_kbnode (n)) {
            if( n == *root )
                *root = nl = n->next;
            else
                nl->next = n->next;
            if( !is_cloned_kbnode( n ) ) {
                cdk_pkt_release( n->pkt );
                cdk_free( n->pkt );
	    }
            cdk_free( n );
            changed = 1;
	}
        else
            nl = n;
    }
    return changed;
}


void
cdk_kbnode_remove( cdk_kbnode_t * root, cdk_kbnode_t node )
{
    cdk_kbnode_t n, nl;

    for( n = *root, nl = NULL; n; n = nl->next ) {
        if( n == node ) {
            if( n == *root )
                *root = nl = n->next;
            else
                nl->next = n->next;
            if( !is_cloned_kbnode( n ) ) {
                cdk_pkt_release( n->pkt );
                cdk_free( n->pkt);
	    }
            cdk_free( n );
	}
        else
            nl = n;
    }
}


/****************
 * Move NODE behind right after WHERE or to the beginning if WHERE is NULL.
 */
void
cdk_kbnode_move (cdk_kbnode_t * root, cdk_kbnode_t node, cdk_kbnode_t where)
{
    cdk_kbnode_t tmp, prev;

    if (!root || !*root || !node)
        return;			/* sanity check */
    for (prev = *root; prev && prev->next != node; prev = prev->next)
        ;
    if (!prev)
        return;			/* node is not in the list */

    if (!where) {		/* move node before root */
        if (node == *root)	/* move to itself */
            return;
        prev->next = node->next;
        node->next = *root;
        *root = node;
        return;
    }
    /* move it after where */
    if (node == where)
        return;
    tmp = node->next;
    node->next = where->next;
    where->next = node;
    prev->next = tmp;
}


/**
 * cdk_kbnode_get_packet:
 * @node: the key node
 *
 * Return the packet which is stored inside the node in @node.
 **/
cdk_packet_t
cdk_kbnode_get_packet( cdk_kbnode_t node )
{
    if( node )
        return node->pkt;
    return NULL;
}


/**
 * cdk_kbnode_read_from_mem:
 * @ret_node: the new key node
 * @buf: the buffer which stores the key sequence
 * @buflen: the length of the buffer
 *
 * Try to read a key node from the memory buffer @buf.
 **/
cdk_error_t
cdk_kbnode_read_from_mem( cdk_kbnode_t * ret_node,
                          const byte * buf, size_t buflen )
{
    cdk_stream_t inp;
    int rc;

    if( !buflen || !ret_node )
        return CDK_Inv_Value;

    *ret_node = NULL;
    inp = cdk_stream_tmp_from_mem( buf, buflen );
    if( !inp )
        return CDK_Out_Of_Core;
    rc = cdk_keydb_get_keyblock( inp, ret_node );
    if( rc == CDK_EOF && *ret_node )
        rc = 0;
    cdk_stream_close( inp );
    return rc;
}


/**
 * cdk_kbnode_write_to_mem:
 * @node: the key node
 * @buf: the buffer to store the node data
 * @r_nbytes: the new length of the buffer.
 *
 * Try to write the contents of the key node to the buffer @buf and
 * return the length of it in @r_nbytes. If buf is zero, only the
 * length of the node is calculated and returned in @r_nbytes.
 **/
cdk_error_t
cdk_kbnode_write_to_mem( cdk_kbnode_t node, byte * buf, size_t * r_nbytes )
{
    cdk_kbnode_t n;
    cdk_stream_t s;
    int rc = 0, len;

    if( !node )
        return CDK_Inv_Value;
    
    s = cdk_stream_tmp( );
    if( !s )
        return CDK_Out_Of_Core;
  
    for( n = node; n; n = n->next ) {
        if( n->pkt->pkttype != CDK_PKT_PUBLIC_KEY
            && n->pkt->pkttype != CDK_PKT_PUBLIC_SUBKEY
            && n->pkt->pkttype != CDK_PKT_SECRET_KEY
            && n->pkt->pkttype != CDK_PKT_SECRET_SUBKEY
            && n->pkt->pkttype != CDK_PKT_SIGNATURE
            && n->pkt->pkttype != CDK_PKT_USER_ID )
            continue;
        rc = cdk_pkt_write( s, n->pkt );
        if( rc )
            break;
    }
    if( !rc ) {
        cdk_stream_seek( s, 0 );
        len = cdk_stream_get_length( s );
        if( !buf ) {
            *r_nbytes = len; /* only return the length of the buffer */
            cdk_stream_close( s );
            return 0;
        }
        if( *r_nbytes < len )
            rc = CDK_Too_Short;
        if( !rc )
            *r_nbytes = cdk_stream_read( s, buf, len );
    }
    cdk_stream_close( s );
    return rc;
}


/**
 * cdk_kbnode_get_attr:
 * @node: the key node
 * @pkttype: the packet type which the attribute should be retrieved from
 * @attr: the attribute to retrive
 *
 * Extract a single attribute from the specified packet type. If no
 * packet type is given, it is assumed that the public key is meant.
 * If the attr was found, it is returned as a pointer which can be cast
 * to a proper type.
 **/
void *
cdk_kbnode_get_attr( cdk_kbnode_t node, int pkttype, int attr )
{
    cdk_packet_t pkt;
    cdk_pkt_pubkey_t pk;
    cdk_pkt_userid_t id;
    cdk_pkt_signature_t sig;
    
    if( !node || !attr )
        return NULL;
    if( !pkttype )
        pkttype = CDK_PKT_PUBLIC_KEY;
    pkt = cdk_kbnode_find_packet( node, pkttype );
    if( !pkt )
        return NULL;
    switch( pkttype ) {
    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_PUBLIC_KEY:
        if( pkttype == CDK_PKT_PUBLIC_KEY )
            pk = pkt->pkt.public_key;
        else
            pk = pkt->pkt.secret_key->pk;
        assert( pk );
        switch( attr ) {
        case CDK_ATTR_CREATED: return (long *)pk->timestamp;
        case CDK_ATTR_EXPIRE : return (long *)pk->expiredate;
        case CDK_ATTR_VERSION: return (byte *)pk->version;
        case CDK_ATTR_LEN    : return (long *)cdk_pk_get_nbits( pk );
        case CDK_ATTR_KEYID:
            if( !pk->keyid[0] || !pk->keyid[1] )
                cdk_pk_get_keyid( pk, pk->keyid );
            return pk->keyid;
        case CDK_ATTR_FPR:
            if( !pk->fpr[0] )
                cdk_pk_get_fingerprint( pk, pk->fpr );
            return pk->fpr;
        case CDK_ATTR_ALGO_PK: return (byte *)pk->pubkey_algo;
        default: return NULL;
        }
        break;

    case CDK_PKT_USER_ID:
        id = pkt->pkt.user_id;
        switch( attr ) {
        case CDK_ATTR_LEN : return (long *)id->len;
        case CDK_ATTR_NAME: return id->name;
        default: return NULL;
        }
        break;

    case CDK_PKT_SIGNATURE:
        sig = pkt->pkt.signature;
        switch( attr ) {
        case CDK_ATTR_ALGO_MD: return (byte *)sig->digest_algo;
        case CDK_ATTR_ALGO_PK: return (byte *)sig->pubkey_algo;
        case CDK_ATTR_VERSION: return (byte *)sig->version;
        case CDK_ATTR_KEYID  : return (u32 *)cdk_sig_get_keyid( sig, NULL );
        default: return NULL;
        }
        break;

    default:
        return NULL;
    }
    return NULL;
}


/**
 * cdk_kbnode_hash:
 * @node: the key node
 * @hashctx: opaque pointer to the hash context
 * @is_v4: OpenPGP signature (yes=1, no=0)
 * @pkttype: packet type to hash (if zero use the packet type from the node)
 * @flags: flags which depend on the operation
 *
 * Hash the key node contents. Two modes are supported. If the packet
 * type is used (!= 0) then the function searches the first node with
 * this type. Otherwise the node is seen as a single node and the type
 * is extracted from it.
 **/
cdk_error_t
cdk_kbnode_hash( cdk_kbnode_t node, cdk_md_hd_t md, int is_v4,
                 int pkttype, int flags )
{
    cdk_packet_t pkt;

    if( !node || !md )
        return CDK_Inv_Value;
    if( !pkttype )
        pkttype = node->pkt->pkttype;
    pkt = cdk_kbnode_find_packet( node, pkttype );
    if( !pkt )
        return CDK_Inv_Packet;
    switch( pkttype ) {
    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
        _cdk_hash_pubkey( pkt->pkt.public_key, md, flags & 1 ); break;
    case CDK_PKT_USER_ID:
        _cdk_hash_userid( pkt->pkt.user_id, is_v4, md ); break;
    case CDK_PKT_SIGNATURE:
        _cdk_hash_sig_data( pkt->pkt.signature, md ); break;
    default:
        return CDK_Inv_Mode;
    }
    return 0;
}

    
