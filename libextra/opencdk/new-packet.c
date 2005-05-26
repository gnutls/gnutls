/* -*- Mode: C; c-file-style: "bsd" -*-
 * new-packet.c - General packet handling (freeing, copying, ...)
 *       Copyright (C) 2001, 2002, 2003 Timo Schulz 
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
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


void
_cdk_free_mpibuf( size_t n, gcry_mpi_t * array )
{
    while( n-- ) {
        gcry_mpi_release( array[n] );
        array[n] = NULL;
    }
}


cdk_error_t
cdk_pkt_new( cdk_packet_t* r_pkt )
{
    cdk_packet_t pkt;

    if( !r_pkt )
        return CDK_Inv_Value;
    pkt = cdk_calloc( 1, sizeof *pkt );
    if( !pkt )
        return CDK_Out_Of_Core;
    *r_pkt = pkt;
    return 0;
}


void
cdk_pkt_init( cdk_packet_t pkt )
{
    if( pkt )
        memset( pkt, 0, sizeof * pkt );
}


static void
free_symkey_enc (cdk_pkt_symkey_enc_t enc)
{
    if (enc) {
        cdk_free (enc->s2k);
        cdk_free (enc);
    }
}


static void
free_pubkey_enc (cdk_pkt_pubkey_enc_t enc)
{
    int nenc;
    if (enc) {
        nenc = cdk_pk_get_nenc (enc->pubkey_algo);
        while (enc->mpi && nenc--) {
            cdk_free (enc->mpi[nenc]);
            enc->mpi[nenc] = NULL;
        }
        cdk_free (enc);
    }
}


static void
free_literal (cdk_pkt_literal_t pt)
{
    if (pt)
        cdk_free (pt);
}


void
_cdk_free_userid (cdk_pkt_userid_t uid)
{
    if (uid) {
        cdk_free (uid->prefs);
        uid->prefs = NULL;
        cdk_free (uid->attrib_img);
        uid->attrib_img = NULL;      
        cdk_free (uid);
    }
}


void
_cdk_free_signature (cdk_pkt_signature_t sig)
{
    int nsig;
    cdk_desig_revoker_t r;
    
    if (sig) {
        nsig = cdk_pk_get_nsig (sig->pubkey_algo);
        while (sig->mpi && nsig--) {
            cdk_free (sig->mpi[nsig]);
            sig->mpi[nsig] = NULL;
        }
        cdk_subpkt_free (sig->hashed);
        sig->hashed = NULL;
        cdk_subpkt_free (sig->unhashed);
        sig->unhashed = NULL;
        while( sig->revkeys ) {
            r = sig->revkeys->next;
            cdk_free( sig->revkeys );
            sig->revkeys = r;
        }
        cdk_free (sig);
    }
}


void
_cdk_free_pubkey (cdk_pkt_pubkey_t pk)
{
    int npkey;
    if (pk) {
        npkey = cdk_pk_get_npkey (pk->pubkey_algo);
        _cdk_free_userid (pk->uid);
        pk->uid = NULL;
        cdk_free (pk->prefs);
        pk->prefs = NULL;
        while (pk->mpi && npkey--) {
            cdk_free (pk->mpi[npkey]);
            pk->mpi[npkey] = NULL; 
        }
        cdk_free (pk);
    }
}


void
_cdk_free_seckey (cdk_pkt_seckey_t sk)
{
    int nskey;
  
    if (sk) {
        nskey = cdk_pk_get_nskey (sk->pubkey_algo);
        while (nskey--) {
            if (sk->mpi[nskey]) {
                wipemem (sk->mpi[nskey], sk->mpi[nskey]->bytes);
                cdk_free (sk->mpi[nskey]);
                sk->mpi[nskey] = NULL;
            }
        }
        cdk_free (sk->encdata);
        sk->encdata = NULL;
        _cdk_free_pubkey (sk->pk);
        sk->pk = NULL;
        cdk_free (sk->protect.s2k);
        sk->protect.s2k = NULL;
        cdk_free (sk);
    }
}


static void
free_encrypted (cdk_pkt_encrypted_t enc)
{
    if (enc) {
        cdk_stream_close (enc->buf);
        enc->buf = NULL;
        cdk_free (enc);
    }
}


void
cdk_pkt_free (cdk_packet_t pkt)
{
    if (!pkt)
        return;

    switch (pkt->pkttype) {
    case CDK_PKT_ATTRIBUTE    :
    case CDK_PKT_USER_ID      : _cdk_free_userid (pkt->pkt.user_id); break;
    case CDK_PKT_PUBLIC_KEY   :
    case CDK_PKT_PUBLIC_SUBKEY: _cdk_free_pubkey (pkt->pkt.public_key); break;
    case CDK_PKT_SECRET_KEY   :
    case CDK_PKT_SECRET_SUBKEY: _cdk_free_seckey (pkt->pkt.secret_key); break;
    case CDK_PKT_SIGNATURE    : _cdk_free_signature (pkt->pkt.signature);break;
    case CDK_PKT_PUBKEY_ENC   : free_pubkey_enc (pkt->pkt.pubkey_enc); break;
    case CDK_PKT_SYMKEY_ENC   : free_symkey_enc (pkt->pkt.symkey_enc); break;
    case CDK_PKT_MDC          : cdk_free (pkt->pkt.mdc); break;
    case CDK_PKT_ENCRYPTED    :
    case CDK_PKT_ENCRYPTED_MDC: free_encrypted (pkt->pkt.encrypted); break;
    case CDK_PKT_ONEPASS_SIG  : cdk_free (pkt->pkt.onepass_sig); break;
    case CDK_PKT_LITERAL      : free_literal (pkt->pkt.literal); break;
    case CDK_PKT_COMPRESSED   : cdk_free (pkt->pkt.compressed); break;
    default                   : break;
    }
}


void
cdk_pkt_release (cdk_packet_t pkt)
{
    if (pkt) {
        cdk_pkt_free (pkt);
        cdk_free (pkt);
    }
}


cdk_error_t
cdk_pkt_alloc( cdk_packet_t* r_pkt, int pkttype )
{
    cdk_packet_t pkt;
    int rc = 0;

    if( !r_pkt )
        return CDK_Inv_Value;
    
    rc = cdk_pkt_new( &pkt );
    if( rc )
        return rc;

    switch (pkttype) {
    case CDK_PKT_USER_ID:
        pkt->pkt.user_id = cdk_calloc (1, sizeof pkt->pkt.user_id);
        if (!pkt->pkt.user_id)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
        pkt->pkt.public_key = cdk_calloc (1, sizeof *pkt->pkt.public_key);
        if (!pkt->pkt.public_key)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_SECRET_SUBKEY:
        pkt->pkt.secret_key = cdk_calloc (1, sizeof *pkt->pkt.secret_key);
        pkt->pkt.secret_key->pk =
            cdk_calloc (1, sizeof *pkt->pkt.secret_key->pk);
        if (!pkt->pkt.secret_key || !pkt->pkt.secret_key->pk)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_SIGNATURE:
        pkt->pkt.signature = cdk_calloc (1, sizeof *pkt->pkt.signature);
        if (!pkt->pkt.signature)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_PUBKEY_ENC:
        pkt->pkt.pubkey_enc = cdk_calloc (1, sizeof *pkt->pkt.pubkey_enc);
        if (!pkt->pkt.pubkey_enc)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_MDC:
        pkt->pkt.mdc = cdk_calloc (1, sizeof *pkt->pkt.mdc);
        if (!pkt->pkt.mdc)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_ENCRYPTED_MDC:
    case CDK_PKT_ENCRYPTED:
        pkt->pkt.symkey_enc = cdk_calloc (1, sizeof *pkt->pkt.symkey_enc);
        if (!pkt->pkt.symkey_enc)
            return CDK_Out_Of_Core;
        break;

    case CDK_PKT_LITERAL:
        pkt->pkt.literal = cdk_calloc (1, sizeof *pkt->pkt.literal);
        if (!pkt->pkt.literal)
            return CDK_Out_Of_Core;
        break;
    }
    pkt->pkttype = pkttype;
    *r_pkt = pkt;
    return 0;
}


byte *
cdk_userid_pref_get_array( cdk_pkt_userid_t id, int type, size_t *ret_len )
{
    cdk_prefitem_t prefs;
    byte * p;
    int i = 0, j = 0;
    
    if( !id || !id->prefs || !ret_len )
        return NULL;
    
    prefs = id->prefs;
    while( prefs[i].type ) {
        if( prefs[i].type == type )
            j++;
        i++;
    }
    if( !j )
        return 0;
    p = cdk_calloc( 1, j + 1 );
    *ret_len = j;
    i = j = 0;
    while( prefs[i].type ) {
        if( prefs[i].type == type )
            p[j++] = prefs[i].value;
        i++;
    }
    p[j] = 0;
    return p;
}


cdk_prefitem_t
_cdk_copy_prefs( const cdk_prefitem_t prefs )
{
    size_t n = 0;
    struct cdk_prefitem_s *new_prefs;
  
    if (!prefs)
        return NULL;

    for (n = 0; prefs[n].type; n++)
        ;
    new_prefs = cdk_calloc (1, sizeof *new_prefs * (n + 1));
    if (!new_prefs)
        return NULL;
    for (n = 0; prefs[n].type; n++) {
        new_prefs[n].type = prefs[n].type;
        new_prefs[n].value = prefs[n].value;
    }
    new_prefs[n].type = CDK_PREFTYPE_NONE;
    new_prefs[n].value = 0;

    return new_prefs;
}


cdk_error_t
_cdk_copy_userid (cdk_pkt_userid_t* dst, cdk_pkt_userid_t src)
{
    cdk_pkt_userid_t u;

    if (!dst || !src)
        return CDK_Inv_Value;

    u = cdk_calloc (1, sizeof *u + strlen (src->name) + 1);
    if (!u)
        return CDK_Out_Of_Core;
    memcpy (u, src, sizeof *u);
    memcpy (u->name, src->name, strlen (src->name));
    u->prefs = _cdk_copy_prefs (src->prefs);
    *dst = u;

    return 0;
}


cdk_error_t
_cdk_copy_pubkey (cdk_pkt_pubkey_t* dst, cdk_pkt_pubkey_t src)
{
    cdk_pkt_pubkey_t k;
    int i;

    if (!dst || !src)
        return CDK_Inv_Value;

    k = cdk_calloc (1, sizeof *k);
    if (!k)
        return CDK_Out_Of_Core;
    memcpy (k, src, sizeof *k);
    if (src->uid)
        _cdk_copy_userid (&k->uid, src->uid);
    if (src->prefs)
        k->prefs = _cdk_copy_prefs (src->prefs);
    for (i = 0; i < cdk_pk_get_npkey (src->pubkey_algo); i++) {
        k->mpi[i] = cdk_calloc (1, sizeof **k->mpi + src->mpi[i]->bytes + 2);
        if (!k->mpi[i])
            return CDK_Out_Of_Core;
        k->mpi[i]->bits = src->mpi[i]->bits;
        k->mpi[i]->bytes = src->mpi[i]->bytes;
        /* copy 2 extra bytes (prefix) */
        memcpy (k->mpi[i]->data, src->mpi[i]->data, src->mpi[i]->bytes + 2);
    }
    *dst = k;

    return 0;
}


cdk_error_t
_cdk_copy_seckey (cdk_pkt_seckey_t* dst, cdk_pkt_seckey_t src)
{
    cdk_pkt_seckey_t k;
    cdk_mpi_t a;
    cdk_s2k_t s2k;
    int i;

    if (!dst || !src)
        return CDK_Inv_Value;

    k = cdk_calloc (1, sizeof *k);
    if (!k)
        return CDK_Out_Of_Core;
    memcpy (k, src, sizeof *k);
    _cdk_copy_pubkey (&k->pk, src->pk);

    if (src->encdata) {
        k->encdata = cdk_calloc (1, src->enclen + 1);
        if (!k->encdata)
            return CDK_Out_Of_Core;
        memcpy (k->encdata, src->encdata, src->enclen);
    }

    s2k = k->protect.s2k = cdk_calloc (1, sizeof *k->protect.s2k);
    if (!k->protect.s2k)
        return CDK_Out_Of_Core;
    s2k->mode = src->protect.s2k->mode;
    s2k->hash_algo = src->protect.s2k->hash_algo;
    s2k->count = src->protect.s2k->count;
    memcpy (s2k->salt, src->protect.s2k->salt, 8);

    for (i = 0; i < cdk_pk_get_nskey (src->pubkey_algo); i++) {
        a = k->mpi[i] = cdk_calloc (1, sizeof **k->mpi + src->mpi[i]->bytes + 2);
        if (!k->mpi[i])
            return CDK_Out_Of_Core;
        a->bits = src->mpi[i]->bits;
        a->bytes = src->mpi[i]->bytes;
        /* copy 2 extra bytes (prefix) */
        memcpy (a->data, src->mpi[i]->data, src->mpi[i]->bytes + 2);
    }
    *dst = k;

    return 0;
}


cdk_error_t
_cdk_copy_pk_to_sk( cdk_pkt_pubkey_t pk, cdk_pkt_seckey_t sk )
{
    if( !pk || !sk )
        return CDK_Inv_Value;

    sk->version = pk->version;
    sk->expiredate = pk->expiredate;
    sk->pubkey_algo = pk->pubkey_algo;
    sk->has_expired = pk->has_expired;
    sk->is_revoked = pk->is_revoked;
    sk->main_keyid[0] = pk->main_keyid[0];
    sk->main_keyid[1] = pk->main_keyid[1];
    sk->keyid[0] = pk->keyid[0];
    sk->keyid[1] = pk->keyid[1];

    return 0;
}


cdk_error_t
_cdk_copy_signature (cdk_pkt_signature_t* dst, cdk_pkt_signature_t src)
{
    cdk_pkt_signature_t s = NULL;
    struct cdk_subpkt_s *res = NULL;

    if (!dst || !src)
        return CDK_Inv_Value;

    s = cdk_calloc (1, sizeof *s);
    if (!s)
        return CDK_Out_Of_Core;
    memcpy (s, src, sizeof *src);

    _cdk_subpkt_copy (&res, src->hashed);
    _cdk_subpkt_copy (&s->hashed, res);
    cdk_subpkt_free (res);
    res = NULL;
    _cdk_subpkt_copy (&res, src->unhashed);
    _cdk_subpkt_copy (&s->unhashed, res);
    cdk_subpkt_free (res);
    res = NULL;
    *dst = s;

    return 0;
}


cdk_error_t
_cdk_pubkey_compare (cdk_pkt_pubkey_t a, cdk_pkt_pubkey_t b)
{
    int na, nb, i;

    if (a->timestamp != b->timestamp || a->pubkey_algo != b->pubkey_algo)
        return -1;
    if (a->version < 4 && a->expiredate != b->expiredate)
        return -1;
    na = cdk_pk_get_npkey (a->pubkey_algo);
    nb = cdk_pk_get_npkey (b->pubkey_algo);
    if (na != nb)
        return -1;
  
    for (i = 0; i < na; i++) {
        if (memcmp (a->mpi[i]->data, b->mpi[i]->data, a->mpi[i]->bytes))
            return -1;
    }

    return 0;
}


/**
 * cdk_subpkt_free:
 * @ctx: the sub packet node to free
 *
 * Release the context.
 **/
void
cdk_subpkt_free( cdk_subpkt_t ctx )
{
    cdk_subpkt_t s;

    while( ctx ) {
        s = ctx->next;
        cdk_free( ctx );
        ctx = s;
    }
}


/**
 * cdk_subpkt_find:
 * @ctx: the sub packet node
 * @type: the packet type to find
 *
 * Find the given packet type in the node. If no packet with this
 * type was found, return null otherwise pointer to the node.
 **/
cdk_subpkt_t
cdk_subpkt_find( cdk_subpkt_t ctx, int type )
{
    cdk_subpkt_t s;

    /* xxx: add some code for the case there are more than one sub packet
            with the same type. */
    for( s = ctx; s; s = s->next ) {
        if( s->type == type )
            return s;
    }

    return NULL;
}


/**
 * cdk_subpkt_new:
 * @size: the size of the new context
 *
 * Create a new sub packet node with the size of @size.
 **/
cdk_subpkt_t
cdk_subpkt_new( size_t size )
{
    cdk_subpkt_t s;

    if( !size )
        return NULL;
    s = cdk_calloc( 1, sizeof *s + size + 1 );
    if( !s )
        return NULL;
    return s;
}


/**
 * cdk_subpkt_get_data:
 * @ctx: the sub packet node
 * @r_type: pointer store the packet type
 * @r_nbytes: pointer to store the packet size
 *
 * Extract the data from the given sub packet. The type is returned
 * in @r_type and the size in @r_nbytes.
 **/
const byte *
cdk_subpkt_get_data( cdk_subpkt_t ctx, int * r_type, size_t * r_nbytes )
{
    if( !ctx || !r_nbytes )
        return NULL;
    if( r_type )
        *r_type = ctx->type;
    *r_nbytes = ctx->size;
    return ctx->d;
}
  

/**
 * cdk_subpkt_add:
 * @root: the root node
 * @node: the node to add
 *
 * Add the node in @node to the root node @root.
 **/
cdk_error_t
cdk_subpkt_add( cdk_subpkt_t root, cdk_subpkt_t node )
{
    cdk_subpkt_t n1;

    if( !root )
        return CDK_Inv_Value;
    for( n1 = root; n1->next; n1 = n1->next )
        ;
    n1->next = node;
    return 0;
}


byte *
_cdk_subpkt_get_array( cdk_subpkt_t s, int count, size_t * r_nbytes )
{
    cdk_subpkt_t list;
    byte * buf;
    int n, nbytes;
  
    if( !s ) {
        if( r_nbytes )
            *r_nbytes = 0;
        return NULL;
    }

    for( n=0, list = s; list; list = list->next ) {
        n += list->size + 1;
        if( list->size < 192 ) n++;
        else if( list->size < 8384 ) n += 2;
        else n += 5;
    }
    buf = cdk_calloc( 1, n+1 );
    if( !buf )
        return NULL;

    n = 0;
    for( list = s; list; list = list->next ) {
        nbytes = 1 + list->size; /* type */
        if( nbytes < 192 )
            buf[n++] = nbytes;
        else if( nbytes < 8384 ) {
            buf[n++] = nbytes / 256 + 192;
            buf[n++] = nbytes % 256;
        }
        else {
            buf[n++] = 0xFF;
            buf[n++] = nbytes >> 24;
            buf[n++] = nbytes >> 16;
            buf[n++] = nbytes >>  8;
            buf[n++] = nbytes;
        }
        buf[n++] = list->type;
        memcpy( buf + n, list->d, list->size );
        n += list->size;
    }
    if( count ) {
        cdk_free( buf );
        buf = NULL;
    }
    if( r_nbytes )
        *r_nbytes = n;
    return buf;
}


cdk_error_t
_cdk_subpkt_copy( cdk_subpkt_t * r_dst, cdk_subpkt_t src )
{
    cdk_subpkt_t root, p, node;

    if (!src || !r_dst)
        return CDK_Inv_Value;
  
    root = NULL;
    for (p = src; p; p = p->next) {
        node = cdk_subpkt_new (p->size);
        if (node) {
            memcpy (node->d, p->d, p->size);
            node->type = p->type;
            node->size = p->size;
        }
        if (!root)
            root = node;
        else
            cdk_subpkt_add (root, node);
    }
    *r_dst = root;
    return 0;
}


cdk_error_t
_cdk_subpkt_hash( cdk_subpkt_t hashed, size_t * r_nbytes, cdk_md_hd_t hd )
{
    byte * p, buf[2];
    size_t nbytes;

    p = _cdk_subpkt_get_array (hashed, 0, &nbytes);
    if (!p)
        return CDK_Out_Of_Core;
    if (nbytes > 65535)
        return CDK_Inv_Value;
    buf[0] = nbytes >> 8;
    buf[1] = nbytes;
    cdk_md_write (hd, buf, 2);
    cdk_md_write (hd, p, nbytes);
    if (r_nbytes)
        *r_nbytes = nbytes;
    return 0;
}


/**
 * cdk_subpkt_init:
 * @node: the sub packet node
 * @type: type of the packet which data should be initialized
 * @buf: the buffer with the actual data
 * @buflen: the size of the data
 *
 * Set the packet data of the given root and set the type of it.
 **/
void
cdk_subpkt_init( cdk_subpkt_t node, int type, const void *buf, size_t buflen )
{
    if( node ) {
        node->type = type;
        node->size = buflen;
        memcpy( node->d, buf, buflen );   
    }    
}


const byte*
cdk_key_desig_revoker_walk( cdk_desig_revoker_t root,
                            cdk_desig_revoker_t * ctx,
                            int *r_class, int *r_algid )
{
    cdk_desig_revoker_t n;
    
    if( !*ctx ) {
        *ctx = root;
        n = root;
    }
    else {
        n = (*ctx)->next;
        *ctx = n;
    }
    if( n && r_class && r_algid ) {
        *r_class = n->class;
        *r_algid = n->algid;
    }
    return n? n->fpr : NULL;
}
