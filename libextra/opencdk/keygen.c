/* -*- Mode: C; c-file-style: "bsd" -*-
 * keygen.c - OpenPGP key generation
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"
#include "types.h"

struct key_ctx_s {
    u32 expire_date;
    int algo;
    int len;
    gcry_mpi_t resarr[6];
    size_t n;
    cdk_pkt_pubkey_t pk;
    cdk_pkt_seckey_t sk;
};


struct cdk_keygen_ctx_s {
    char * user_id;
    cdk_pkt_userid_t id;
    byte * sym_prefs;
    size_t sym_len;
    byte * hash_prefs;
    size_t hash_len;
    byte * zip_prefs;
    size_t zip_len;
    unsigned mdc_feature:1;
    unsigned ks_no_modify:1;
    char * ks_pref_url;
    cdk_pkt_signature_t sig;
    unsigned protect:1;
    struct key_ctx_s key[2];
    char * pass;
    size_t pass_len;
};


/* default preferences */
static byte def_sym_prefs[] = {CDK_CIPHER_AES, CDK_CIPHER_CAST5,
                               CDK_CIPHER_TWOFISH, CDK_CIPHER_AES192,
                               CDK_CIPHER_AES256, CDK_CIPHER_3DES,
                               CDK_CIPHER_BLOWFISH};
static byte def_hash_prefs[] = {CDK_MD_SHA1, CDK_MD_RMD160, CDK_MD_MD5};
static byte def_zip_prefs[] = {CDK_COMPRESS_ZIP, CDK_COMPRESS_ZLIB};


static int
check_pref_array( const byte * p, size_t n, int type )
{
    int i;

    if( !p )
        return 0;
    
    if( type == CDK_PREFTYPE_SYM ) {
        for( i = 0; i < n; i++ ) {
            if( cdk_cipher_test_algo( p[i] ) )
                return -1;
        }
    }
    else if( type == CDK_PREFTYPE_HASH ) {
        for( i = 0; i < n; i++ ) {
            if( cdk_md_test_algo( p[i] ) )
                return -1;
        }
    }
    else if( type == CDK_PREFTYPE_ZIP ) {
        if( n > 2 )
            return -1;
        if( p[0] > 2 || p[1] > 2 )
            return -1;
    }
    else
        return -1;
    return 0;
}


/**
 * cdk_keygen_set_prefs: Set the preferences for the userID
 * @hd: the keygen object
 * @hd: the preference type
 * @array: one-octet array with algorithm numers
 *
 **/
cdk_error_t
cdk_keygen_set_prefs( cdk_keygen_ctx_t hd, enum cdk_pref_type_t type,
                      const byte * array, size_t n )
{
    int rc;
    
    if( !hd )
        return CDK_Inv_Value;

    rc = check_pref_array( array, n, type );
    if( rc )
        return CDK_Inv_Value;
    
    switch( type) {
    case CDK_PREFTYPE_SYM:
        hd->sym_len = array? n : DIM( def_sym_prefs );
        hd->sym_prefs = cdk_calloc( 1, hd->sym_len );
        if( hd->sym_prefs )
            memcpy( hd->sym_prefs, array? array : def_sym_prefs, hd->sym_len );
        break;
      
    case CDK_PREFTYPE_HASH:
        hd->hash_len = array? n : DIM( def_hash_prefs );
        hd->hash_prefs = cdk_calloc( 1, hd->hash_len );
        if( hd->hash_prefs )
            memcpy( hd->hash_prefs, array? array : def_hash_prefs,
                    hd->hash_len );
        break;
      
    case CDK_PREFTYPE_ZIP:
        hd->zip_len = array? n : DIM( def_zip_prefs );
        hd->zip_prefs = cdk_calloc( 1, hd->zip_len );
        if( hd->zip_prefs )
            memcpy( hd->zip_prefs, array? array : def_zip_prefs, hd->zip_len );
        break;
      
    default:
        return CDK_Inv_Mode;
    }
  
    return 0;
}


/**
 * cdk_keygen_set_name: set the userid name for the key
 * @hd: the keygen object
 * @name: name
 *
 * The name will be encoded in UTF8 to avoid problems.
 **/
void
cdk_keygen_set_name( cdk_keygen_ctx_t hd, const char * name )
{
    if( hd ) {
        cdk_free( hd->user_id );
        hd->user_id = cdk_utf8_encode( name );
    }
}


static int
check_bits( int bits, int algo )
{
    if( bits < 768 )
        return 768;
    if( algo == CDK_PK_DSA && bits > 1024 )
        return 1024;
    if( bits > 4096 )
        return 4096;
    return bits;
}


/**
 * cdk_keygen_set_algo_info: set the length and type of the key
 * @hd: the keygen object.
 * @type: key type (primary=0, subkey=1)
 * @algo: algorithm compliant with rfc2440
 * @bits: lengt of the key in bits
 *
 **/
cdk_error_t
cdk_keygen_set_algo_info( cdk_keygen_ctx_t hd, int type,
                          enum cdk_pk_algo_t algo, int bits )
{
    int rc;
    int usage = type? PK_USAGE_ENCR : PK_USAGE_SIGN;
  
    if( !hd )
        return CDK_Inv_Value;
    if( type < 0 || type > 1 )
        return CDK_Inv_Value;

    if( bits % 128 != 0 )
        bits = bits + ( bits % 128 );
  
    rc = _cdk_pk_test_algo( algo, usage );
    if( rc )
        return rc;

    /* type=0 primary type=1 sub */
    hd->key[type].algo = algo;
    hd->key[type].len = check_bits( bits, algo );

    return 0;
}


/**
 * cdk_keygen_set_mdc_feature: set the mdc feature for the key
 * @hd: keygen object
 * @val: boolean( yes=1, no=0)
 *
 * if you want a RFC2440 compliant key, you've to disable this feature
 * until the rfc2440-bis8 becomes the next standard.
 **/
void
cdk_keygen_set_mdc_feature( cdk_keygen_ctx_t hd, int val )
{
    if( hd )
        hd->mdc_feature = val;
}



void
cdk_keygen_set_keyserver_flags( cdk_keygen_ctx_t hd, int no_modify,
                                const char *pref_url )
{
    if( no_modify )
        hd->ks_no_modify = 1;
    if( pref_url )
        hd->ks_pref_url = cdk_strdup( pref_url );
} /* cdk_keygen_set_keyserver_flags */

    
/**
 * cdk_keygen_set_expire_date: set the expire date of the primary key
 * @hd: keygen object
 * @type: key type( 0=primary, 1=seconardy)
 * @timestamp: the date the key should expire
 *
 **/
void
cdk_keygen_set_expire_date( cdk_keygen_ctx_t hd, int type, long timestamp )
{
    if( !hd )
        return;
    if( type < 0 || type > 1 )
        return;
    if( timestamp < 0 || timestamp < _cdk_timestamp( ) )
        timestamp = 0;
    hd->key[type].expire_date = timestamp;
}


void
cdk_keygen_set_passphrase( cdk_keygen_ctx_t hd, const char * pass )
{
    if( !hd )
        return;
    if( pass ) {
        size_t n = strlen( pass );
        _cdk_sec_free( hd->pass, hd->pass_len );
        hd->pass = cdk_salloc( n + 1, 1 );
        if( hd->pass ) {
            memcpy( hd->pass, pass, n );
            hd->pass[n] = '\0';
            hd->pass_len = n;
            hd->protect = 1;
        }
    }
}


static int
read_single_mpi( gcry_sexp_t s_key, const char * val, gcry_mpi_t * r_resarr )
{
    gcry_sexp_t list;

    if( !r_resarr )
        return CDK_Inv_Value;
    list = gcry_sexp_find_token( s_key, val, 0 );
    if( list )
        *r_resarr = gcry_sexp_nth_mpi( list, 1, 0 );
    gcry_sexp_release( list );
    return list? 0 : CDK_Gcry_Error;
}

  
static int
read_dsa_key( gcry_sexp_t s_key, gcry_mpi_t * resarr )
{
    int rc = read_single_mpi( s_key, "p", &resarr[0] );
    if( !rc )
        rc = read_single_mpi( s_key, "q", &resarr[1] );
    if( !rc )
        rc = read_single_mpi( s_key, "g", &resarr[2] );
    if( !rc )
        rc = read_single_mpi( s_key, "y", &resarr[3] );
    if( !rc )
        rc = read_single_mpi( s_key, "x", &resarr[4] );
    return rc;
}


static int
read_elg_key( gcry_sexp_t s_key, gcry_mpi_t * resarr )
{
    int rc = read_single_mpi( s_key, "p", &resarr[0] );
    if( !rc )
        rc = read_single_mpi( s_key, "g", &resarr[1] );
    if( !rc )
        rc = read_single_mpi( s_key, "y", &resarr[2] );
    if( !rc )
        rc = read_single_mpi( s_key, "x", &resarr[3] );
    return rc;  
}


static int
read_rsa_key( gcry_sexp_t s_key, gcry_mpi_t * resarr )
{
    int rc = read_single_mpi( s_key, "n", &resarr[0] );
    if( !rc )
        rc =read_single_mpi( s_key, "e", &resarr[1] );
    if( !rc )
        rc = read_single_mpi( s_key, "d", &resarr[2] );
    if( !rc )
        rc = read_single_mpi( s_key, "p", &resarr[3] );
    if( !rc )
        rc = read_single_mpi( s_key, "q", &resarr[4] );
    if( !rc )
        rc = read_single_mpi( s_key, "u", &resarr[5] );
    return rc;
}
  

static int
generate_subkey( cdk_keygen_ctx_t hd )
{
    gcry_sexp_t s_params = NULL, s_key;
    size_t n = hd->key[1].len;
    int rc;

    if( !hd )
        return CDK_Inv_Value;
  
    if( is_DSA( hd->key[1].algo) )
        rc = gcry_sexp_build( &s_params, NULL, "(genkey(dsa(nbits %d)))", n );
    else if( is_ELG( hd->key[1].algo) )
        rc = gcry_sexp_build( &s_params, NULL, "(genkey(elg(nbits %d)))", n );
    else if( is_RSA( hd->key[1].algo) )
        rc = gcry_sexp_build( &s_params, NULL, "(genkey(rsa(nbits %d)))", n );
    else
        rc = CDK_Inv_Algo;
    if( !rc )
        rc = gcry_pk_genkey( &s_key, s_params );
    gcry_sexp_release( s_params );
    if( !rc ) {
        if( is_DSA( hd->key[1].algo) )
            rc = read_dsa_key( s_key, hd->key[1].resarr );
        else if( is_ELG( hd->key[1].algo) )
            rc = read_elg_key( s_key, hd->key[1].resarr );
        else if( is_RSA( hd->key[1].algo) )
            rc = read_rsa_key( s_key, hd->key[1].resarr );
    }
    hd->key[1].n = cdk_pk_get_npkey( hd->key[1].algo );
    gcry_sexp_release( s_key );
    return rc;
}
  

/**
 * cdk_keygen_start: kick off the key generation
 * @hd: the keygen object
 *
 **/
cdk_error_t
cdk_keygen_start( cdk_keygen_ctx_t hd )
{
    gcry_sexp_t s_params = NULL, s_key = NULL;
    size_t n;
    int rc = 0;
  
    if( !hd || !hd->user_id )
        return CDK_Inv_Value;
    if( is_ELG( hd->key[0].algo ) )
        return CDK_Inv_Mode;
    if( !hd->key[0].len )
        hd->key[0].len = 1024;
    n = hd->key[0].len;

    if( !hd->sym_prefs )
        cdk_keygen_set_prefs( hd, CDK_PREFTYPE_SYM, NULL, 0 );
    if( !hd->hash_prefs )
        cdk_keygen_set_prefs( hd, CDK_PREFTYPE_HASH, NULL, 0 );
    if( !hd->zip_prefs )
        cdk_keygen_set_prefs( hd, CDK_PREFTYPE_ZIP, NULL, 0 );

    if( is_DSA( hd->key[0].algo ) )
        rc = gcry_sexp_build( &s_params, NULL, "(genkey(dsa(nbits %d)))", n );
    else if( is_RSA( hd->key[0].algo ) )
        rc = gcry_sexp_build( &s_params, NULL, "(genkey(rsa(nbits %d)))", n );
    else
        rc = CDK_Inv_Algo;
    if( !rc )
        rc = gcry_pk_genkey( &s_key, s_params );
    gcry_sexp_release( s_params );
    if( !rc ) {
        if( is_DSA( hd->key[0].algo ) )
            rc = read_dsa_key( s_key, hd->key[0].resarr );
        else if( is_RSA( hd->key[0].algo ) )
            rc = read_rsa_key( s_key, hd->key[0].resarr );
        hd->key[0].n = cdk_pk_get_npkey( hd->key[0].algo );
    }
    gcry_sexp_release( s_key );
    if( !rc ) {
        if( hd->key[1].algo && hd->key[1].len )
            rc = generate_subkey( hd );
    }
    return rc;
}


static int
gcry_mpi_to_native( cdk_keygen_ctx_t hd, size_t nkey, int type,
                    cdk_pkt_pubkey_t pk, cdk_pkt_seckey_t sk )
{
    gcry_mpi_t * resarr;
    cdk_mpi_t a = NULL;
    size_t nbytes;
    int i = 0, j = 0, nbits;
    int rc = 0;

    if( !hd )
        return CDK_Inv_Value;
    if( !pk && !sk )
        return CDK_Inv_Value;
    if( type < 0 || type > 1 )
        return CDK_Inv_Value;

    resarr = hd->key[type].resarr;
    if( sk )
        i += cdk_pk_get_npkey( sk->pubkey_algo );
    while( j != nkey ) {
        nbits = gcry_mpi_get_nbits( resarr[i] );
        if( pk )
            a = cdk_calloc( 1, sizeof * a + (nbits + 7) / 8 + 2 + 1 );
        else if( sk )
            a = cdk_salloc( sizeof * a + (nbits + 7) / 8 + 2 + 1, 1 );
        a->bits = nbits;
        a->bytes = ( nbits + 7 ) / 8;
        nbytes = a->bytes;
        a->data[0] = nbits >> 8;
        a->data[1] = nbits;
        rc = gcry_mpi_print( GCRYMPI_FMT_USG, a->data+2, nbytes, &nbytes, resarr[i] );
        if( rc )
            break;
        if( pk )
            pk->mpi[j++] = a;
        else if( sk )
            sk->mpi[j++] = a;
        i++;
    }
    return rc;
}

  
static cdk_pkt_pubkey_t
pk_create( cdk_keygen_ctx_t hd, int type )
{
    cdk_pkt_pubkey_t pk;
    int rc = 0, npkey = 0;

    if( type < 0 || type > 1 )
        return NULL;
    pk = cdk_calloc( 1, sizeof * pk );
    if( !pk )
        return NULL;
    pk->version = 4;
    pk->pubkey_algo = hd->key[type].algo;
    pk->timestamp = _cdk_timestamp( );
    if( hd->key[type].expire_date )
        pk->expiredate = pk->timestamp + hd->key[type].expire_date;
    npkey = cdk_pk_get_npkey( pk->pubkey_algo );
    rc = gcry_mpi_to_native( hd, npkey, type, pk, NULL );
    if( rc ) {
        cdk_free( pk );
        pk = NULL;
    }
    return pk;
}


static cdk_pkt_seckey_t
sk_create( cdk_keygen_ctx_t hd, int type )
{
    cdk_pkt_seckey_t sk;
    int nskey, rc = 0;

    if( type < 0 || type > 1 )
        return NULL;
    sk = cdk_calloc( 1, sizeof * sk );
    if( !sk )
        return NULL;
    _cdk_copy_pubkey( &sk->pk, hd->key[type].pk );
    sk->version = 4;
    sk->pubkey_algo = hd->key[type].algo;
    sk->csum = 0;
    sk->is_protected = 0;
    nskey = cdk_pk_get_nskey( sk->pubkey_algo );
    rc = gcry_mpi_to_native( hd, nskey, type, NULL, sk );
    if( rc ) {
        cdk_free( sk );
        sk = NULL;
    }
    return sk;
}


static cdk_pkt_userid_t
uid_create( cdk_keygen_ctx_t hd )
{
    cdk_pkt_userid_t id;

    if( !hd->user_id )
        return NULL;
    id = cdk_calloc( 1, sizeof * id + strlen( hd->user_id ) + 1 );
    if( !id )
        return NULL;
    strcpy( id->name, hd->user_id );
    id->len = strlen( hd->user_id );
    return id;
}


static cdk_pkt_signature_t
sig_subkey_create( cdk_keygen_ctx_t hd )
{
    cdk_md_hd_t md;
    cdk_subpkt_t node;
    cdk_pkt_signature_t sig;
    cdk_pkt_pubkey_t pk = hd->key[0].pk;
    cdk_pkt_pubkey_t sub_pk = hd->key[1].pk;
    cdk_pkt_seckey_t sk = hd->key[0].sk;
    byte buf[4];
    int rc;
  
    sig = cdk_calloc( 1, sizeof * sig );
    if( !sig )
        return NULL;
    _cdk_sig_create( pk, sig );
    sig->sig_class = 0x18;
    sig->digest_algo = CDK_MD_SHA1;

    if( sub_pk->expiredate ) {
        _cdk_u32tobuf( sub_pk->expiredate - sub_pk->timestamp, buf );
        node = cdk_subpkt_new( 4 );
        if( node ) {
            cdk_subpkt_init( node, CDK_SIGSUBPKT_KEY_EXPIRE, buf, 4 );
            cdk_subpkt_add( sig->hashed, node );
        }
    }
  
    md = cdk_md_open( sig->digest_algo, 0 );
    if( !md ) {
        _cdk_free_signature( sig );
        return NULL;
    }
    
    _cdk_hash_pubkey( pk, md, 0 );
    _cdk_hash_pubkey( sub_pk, md, 0 );
    rc = _cdk_sig_complete( sig, sk, md );
    cdk_md_close( md );
    if( rc ) {
        _cdk_free_signature( sig );
        return NULL;
    }
    return sig;
}


static cdk_pkt_signature_t
sig_self_create( cdk_keygen_ctx_t hd )
{
    cdk_md_hd_t md;
    cdk_subpkt_t node;
    cdk_pkt_signature_t sig;
    cdk_pkt_pubkey_t pk = hd->key[0].pk;
    cdk_pkt_userid_t id = hd->id;
    cdk_pkt_seckey_t sk = hd->key[0].sk;
    u32 keyid[2];
    byte buf[8], * p;
    int rc;

    sig = cdk_calloc( 1, sizeof * sig );
    if( !sig )
        return NULL;
    sig->version = 4;
    sig->timestamp = _cdk_timestamp( );
    sig->sig_class = 0x13;
    sig->pubkey_algo = hd->key[0].algo;
    sig->digest_algo = CDK_MD_SHA1;

    _cdk_u32tobuf( sig->timestamp, buf );
    sig->hashed = node = cdk_subpkt_new( 4 );
    if( node )
        cdk_subpkt_init( node, CDK_SIGSUBPKT_SIG_CREATED, buf, 4 );

    p = hd->sym_prefs;
    node = cdk_subpkt_new( hd->sym_len + 1 );
    if( node ) {
        cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_SYM, p, hd->sym_len );
        cdk_subpkt_add( sig->hashed, node );
    }

    p = hd->hash_prefs;
    node = cdk_subpkt_new( hd->hash_len + 1 );
    if( node ) {
        cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_HASH, p, hd->hash_len );
        cdk_subpkt_add( sig->hashed, node );
    }

    p = hd->zip_prefs;
    node = cdk_subpkt_new( hd->zip_len + 1 );
    if( node ) {
        cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_ZIP, p, hd->zip_len );
        cdk_subpkt_add( sig->hashed, node );
    }

    if( hd->mdc_feature ) {
        buf[0] = 0x01;
        node = cdk_subpkt_new( 1 );
        if( node ) {
            cdk_subpkt_init( node, CDK_SIGSUBPKT_FEATURES, buf, 1 );
            cdk_subpkt_add( sig->hashed, node );
        }
    }

    if( hd->ks_no_modify ) {
        buf[0] = 0x80;
        node = cdk_subpkt_new( 1 );
        if( node ) {
            cdk_subpkt_init( node, CDK_SIGSUBPKT_KS_FLAGS, buf, 1 );
            cdk_subpkt_add( sig->hashed, node );
        }
    }

    if( hd->ks_pref_url ) {
        node = cdk_subpkt_new( strlen( hd->ks_pref_url ) + 1 );
        if( node ) {
            cdk_subpkt_init( node, CDK_SIGSUBPKT_PREF_KS,
                             hd->ks_pref_url, strlen( hd->ks_pref_url ) );
            cdk_subpkt_add( sig->hashed, node );
        }
    }
  
    if( pk->expiredate ) {
        node = cdk_subpkt_new( 4 );
        if( node ) {
            _cdk_u32tobuf( pk->expiredate - pk->timestamp, buf );
            cdk_subpkt_init( node, CDK_SIGSUBPKT_KEY_EXPIRE, buf, 4 );
            cdk_subpkt_add( sig->hashed, node );
        }
    }

    sig->unhashed = node = cdk_subpkt_new( 8 );
    if( node ) {
        cdk_pk_get_keyid( pk, keyid );
        _cdk_u32tobuf( keyid[0], buf );
        _cdk_u32tobuf( keyid[1], buf + 4 );
        cdk_subpkt_init( node, CDK_SIGSUBPKT_ISSUER,  buf, 8 );
    }

    md = cdk_md_open( sig->digest_algo, 0 );
    if( !md ) {
        _cdk_free_signature( sig );
        return NULL;
    }

    _cdk_hash_pubkey( pk, md, 0 );
    _cdk_hash_userid( id, sig->version == 4, md );
    rc = _cdk_sig_complete( sig, sk, md );
    cdk_md_close( md );
    if( rc ) {
        _cdk_free_signature( sig );
        return NULL;
    }  
    return sig;
}


/**
 * cdk_keygen_save: save the generated keys to disk
 * @hd: the keygen object
 * @pub: name of the file to store the public key
 * @sec: name of the file to store the secret key
 *
 **/
cdk_error_t
cdk_keygen_save( cdk_keygen_ctx_t hd, const char * pubf, const char * secf )
{
    cdk_stream_t out = NULL;
    CDK_PACKET pkt;
    int rc;

    hd->key[0].pk = pk_create( hd, 0 );
    if( !hd->key[0].pk )
        return CDK_Inv_Packet;
    hd->key[0].sk = sk_create( hd, 0 );
    if( !hd->key[0].sk )
        return CDK_Inv_Packet;
    hd->id = uid_create( hd );
    if( !hd->id )
        return CDK_Inv_Packet;
    hd->sig = sig_self_create( hd );
    if( !hd->sig )
        return CDK_Inv_Packet;

    rc = cdk_stream_create( pubf, &out );
    if( rc )
        return rc;
  
    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_PUBLIC_KEY;
    pkt.pkt.public_key = hd->key[0].pk;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;
  
    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_USER_ID;
    pkt.pkt.user_id = hd->id;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;

    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_SIGNATURE;
    pkt.pkt.signature = hd->sig;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;

    if( hd->key[1].algo ) {
        cdk_pkt_init( &pkt );
        pkt.pkttype = CDK_PKT_PUBLIC_SUBKEY;
        pkt.pkt.public_key = hd->key[1].pk = pk_create( hd, 1 );
        rc = cdk_pkt_write( out, &pkt );
        if( rc )
            goto fail;

        cdk_pkt_init( &pkt );
        pkt.pkttype = CDK_PKT_SIGNATURE;
        pkt.pkt.signature = sig_subkey_create( hd );
        rc = cdk_pkt_write( out, &pkt );
        cdk_pkt_free( &pkt );
        if( rc )
            goto fail;
    }
  
    cdk_stream_close( out );
    out = NULL;

    rc = cdk_stream_create( secf, &out );
    if( rc )
        goto fail;

    if( hd->protect ) {
        rc = cdk_sk_protect( hd->key[0].sk, hd->pass );
        if( rc )
            goto fail;
    }

    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_SECRET_KEY;
    pkt.pkt.secret_key = hd->key[0].sk;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;

    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_USER_ID;
    pkt.pkt.user_id = hd->id;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;

    cdk_pkt_init( &pkt );
    pkt.pkttype = CDK_PKT_SIGNATURE;
    pkt.pkt.signature = hd->sig;
    rc = cdk_pkt_write( out, &pkt );
    if( rc )
        goto fail;

    if( hd->key[1].algo ) {
        hd->key[1].sk = sk_create( hd, 1 );
        if( hd->protect && (rc = cdk_sk_protect( hd->key[1].sk, hd->pass )) )
            goto fail;
        cdk_pkt_init( &pkt );
        pkt.pkttype = CDK_PKT_SECRET_SUBKEY;
        pkt.pkt.secret_key = hd->key[1].sk;
        rc = cdk_pkt_write( out, &pkt );
        if( rc )
            goto fail;
    }

 fail:
    cdk_stream_close( out );
    return rc;
}


/**
 * cdk_keygen_free: free the keygen object
 * @hd: the keygen object
 *
 **/
void
cdk_keygen_free( cdk_keygen_ctx_t hd )
{
    if( hd ) {
        _cdk_free_pubkey( hd->key[0].pk );
        _cdk_free_pubkey( hd->key[1].pk );
        _cdk_free_seckey( hd->key[0].sk );
        _cdk_free_seckey( hd->key[1].sk );
        _cdk_free_userid( hd->id );
        _cdk_free_signature( hd->sig );
        cdk_free( hd->sym_prefs );
        cdk_free( hd->hash_prefs );
        cdk_free( hd->zip_prefs );
        _cdk_sec_free( hd->pass, hd->pass_len );
        _cdk_free_mpibuf( hd->key[0].n, hd->key[0].resarr );
        _cdk_free_mpibuf( hd->key[1].n, hd->key[1].resarr );
        cdk_free( hd );
    }
}


/**
 * cdk_keygen_new:
 * @r_hd: the new object
 *
 **/
cdk_error_t
cdk_keygen_new( cdk_keygen_ctx_t * r_hd )
{
    cdk_keygen_ctx_t hd;

    if( !r_hd )
        return CDK_Inv_Value;
    hd = cdk_calloc( 1, sizeof * hd );
    if( !hd )
        return CDK_Out_Of_Core;
    *r_hd = hd;
    return 0;
}
