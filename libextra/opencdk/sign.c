/* -*- Mode: C; c-file-style: "bsd" -*-
 * sign.c - Signing routines
 *        Copyright (C) 2006 Free Software Foundation, Inc.
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
#include <time.h>
#include <string.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "filters.h"
#include "stream.h"


static int file_clearsign( cdk_ctx_t, cdk_strlist_t,
                           const char *, const char * );
static int stream_clearsign( cdk_ctx_t, cdk_stream_t,
                             cdk_stream_t, cdk_strlist_t );


static void
calc_subpkt_size( cdk_pkt_signature_t sig )
{
    size_t nbytes;
  
    if( sig->hashed ) {
        _cdk_subpkt_get_array( sig->hashed, 1, &nbytes );
        sig->hashed_size = nbytes;
    }
    if( sig->unhashed ) {
        _cdk_subpkt_get_array( sig->unhashed, 1, &nbytes );
        sig->unhashed_size = nbytes;
    }
}


int
_cdk_sig_hash_for( int pkalgo, int pktver )
{
    if( is_DSA( pkalgo ) )
        return CDK_MD_SHA1;
    else if( is_RSA( pkalgo ) && pktver < 4 )
        return CDK_MD_MD5;
    return CDK_MD_SHA1; /* default message digest */
}


int
_cdk_sig_create( cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig )
{
    cdk_subpkt_t node;
    byte buf[8];

    if( !sig )
        return CDK_Inv_Value;

    if( pk ) {
        if( !sig->version )
            sig->version = pk->version;
        sig->pubkey_algo = pk->pubkey_algo;
        sig->digest_algo = _cdk_sig_hash_for( pk->pubkey_algo, pk->version );
        cdk_pk_get_keyid( pk, sig->keyid );
    }
    sig->timestamp = _cdk_timestamp( );
    if( sig->version == 3 )
        return 0;
  
    sig->hashed = sig->unhashed = NULL;

    _cdk_u32tobuf( sig->keyid[0], buf );
    _cdk_u32tobuf( sig->keyid[1], buf + 4 );
    node = cdk_subpkt_new( 8 );
    if( node )
        cdk_subpkt_init( node, CDK_SIGSUBPKT_ISSUER, buf, 8 );
    sig->unhashed = node;
  
    _cdk_u32tobuf( sig->timestamp, buf );
    node = cdk_subpkt_new( 4 );
    if( node ) {
        cdk_subpkt_init( node, CDK_SIGSUBPKT_SIG_CREATED, buf, 4 );
        sig->hashed = node;
    }
  
    if( sig->expiredate ) {
        u32 u = sig->expiredate - sig->timestamp;
        _cdk_u32tobuf( u, buf );
        node = cdk_subpkt_new( 4 );
        if( node ) {
            cdk_subpkt_init( node, CDK_SIGSUBPKT_SIG_EXPIRE, buf, 4 );
            cdk_subpkt_add( sig->hashed, node );
        }
    }
    calc_subpkt_size( sig );
    return 0;
}


int
_cdk_sig_complete( cdk_pkt_signature_t sig, cdk_pkt_seckey_t sk,
                   cdk_md_hd_t md )
{
    byte digest[24];

    if( !sig || !sk || !md )
        return CDK_Inv_Value;
  
    calc_subpkt_size( sig );
    _cdk_hash_sig_data( sig, md );
    cdk_md_final( md );
    memcpy( digest, cdk_md_read( md, sig->digest_algo),
            cdk_md_get_algo_dlen( sig->digest_algo ) );
    return cdk_pk_sign( sk, sig, digest );
}


static int
write_literal( cdk_stream_t inp, cdk_stream_t out )
{
    cdk_packet_t pkt;
    cdk_pkt_literal_t pt;
    const char * s = _cdk_stream_get_fname( inp );
    int rc;

    if( !inp || !out )
        return CDK_Inv_Value;

    pkt = cdk_calloc( 1, sizeof *pkt );
    if( !pkt )
        return CDK_Out_Of_Core;
    cdk_stream_seek( inp, 0 );
    if( !s )
        s = "_CONSOLE";
    pt = cdk_calloc( 1, sizeof *pt + strlen( s ) + 1 );
    if( !pt )
        return CDK_Out_Of_Core;
    pt->len = cdk_stream_get_length( inp );
    pt->mode = 'b';
    pt->timestamp = _cdk_timestamp(  );
    pt->namelen = strlen( s );
    pt->buf = inp;
    strcpy( pt->name, s );
    pkt->pkttype = CDK_PKT_LITERAL;
    pkt->pkt.literal = pt;
    rc = cdk_pkt_write( out, pkt );
    cdk_free( pt );
    cdk_free( pkt );
    return rc;
}


static int
write_pubkey_enc_list( cdk_ctx_t hd, cdk_stream_t out, cdk_strlist_t remusr )
{
    cdk_keylist_t pkl;
    int rc;

    if( !hd || !out )
        return CDK_Inv_Value;
  
    rc = cdk_pklist_build( &pkl, hd->db.pub, remusr, PK_USAGE_ENCR );
    if( rc )
        return rc;

    cdk_dek_free( hd->dek );
    rc = cdk_dek_new( &hd->dek );
    if( !rc )
        rc = cdk_dek_set_cipher( hd->dek, cdk_pklist_select_algo( pkl, 1 ) );
    if( !rc )
        rc = cdk_dek_set_key( hd->dek, NULL, 0 );
    if( !rc ) {
        cdk_dek_set_mdc_flag( hd->dek, cdk_pklist_use_mdc( pkl ) );
        rc = cdk_pklist_encrypt( pkl, hd->dek, out );
    }
    cdk_pklist_release( pkl );
    return rc;
}


static int
sig_get_version( cdk_ctx_t hd, cdk_keylist_t kl )
{
    cdk_keylist_t l;

    if( hd && hd->opt.compat )
        return 3;
  
    for( l = kl; l; l = l->next ) {
        if( (l->type == CDK_PKT_PUBLIC_KEY && l->key.pk->version == 3)
            || (l->type == CDK_PKT_SECRET_KEY && l->key.sk->version == 3))
            return 3;
    }
    return 4;
}


/**
 * cdk_stream_sign:
 * @hd: session handle
 * @inp: input stream
 * @out: output stream
 * @locusr: local user list for signing
 * @remusr: remote user list for encrypting
 * @encryptflag: shall the output be encrypted? (1/0)
 * @sigmode: signature mode
 *
 * Sign the data from the STREAM @inp.
 **/
cdk_error_t
cdk_stream_sign( cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out,
                 cdk_strlist_t locusr, cdk_strlist_t remusr,
                 int encryptflag, int sigmode )
{
    cdk_keylist_t list;
    cdk_pkt_seckey_t sk;
    md_filter_t * mfx;
    int sigver, digest_algo;
    int rc, detached = sigmode == CDK_SIGMODE_DETACHED;

    if( !hd )
        return CDK_Inv_Value;
    if( detached && encryptflag )
        return CDK_Inv_Mode;
    
    if( sigmode == CDK_SIGMODE_CLEAR )
        return stream_clearsign( hd, inp, out, locusr );
    
    rc = cdk_sklist_build( &list, hd->db.sec, hd, locusr, 1, PK_USAGE_SIGN );
    if( rc )
        return rc;

    sk = list->key.sk;
    digest_algo = _cdk_sig_hash_for( sk->pubkey_algo, sk->version );
    if( cdk_handle_control( hd, CDK_CTLF_GET, CDK_CTL_FORCE_DIGEST ) )
        digest_algo = hd->digest_algo;

    if( hd->opt.armor )
        cdk_stream_set_armor_flag( out, detached? CDK_ARMOR_SIGNATURE : 0 );
  
    if( encryptflag ) {
        cdk_stream_set_cache( out, 1 );
        rc = write_pubkey_enc_list( hd, out, remusr );
        if( rc ) {
            cdk_sklist_release( list );
            return rc;
        }
        cdk_stream_set_cipher_flag( out, hd->dek, hd->dek->use_mdc );
        cdk_stream_set_cache( out, 0 );
    }
  
    cdk_stream_set_hash_flag( inp, digest_algo );
    /* kick off the filter */
    sigver = sig_get_version( hd, list );
    cdk_stream_read( inp, NULL, 0 );
    mfx = _cdk_stream_get_opaque( inp, fHASH );
    if( mfx && mfx->md ) {
        if( sigver == 3 ) {
            rc = cdk_sklist_write( list, out, mfx->md, 0x00, 0x03 );
            if( !rc && !detached )
                rc = write_literal( inp, out );
        }
        else {
            if( !detached ) {
                rc = cdk_sklist_write_onepass( list, out, 0x00, digest_algo );
                if( !rc )
                    rc = write_literal( inp, out );
            }
            if( !rc )
                rc = cdk_sklist_write( list, out, mfx->md, 0x00, 0x04 );
        }
    }
    cdk_sklist_release( list );
    return rc;
}


/**
 * cdk_file_sign:
 * @locusr: List of userid which should be used for signing
 * @remusr: If encrypt is valid, the list of recipients
 * @file: Name of the input file
 * @output: Name of the output file
 * @sigmode: Signature mode
 * @encryptflag: enable sign and encrypt
 *
 * Sign a file.
 **/
cdk_error_t
cdk_file_sign( cdk_ctx_t hd, cdk_strlist_t locusr, cdk_strlist_t remusr,
               const char * file, const char * output,
               int sigmode, int encryptflag )
{
    cdk_stream_t inp = NULL, out = NULL;
    int rc = 0;

    if( !file || !output )
        return CDK_Inv_Value;
    if( encryptflag && !remusr )
        return CDK_Inv_Value;
    if( (sigmode != CDK_SIGMODE_NORMAL) && encryptflag )
        return CDK_Inv_Mode;
    if( !remusr && !locusr )
        return CDK_Inv_Value;
    if( sigmode == CDK_SIGMODE_CLEAR )
        return file_clearsign( hd, locusr, file, output );

    rc = cdk_stream_open( file, &inp );
    if( rc )
        return rc;

    if( hd->opt.armor || encryptflag )
        rc = cdk_stream_new( output, &out );
    else
        rc = cdk_stream_create( output, &out );
    if( rc ) {
        cdk_stream_close( inp );
        return rc;
    }
    rc = cdk_stream_sign( hd, inp, out, locusr, remusr, encryptflag, sigmode );
    
    cdk_stream_close( inp );
    cdk_stream_close( out );
    return rc;
}


static void
put_hash_line( cdk_stream_t out, int digest_algo, int is_v4 )
{
    const char * s = NULL;

    if( !is_v4 ) {
        cdk_stream_putc( out, '\n' );
        return;
    }

    switch( digest_algo ) {
    case CDK_MD_MD2    : s = "Hash: MD2\n\n"; break;
    case CDK_MD_MD5    : s = "Hash: MD5\n\n"; break;
    case CDK_MD_SHA1   : s = "Hash: SHA1\n\n"; break;
    case CDK_MD_RMD160 : s = "Hash: RIPEMD160\n\n"; break;
    case CDK_MD_SHA256 : s = "Hash: SHA256\n\n"; break;
    default            : s = "Hash: SHA1\n\n"; break;
    }
    _cdk_stream_puts( out, s );
}


void
_cdk_trim_string( char * s, int canon )
{
    while( s && *s &&(  s[strlen( s )-1] == '\t'
                        || s[strlen( s )-1] == '\r'
                        || s[strlen( s )-1] == '\n'
                        || s[strlen( s )-1] == ' '))
        s[strlen( s ) -1] = '\0';
    if( canon )
        strcat( s, "\r\n" );
}


static int
stream_clearsign( cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out,
                  cdk_strlist_t locusr )
{
    cdk_md_hd_t md = NULL;
    cdk_keylist_t list;
    cdk_stream_t tmp;
    cdk_pkt_seckey_t sk;
    const char * s;
    char buf[1024+2];
    int digest_algo, sigver;
    int rc, nread;
    
    rc = cdk_sklist_build( &list, hd->db.sec, hd, locusr, 1, PK_USAGE_SIGN );
    if( rc )
        return rc;

    sk = list->key.sk;
    digest_algo = _cdk_sig_hash_for( sk->pubkey_algo, sk->version );
    md = cdk_md_open( digest_algo, 0 );
    if( !md ) {
        cdk_sklist_release( list );
        return CDK_Gcry_Error;
    }

    s = _cdk_armor_get_lineend( );
    strcpy( buf, "-----BEGIN PGP SIGNED MESSAGE-----" );
    strcat( buf, s );
    _cdk_stream_puts( out, buf );
    put_hash_line( out, digest_algo, sk->version == 4 );
  
    while( !cdk_stream_eof( inp ) ) {
        nread = _cdk_stream_gets( inp, buf, sizeof buf-1 );
        if( !nread )
            break;
        _cdk_trim_string( buf, 1 );
        cdk_md_write( md, buf, strlen( buf ) );
        if( buf[0] == '-' ) {
            memmove( &buf[2], buf, nread + 1 );
            buf[1] = ' ';
        }
        if( strlen( s ) == 1 ) {
            buf[strlen( buf ) - 1] = '\0';
            buf[strlen( buf ) - 1] = '\n';
        }
        _cdk_stream_puts( out, buf );
    }
    _cdk_stream_puts( out, s );
    tmp = cdk_stream_tmp( );
    if( !tmp ) {
        rc = CDK_Out_Of_Core;
        goto leave;
    }
    cdk_stream_tmp_set_mode( tmp, 1 );
    cdk_stream_set_armor_flag( tmp, CDK_ARMOR_SIGNATURE );

    sigver = sig_get_version( hd, list );
    rc = cdk_sklist_write( list, tmp, md, 0x01, sigver );
    if( rc ) {
        cdk_stream_close( tmp );
        goto leave;
    }
  
    rc = cdk_stream_flush( tmp );
    if( rc )
        goto leave;
  
    while( !cdk_stream_eof( tmp ) ) {
        nread = cdk_stream_read( tmp, buf, sizeof buf-1 );
        if( !nread )
            break;
        cdk_stream_write( out, buf, nread );
    }
    cdk_stream_close( tmp );
  
 leave:
    cdk_md_close( md );
    cdk_sklist_release( list );
    return rc;
}


static int
file_clearsign( cdk_ctx_t hd, cdk_strlist_t locusr,
                const char * file, const char * output )
{
    cdk_stream_t inp = NULL, out = NULL;
    int rc;
  
    if( !locusr || !file || !output )
        return CDK_Inv_Value;
    if( !hd->opt.overwrite && _cdk_check_file( output ) )
        return CDK_Inv_Mode;

    rc = cdk_stream_open( file, &inp );
    if( rc )
        return rc;
  
    rc = cdk_stream_create( output, &out );
    if( rc ) {
        cdk_stream_close( inp );
        return rc;
    }

    rc = stream_clearsign( hd, inp, out, locusr );
    
    cdk_stream_close( inp );
    cdk_stream_close( out );
    
    return rc;
}

