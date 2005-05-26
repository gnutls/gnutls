/* -*- Mode: C; c-file-style: "bsd" -*-
 * encrypt.c
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "stream.h"
#include "packet.h"


struct mainproc_ctx_s {
    cdk_dek_t dek;
    cdk_stream_t s;
    cdk_kbnode_t node;
    cdk_stream_t tmpfp;
    struct {
        unsigned present:1;
        unsigned one_pass:1;
        cdk_md_hd_t md;
        int digest_algo;
        int is_expired;
        cdk_pkt_pubkey_t pk;
        unsigned pt_offset;
    } sig;
    unsigned eof_seen:1;
    unsigned key_seen:1;
    char * file; /* for detached signatures */
    const char * output;
};
typedef struct mainproc_ctx_s * CTX;


static void
write_marker_packet( cdk_stream_t out )
{
    byte buf[5];

    buf[0] = (0x80 | (10<<2));
    buf[1] = 3;
    buf[2] = 0x50;
    buf[3] = 0x47;
    buf[4] = 0x50;
    cdk_stream_write( out, buf, 5 );
}


static void
literal_set_rfc1991( cdk_stream_t out )
{
    literal_filter_t * pfx;
    pfx = _cdk_stream_get_opaque( out, fLITERAL );
    if( pfx )
        pfx->rfc1991 = 1;
}


static int
sym_stream_encrypt (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out)
{
    cdk_packet_t pkt = NULL;
    cdk_pkt_symkey_enc_t enc;
    char * pw = NULL;
    int rc = 0;

    if( !hd || !inp || !out )
        return CDK_Inv_Value;

    pw = _cdk_passphrase_get( hd, "Enter Passphrase: " );
    if( !pw )
        goto fail;

    cdk_free( hd->s2k );
    rc = cdk_s2k_new( &hd->s2k, hd->_s2k.mode, hd->_s2k.digest_algo, NULL );
    if( rc )
        goto fail;
    
    cdk_dek_free( hd->dek );
    rc = cdk_dek_from_passphrase( &hd->dek, hd->cipher_algo, hd->s2k, 2, pw );
    if( rc )
        goto fail;

    if( hd->opt.rfc1991 ) {
        hd->dek->rfc1991 = 1;
        goto start; /* skip the pkt_symkey_enc packet. */
    }
  
    cdk_stream_set_cache( out, 1 );
    if( hd->opt.compat )
        write_marker_packet( out );
      
    enc = cdk_calloc( 1, sizeof *enc );
    if( !enc ) {
        rc = CDK_Out_Of_Core;
        goto fail;
    }
    pkt = cdk_calloc( 1, sizeof * pkt );
    if( !pkt ) {
        rc = CDK_Out_Of_Core;
        goto fail;
    }
    enc->version = 4;
    enc->cipher_algo = hd->dek->algo;
    enc->s2k = hd->s2k;
    pkt->pkttype = CDK_PKT_SYMKEY_ENC;
    pkt->pkt.symkey_enc = enc;
    rc = cdk_pkt_write( out, pkt );
    cdk_free( enc );
    if( rc )
        goto fail;
    cdk_stream_set_cache( out, 0 );

 start:
    if( hd->opt.armor )
        cdk_stream_set_armor_flag( out, 0 );
    cdk_stream_set_cipher_flag( out, hd->dek, hd->opt.mdc );
    if( hd->opt.compress )
        cdk_stream_set_compress_flag( out, hd->compress.algo,
                                      hd->compress.level );
    cdk_stream_set_literal_flag( out, 0, _cdk_stream_get_fname( inp ) );
    if( hd->opt.rfc1991 )
        literal_set_rfc1991( out );
    rc = cdk_stream_kick_off( inp, out );

fail:
    _cdk_passphrase_free( pw, pw? strlen( pw ) : 0 );
    cdk_free( pkt );
    return rc;
}


static int
use_rfc1991_format( cdk_ctx_t hd, cdk_keylist_t kl )
{
    cdk_keylist_t l;
  
    if( hd->opt.rfc1991 )
        return 1;
    for( l = kl; l; l = l->next ) {
        if( l->type == CDK_PKT_PUBLIC_KEY && l->key.pk->version == 3 )
            return 1;
    }
    return 0;
}


static int
select_cipher_algo( int rfc1991, cdk_keylist_t kl )
{
    int pgp2 = _cdk_is_idea_available( );
    int def_cipher = pgp2 && rfc1991? CDK_CIPHER_IDEA : CDK_CIPHER_CAST5;
    return rfc1991?def_cipher : cdk_pklist_select_algo( kl, CDK_PREFTYPE_SYM );
} 


int
_cdk_check_args( int overwrite, const char * in, const char * out )
{
    if( !in || !out )
        return CDK_Inv_Value;
    if( !_cdk_strcmp( in, out ) )
        return CDK_Inv_Mode;
    if( !overwrite && !_cdk_check_file( out ) )
        return CDK_Inv_Mode;
    return 0;
}


/**
 * cdk_stream_encrypt: Encrypt a stream.
 * @hd: Handle
 * @remusr: List of recipients
 * @inp: Input stream handle
 * @out: Output stream handle
 *
 * If remusr is NULL, then symmetric encryption is used. Via the
 * handle the caller can set or unset multiple options.
 */
cdk_error_t
cdk_stream_encrypt( cdk_ctx_t hd, cdk_strlist_t remusr,
                    cdk_stream_t inp, cdk_stream_t out )
{
    cdk_keylist_t pkl = NULL;
    int cipher_algo, compress_algo = 0;
    int use_rfc1991 = 0;
    int rc = 0;

    if( !hd || !inp || !out )
        return CDK_Inv_Value;

    if( !remusr )
        return sym_stream_encrypt( hd, inp, out );

    rc = cdk_pklist_build( &pkl, hd->db.pub, remusr, PK_USAGE_ENCR );
    if( rc )
        return rc;

    use_rfc1991 = use_rfc1991_format( hd, pkl );
    cipher_algo = select_cipher_algo( use_rfc1991, pkl );
    cdk_dek_free( hd->dek );
    rc = cdk_dek_new( &hd->dek );
    if( !rc )
        rc = cdk_dek_set_cipher( hd->dek, cipher_algo );
    if( !rc )
        rc = cdk_dek_set_key( hd->dek, NULL, 0 );
    if( rc ) {
        cdk_pklist_release( pkl );
        return rc;
    }
    compress_algo = use_rfc1991? CDK_COMPRESS_ZIP: hd->compress.algo;

    if( !hd->opt.rfc1991 && !hd->opt.compat )
        cdk_dek_set_mdc_flag( hd->dek, cdk_pklist_use_mdc( pkl ) );
    hd->dek->rfc1991 = use_rfc1991;

    cdk_stream_set_cache( out, 1 );
    if( hd->opt.compat && !hd->opt.rfc1991 )
        write_marker_packet( out );
    
    rc = cdk_pklist_encrypt( pkl, hd->dek, out );
    cdk_pklist_release( pkl );
    if( rc )
        return rc;

    cdk_stream_set_cache( out, 0 );

    if( hd->opt.armor )
        cdk_stream_set_armor_flag( out, 0 );
    cdk_stream_set_cipher_flag( out, hd->dek, 0 );
    if( hd->opt.compress )
        cdk_stream_set_compress_flag( out, compress_algo, hd->compress.level );
    cdk_stream_set_literal_flag( out, 0, _cdk_stream_get_fname( inp ) );
    if( hd->dek->rfc1991 )
        literal_set_rfc1991( out );

    return cdk_stream_kick_off( inp, out );
}


/**
 * cdk_file_encrypt: Encrypt a file.
 * @hd: Handle
 * @remusr: List of recipient
 * @file: Input file
 * @output: Output file
 *
 **/
cdk_error_t
cdk_file_encrypt (cdk_ctx_t hd, cdk_strlist_t remusr,
                  const char * file, const char * output)
{
    cdk_stream_t inp = NULL, out = NULL;
    int rc;

    rc = _cdk_check_args( hd->opt.overwrite, file, output );
    if( !rc )
        rc = cdk_stream_open( file, &inp );
    if( !rc )
        rc = cdk_stream_new( output, &out );
    if( !rc )
        rc = cdk_stream_encrypt( hd, remusr, inp, out );
    cdk_stream_close( inp );
    cdk_stream_close( out );
    return rc;
}


static void
write_status (cdk_ctx_t hd, int type, const char * fmt, ...)
{
    va_list arg_ptr;
    char * buf;
    int n;
  
    if (!hd->callback)
        return;

    va_start (arg_ptr, fmt);
    n = _cdk_vasprintf (&buf, fmt, arg_ptr);
    buf[n] = '\0';
    hd->callback (hd->callback_value, type, buf);
    _cdk_vasprintf_free (buf);
    va_end (arg_ptr);
}


static int
is_openpgp_ext (const char * file)
{
    return (strstr (file, ".asc") || strstr (file, ".sig")
            || strstr (file, ".gpg") || strstr (file, ".pgp")) ? 1 : 0;
}
  

static int
hash_data_file( char * file, int digest_algo, cdk_md_hd_t * r_md )
{
    md_filter_t * mfx;
    cdk_stream_t s;
    int rc;

    if( file && is_openpgp_ext( file ) )
        file[strlen( file ) - 4] = '\0';
    else
        return CDK_General_Error;

    rc = cdk_stream_open( file, &s );
    if( rc )
        return rc;
  
    cdk_stream_set_hash_flag( s, digest_algo );
    cdk_stream_read( s, NULL, 0 );
    mfx = _cdk_stream_get_opaque( s, fHASH );
    if( mfx && mfx->md )
        *r_md = cdk_md_copy( mfx->md );
    cdk_stream_close( s );
    return 0;
}


static int
handle_symkey_enc (CTX c, cdk_ctx_t hd, cdk_packet_t pkt)
{
    cdk_pkt_symkey_enc_t key;
    char * pw = NULL;
    int rc = 0;

    assert (pkt->pkttype == CDK_PKT_SYMKEY_ENC);

    c->key_seen = 1;
    if (c->dek)
        return 0; /* we already decrypted the session key */
  
    pw = _cdk_passphrase_get( hd, "Enter Passphrase: " );
    if( !pw )
        return CDK_Out_Of_Core;

    key = pkt->pkt.symkey_enc;
    rc = cdk_dek_from_passphrase( &c->dek, key->cipher_algo, key->s2k, 0, pw );
    _cdk_passphrase_free( pw, pw? strlen( pw ) : 0 );
    return rc;
}


static int
get_seckey( cdk_ctx_t hd, cdk_keydb_hd_t db, u32 * keyid,
            cdk_pkt_seckey_t*r_sk )
{
    int rc;

    if( !r_sk )
        return CDK_Inv_Value;
    if( hd->cache.on && hd->cache.sk ) {
        cdk_pkt_seckey_t sk = hd->cache.sk;
        cdk_sk_get_keyid( sk, NULL );
        if( sk->keyid[0] == keyid[0] && sk->keyid[1] == keyid[1] ) {
            *r_sk = sk;
            return 0;
        }
    }
    rc = cdk_keydb_get_sk( db, keyid, r_sk );
    if( hd->cache.on )
        hd->cache.sk = *r_sk;
    return rc;
}
    

static int
handle_pubkey_enc( CTX c, cdk_ctx_t hd, cdk_packet_t pkt )
{
    cdk_pkt_pubkey_enc_t enc;
    cdk_pkt_seckey_t sk = NULL;
    int rc = 0;

    assert( pkt->pkttype == CDK_PKT_PUBKEY_ENC );

    c->key_seen = 1;
    enc = pkt->pkt.pubkey_enc;
    write_status( hd, CDK_CB_PUBKEY_ENC, "%08lX%08lX %d %d",
                  enc->keyid[0], enc->keyid[1], enc->pubkey_algo,
                  (enc->mpi[0]->bits+7)/8*8 );
  
    if( c->dek )
        return 0; /* we already decrypted the session key */

    /* we checked before that there is at least one secret key so we
       skip this packet and continue without errors */
    if( cdk_keydb_check_sk( hd->db.sec, enc->keyid ) )
        return 0;
    rc = get_seckey( hd, hd->db.sec, enc->keyid, &sk );
    if( !rc )
        rc = cdk_dek_extract( &c->dek, hd, enc, sk );
    if( !hd->cache.on )
        _cdk_free_seckey( sk );
    return rc;
}


static int
rfc1991_get_sesskey (cdk_dek_t * r_dek, cdk_ctx_t hd)
{
    cdk_s2k_t s2k;
    char * pw;
    int rc;

    if (!r_dek)
        return CDK_Inv_Value;
  
    pw = _cdk_passphrase_get (hd, "Enter Passphrase: ");
    if (!pw)
        return CDK_Out_Of_Core;
    rc = cdk_s2k_new( &s2k, 0, CDK_MD_MD5, NULL );
    if( rc ) {
        _cdk_passphrase_free( pw, pw? strlen( pw ) : 0 );
        return CDK_Out_Of_Core;
    }
    rc = cdk_dek_from_passphrase( r_dek, CDK_CIPHER_IDEA, s2k, 0, pw );
    _cdk_passphrase_free( pw, pw? strlen( pw ) : 0 );
    cdk_free( s2k );
    return rc;
}

  
static int
handle_encrypted (CTX c, cdk_ctx_t hd, cdk_packet_t pkt, int use_mdc)
{
    cdk_pkt_encrypted_t enc;
    int pgp2_compat = _cdk_is_idea_available ();
    int rc = 0, pkttype = pkt->pkttype;

    assert (CDK_PKT_IS_ENCRYPTED (pkttype));

    if (!c->dek) {
        if (!pgp2_compat)
            return CDK_Error_No_Key;
        else if (!c->key_seen) {
            _cdk_log_debug ("RFC1991 message was detected.\n");
            rc = rfc1991_get_sesskey (&c->dek, hd);
            if (rc)
                return rc;
        }
        else
            return CDK_Error_No_Key;
    }
  
    enc = pkt->pkt.encrypted;
    cdk_stream_set_cipher_flag (enc->buf, c->dek, use_mdc);
    rc = cdk_stream_read (enc->buf, NULL, 0);
    if (!rc)
        c->s = enc->buf;
    else
        rc = _cdk_stream_get_errno (enc->buf);
    return rc;
}


static int
handle_compressed( CTX c, cdk_packet_t pkt )
{
    cdk_pkt_compressed_t zip;
    int rc;

    assert( pkt->pkttype == CDK_PKT_COMPRESSED );
  
    zip = pkt->pkt.compressed;
    cdk_stream_set_compress_flag( c->s, zip->algorithm, 0 );
    rc = cdk_stream_read( c->s, NULL, 0 );
    if( rc )
        rc = _cdk_stream_get_errno( c->s );
    return rc;
}


static int
handle_onepass_sig( CTX c, cdk_packet_t pkt )
{
    int rc = 0;
    
    assert (pkt->pkttype == CDK_PKT_ONEPASS_SIG);

    if( c->sig.md )
        return 0; /* already open */       
    c->sig.digest_algo = pkt->pkt.onepass_sig->digest_algo;
    if( cdk_md_test_algo( c->sig.digest_algo ) )
        return CDK_Inv_Algo;
    c->sig.md = cdk_md_open( c->sig.digest_algo, 0 );
    if( !c->sig.md )
        rc = CDK_Gcry_Error;
    return rc;
}


static int
handle_literal( CTX c, cdk_packet_t pkt, cdk_stream_t * ret_out )
{
    literal_filter_t * pfx;
    cdk_pkt_literal_t pt;
    cdk_stream_t out;
    const char * s;
    int rc = 0;

    assert( pkt->pkttype == CDK_PKT_LITERAL );

    if( !ret_out )
        return CDK_Inv_Value;

    if( !c->tmpfp ) {
        /* fixme: handle _CONSOLE */
        s = c->output? c->output : pkt->pkt.literal->name;
        rc = cdk_stream_create( s, ret_out );
        if( rc )
            return rc;
    }
    else
        *ret_out = c->tmpfp;
    out = *ret_out;
    pt = pkt->pkt.literal;
    cdk_stream_seek( c->s, c->sig.present? c->sig.pt_offset : 0 );
    cdk_stream_set_literal_flag( c->s, 0, NULL );
    if( c->sig.present ) {
        _cdk_log_debug( "enable hash filter (algo=%d)\n", c->sig.digest_algo );
        pfx = _cdk_stream_get_opaque( c->s, fLITERAL );
        if( pfx )
            pfx->md = c->sig.md;
    }
    return cdk_stream_kick_off( c->s, out );
}


static byte *
mpi_encode( cdk_pkt_signature_t sig )
{
    cdk_mpi_t a;
    byte * p;
    size_t len, i, nsig = 0, pos = 0;
    
    nsig = cdk_pk_get_nsig( sig->pubkey_algo );
    for( i = 0, len = 0; i < nsig; i++ )
        len += sig->mpi[i]->bytes + 2;
    p = cdk_calloc( 1, len + 1 );
    if( !p )
        return NULL;
    for( i = 0; i < nsig; i++ ) {
        a = sig->mpi[i];
        p[pos++] = a->bits >> 8;
        p[pos++] = a->bits;
        memcpy( p + pos, a->data, a->bytes );
        pos += a->bytes;
    }
    return p;
}


static void
store_verify_result( cdk_pkt_signature_t sig, _cdk_verify_result_t res )
{
    res->sig_len = sig->mpi[0]->bits;
    res->sig_ver = sig->version;
    res->keyid[0] = sig->keyid[0];
    res->keyid[1] = sig->keyid[1];
    res->created = sig->timestamp;
    res->pubkey_algo = sig->pubkey_algo;
    res->digest_algo = sig->digest_algo;
    if( sig->flags.expired )
        res->sig_flags |= CDK_FLAG_SIG_EXPIRED;
    res->sig_data = mpi_encode( sig );
}

    
static int
handle_signature (cdk_ctx_t hd, CTX c, cdk_packet_t pkt)
{
    _cdk_verify_result_t res;
    cdk_pkt_signature_t sig;
    u32 keyid[2];
    int rc;

    assert( pkt->pkttype == CDK_PKT_SIGNATURE );

    if( !c->sig.present )
        return CDK_Inv_Packet;

    _cdk_result_verify_free( hd->result.verify );
    res = hd->result.verify = _cdk_result_verify_new( );
    if( !hd->result.verify )
        return CDK_Out_Of_Core;
  
    sig = pkt->pkt.signature;
    if( !c->sig.one_pass && !c->sig.md ) {
        if( cdk_md_test_algo( sig->digest_algo ) )
            return CDK_Inv_Algo;
        rc = hash_data_file( c->file, sig->digest_algo, &c->sig.md );
        if( rc )
            return rc;
    }

    cdk_sig_get_keyid( sig, keyid );
    store_verify_result( sig, res );
  
    rc = cdk_keydb_get_pk( hd->db.pub, keyid, &c->sig.pk );
    if( rc ) {
        res->sig_status = CDK_SIGSTAT_NOKEY;
        return rc;
    }
    if( c->sig.pk->is_revoked )
        res->sig_flags |= CDK_FLAG_KEY_REVOKED;
    if( c->sig.pk->has_expired )
        res->sig_flags |= CDK_FLAG_KEY_EXPIRED;

    rc = _cdk_sig_check( c->sig.pk, sig, c->sig.md, &c->sig.is_expired );
    res->sig_status = !rc? CDK_SIGSTAT_GOOD : CDK_SIGSTAT_BAD;
    if( !rc )
        _cdk_log_debug("good signature from %08lX%08lX (expired %d)\n",
                       keyid[0], keyid[1], c->sig.is_expired );
    return rc;
}


static void
free_mainproc( CTX c )
{
    if( !c )
        return;
    cdk_kbnode_release( c->node );
    c->node = NULL;
    if( c->sig.present ) {
        cdk_md_close( c->sig.md );
        c->sig.md = NULL;
        _cdk_free_pubkey( c->sig.pk );
        c->sig.pk = NULL;
    }
    cdk_free (c->file);
    c->file = NULL;
    cdk_free (c->dek);
    c->dek = NULL;
    cdk_free (c);
}


static int
do_proc_packets( cdk_ctx_t hd, CTX c, cdk_stream_t inp,
                 cdk_stream_t * ret_out )
{
    cdk_packet_t pkt = NULL;
    cdk_kbnode_t n = NULL, node;
    const char * s;
    int rc = 0, npos, with_mdc = 0;

    if( !hd || !c )
        return CDK_Inv_Value;

    s = _cdk_stream_get_fname (inp);
    c->file = cdk_strdup (s? s : " ");
    if (!c->file) {
        cdk_free (c);
        return CDK_Out_Of_Core;
    }
  
    while (!cdk_stream_eof (inp)) {
        pkt = cdk_calloc (1, sizeof *pkt);
        if (!pkt)
            return CDK_Out_Of_Core;
        rc = cdk_pkt_read (inp, pkt);
        _cdk_log_debug ("type=%d old_ctb=%d len=%d (%d)\n",
                        pkt->pkttype, pkt->old_ctb, pkt->pktlen, rc);
        if (rc == CDK_EOF)
            c->eof_seen = 1;
        if (rc)
            break;
      
        n = cdk_kbnode_new (pkt);
        if (!c->node)
            c->node = n;
        else
            _cdk_kbnode_add (c->node, n);

        switch (pkt->pkttype) {
        case CDK_PKT_SYMKEY_ENC:
            rc = handle_symkey_enc (c, hd, pkt);
            _cdk_log_debug (" handle_symkey_enc (%d)\n", rc);
            break;
          
        case CDK_PKT_PUBKEY_ENC:
            rc = handle_pubkey_enc (c, hd, pkt);
            _cdk_log_debug (" handle_pubkey_enc (%d)\n", rc); 
            break;
          
        case CDK_PKT_ENCRYPTED_MDC: 
        case CDK_PKT_ENCRYPTED:
            with_mdc = pkt->pkttype == CDK_PKT_ENCRYPTED_MDC;
            rc = handle_encrypted (c, hd, pkt, with_mdc);
            _cdk_log_debug (" handle_encrypted (%d)\n", rc);
            if (!rc)
                inp = c->s;
            break;
          
        case CDK_PKT_COMPRESSED:
            if (!c->s)
                c->s = inp;
            rc = handle_compressed (c, pkt);
            _cdk_log_debug (" handle_compressed (%d)\n", rc);
            break;

        case CDK_PKT_ONEPASS_SIG:
            if (!c->s)
                c->s = inp;
            _cdk_log_debug (" handle_onepass_sig (0)\n");
            c->sig.present = 1;
            c->sig.one_pass = 1;
            c->sig.pt_offset = cdk_stream_tell (c->s);
            break;

        case CDK_PKT_LITERAL:
            /* skip rest of the packet */
            if (!c->s)
                c->s = inp;
            if( !_cdk_stream_get_blockmode( c->s ) ) {
                npos = cdk_stream_tell (c->s) + pkt->pkt.literal->len;
                cdk_stream_seek (c->s, npos);
            }
            else
                cdk_stream_seek( c->s, cdk_stream_get_length( c->s ) );
            break;
          
        case CDK_PKT_SIGNATURE:
            if (!c->sig.present)
                c->sig.present = 1;
            break; /* handle it later */

        case CDK_PKT_MDC:
            _cdk_log_debug( "MDC packet detected.\n" );
            break;

        case CDK_PKT_MARKER:
            _cdk_log_debug( "marker packet detected.\n" );
            break;

        default:
            rc = CDK_Inv_Packet;
            break; 
        }
        if (rc)
            break;
    }
    if( c->eof_seen == 1 )
        rc = 0;
    for( node = c->node; !rc && node; node = node->next ) {
        pkt = node->pkt;
        switch (pkt->pkttype) {
        case CDK_PKT_ONEPASS_SIG:
            rc = handle_onepass_sig (c, pkt);
            _cdk_log_debug (" _handle_onepass_sig (%d)\n", rc);
            break;
          
        case CDK_PKT_LITERAL:
            rc = handle_literal (c, pkt, ret_out);
            _cdk_log_debug (" _handle_literal (%d)\n", rc);
            break;

        case CDK_PKT_SIGNATURE:
            rc = handle_signature (hd, c, pkt);
            _cdk_log_debug (" _handle_signature (%d)\n", rc);
            break;

        default:
            _cdk_log_debug ("skip packet type %d\n", pkt->pkttype);
            break;
        }
        if (rc)
            break;
    }
    if( rc == CDK_EOF )
        rc = CDK_Wrong_Seckey;
    return rc;
}


int
_cdk_proc_packets( cdk_ctx_t hd, cdk_stream_t inp,
                   const char * output, cdk_stream_t outstream,
                   cdk_md_hd_t md )
{
    cdk_stream_t out = NULL;
    CTX c;
    int rc;

    if( !inp )
        return CDK_Inv_Value;
    if( output && outstream )
        return CDK_Inv_Mode;

    c = cdk_calloc( 1, sizeof *c );
    if( !c )
        return CDK_Out_Of_Core;
    if( output )
        c->output = output;
    if( outstream )
        c->tmpfp = outstream;
    if( md )
        c->sig.md = md;
    rc = do_proc_packets( hd, c, inp, &out );
    if( !c->tmpfp )
        cdk_stream_close( out );
    free_mainproc( c );
    return rc;
}


static int
check_pubkey_enc_list( cdk_stream_t in, cdk_keydb_hd_t hd )
{
    cdk_packet_t pkt;
    int n = 0, nenc = 0;
    
    if( !in || !hd )
        return CDK_Inv_Value;

    if( cdk_armor_filter_use( in ) )
        cdk_stream_set_armor_flag( in, 0 );
    pkt = cdk_calloc( 1, sizeof * pkt );
    cdk_pkt_init( pkt );
    while( !cdk_pkt_read( in, pkt ) ) {
        if( pkt->pkttype != CDK_PKT_PUBKEY_ENC ) {
            if( CDK_PKT_IS_ENCRYPTED( pkt->pkttype ) )
                cdk_free( pkt->pkt.encrypted );
            else
                cdk_pkt_free( pkt );
            break;
        }
        nenc++;
        if( !cdk_keydb_check_sk( hd, pkt->pkt.pubkey_enc->keyid ) )
            n++;
        cdk_pkt_free( pkt );
        cdk_pkt_init( pkt );
    }
    cdk_free( pkt );
    cdk_stream_seek( in, 0 );
    if( !nenc )
        return 0;
    _cdk_log_debug( "found %d secret keys\n", n );
    return n? 0 : CDK_Error_No_Key;
}
    

/**
 * cdk_file_decrypt - Decrypt a file.
 * @hd: Handle.
 * @file: Name of the file to decrypt.
 * @output: Output filename.
 *
 * When the operation was successfull, hd can contain information about
 * the signature (when present) and more.
 **/
cdk_error_t
cdk_file_decrypt( cdk_ctx_t hd, const char * file, const char * output )
{
    cdk_stream_t inp = NULL;
    int rc = 0;

    if( !file )
        return CDK_Inv_Value;
    
    if( file && output )
        rc = _cdk_check_args( hd->opt.overwrite, file, output );
    if( !rc )
        rc = cdk_stream_open( file, &inp );
    if( !rc )
        rc = check_pubkey_enc_list( inp, hd->db.sec );
    if( !rc )
        rc = _cdk_proc_packets( hd, inp, output, NULL, NULL );

    cdk_stream_close( inp );
    return rc;
}


cdk_error_t
cdk_stream_decrypt( cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out )
{
    int rc;

    rc = check_pubkey_enc_list( inp, hd->db.sec );
    if( !rc )
        rc = _cdk_proc_packets( hd, inp, NULL, out, NULL );
    return rc;
}


/**
 * cdk_data_transform:
 * @hd: session handle
 * @mode: crypto mode
 * @locusr: local user list (sign mode only)
 * @remusr: remote users 'recipients'
 * @inbuf: input buffer with data
 * @insize: length of data in bytes
 * @outbuf: pointer to the output data (will be allocated)
 * @outsize: size of the new data in bytes
 * @modval: value for the modus (for example sign mode)
 *
 * This function transforms data into the given openpgp mode. It works
 * exactly like the cdk_file_xxx functions with the exception that it can
 * be used with memory and not with streams or files.
 **/
cdk_error_t
cdk_data_transform( cdk_ctx_t hd, enum cdk_crypto_mode_t mode,
                    cdk_strlist_t locusr, cdk_strlist_t remusr,
                    const void * inbuf, size_t insize,
                    byte ** outbuf, size_t * outsize,
                    int modval )
{
    cdk_stream_t inp, out;
    cdk_keydb_hd_t db;
    cdk_kbnode_t knode = NULL;
    int rc, res[4];
    
    if( !hd )
        return CDK_Inv_Value;
    if( !mode )
        return 0;
    if( mode == CDK_CRYPTYPE_SIGN && !locusr )
        return CDK_Inv_Value;
    if( !inbuf || !insize || !outbuf )
        return CDK_Inv_Value;

    inp = cdk_stream_tmp_from_mem( inbuf, insize );
    if( !inp )
        return CDK_Out_Of_Core;
    out = cdk_stream_tmp( );
    if( !out ) {
        cdk_stream_close( inp );
        return CDK_Out_Of_Core;
    }

    cdk_stream_tmp_set_mode( inp, 0 );
    cdk_stream_tmp_set_mode( out, 1 );
        
    switch( mode ) {
    case CDK_CRYPTYPE_ENCRYPT:
        rc = cdk_stream_encrypt( hd, remusr, inp, out );
        break;

    case CDK_CRYPTYPE_DECRYPT:
        rc = cdk_stream_decrypt( hd, inp, out );
        break;

    case CDK_CRYPTYPE_SIGN:
        rc = cdk_stream_sign( hd, inp, out, locusr, remusr, 0, modval );
        break;

    case CDK_CRYPTYPE_VERIFY:
        rc = cdk_stream_verify( hd, inp, out );
        break;

    case CDK_CRYPTYPE_EXPORT:
        if( cdk_handle_control( hd, CDK_CTLF_GET, CDK_CTL_ARMOR ) )
            cdk_stream_set_armor_flag( out, CDK_ARMOR_PUBKEY );
        db = cdk_handle_get_keydb( hd, CDK_DBTYPE_PK_KEYRING );
        rc = cdk_keydb_export( db, out, remusr );
        break;

    case CDK_CRYPTYPE_IMPORT:
        if( cdk_armor_filter_use( inp ) )
            cdk_stream_set_armor_flag( inp, 0 );
        rc = cdk_keydb_get_keyblock( inp, &knode );
        if( knode ) {
            db = cdk_handle_get_keydb( hd, CDK_DBTYPE_PK_KEYRING );
            rc = cdk_keydb_import( db, knode, res );
            if( !rc ) {
                *outbuf = NULL; /* FIXME */
                *outsize = strlen( *outbuf );
            }
            cdk_kbnode_release( knode );
        }
        break;

    default:
        rc = CDK_Inv_Mode;
        break;
    }

    cdk_stream_close( inp );
    if( !rc && mode != CDK_CRYPTYPE_VERIFY ) {
        cdk_stream_tmp_set_mode( out, 0 );
        rc = cdk_stream_mmap( out, outbuf, outsize );
    }
    else if( !rc && mode == CDK_CRYPTYPE_VERIFY ) {
        *outbuf = NULL; /* FIXME */
        *outsize = *outbuf? strlen( *outbuf ) : 0;
    }
    cdk_stream_close( out );
    return rc;
}

    
