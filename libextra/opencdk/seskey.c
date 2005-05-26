/* -*- Mode: C; c-file-style: "bsd" -*-
 * seskey.c - Session key routines
 *        Copyright (C) 2002, 2003 Timo Schulz
 *        Copyright (C) 1998-2002 Free Software Foundation, Inc.
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
#include <assert.h>
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"


/* We encode the MD in this way:
 *
 * 0  1 PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
 *
 * PAD consists of FF bytes.
 */
static int
do_encode_md (byte ** r_frame, size_t * r_flen, const byte * md, int algo,
	      size_t len, unsigned nbits, const byte * asn, size_t asnlen)
{
    byte * frame = NULL;
    size_t n = 0;
    int i, nframe = (nbits + 7) / 8;

    if( !asn || !md || !r_frame || !r_flen )
        return CDK_Inv_Value;

    if (len + asnlen + 4 > nframe)
        return CDK_General_Error;

    frame = cdk_calloc (1, nframe);
    if (!frame)
        return CDK_Out_Of_Core;
    frame[n++] = 0;
    frame[n++] = 1;
    i = nframe - len - asnlen - 3;
    if (i < 0) {
        cdk_free (frame);
        return CDK_Inv_Value;
    }
    memset (frame + n, 0xff, i);
    n += i;
    frame[n++] = 0;
    memcpy (frame + n, asn, asnlen);
    n += asnlen;
    memcpy (frame + n, md, len);
    n += len;
    if( n != nframe ) {
        cdk_free( frame );
        return CDK_Inv_Value;
    }
    *r_frame = frame;
    *r_flen = n;
    return 0;
}


/* RFC2437 format:
 *  
 *  0  2  RND(n bytes)  0  [A  DEK(k bytes)  CSUM(2 bytes)]
 *  
 *  RND - randomized bytes for padding.
 *  A - cipher algorithm.
 *  DEK - random session key.
 *  CKSUM - algebraic checksum of the DEK.
 */
cdk_error_t
cdk_dek_encode_pkcs1( cdk_dek_t dek, int nbits, cdk_sesskey_t * r_esk )
{
    gcry_mpi_t a = NULL;
    byte * p, * frame;
    size_t n = 0;
    u16 chksum = 0;
    int i = 0, nframe = 0;
    int rc = 0;

    if( !r_esk || !dek )
        return CDK_Inv_Value;

    for (i = 0; i < dek->keylen; i++)
        chksum += dek->key[i];
    nframe = (nbits + 7) / 8;
    frame = cdk_salloc (nframe + 1, 1);
    if (!frame)
        return CDK_Out_Of_Core;
    n = 0;
    frame[n++] = 0x00;
    frame[n++] = 0x02;
    i = nframe - 6 - dek->keylen;
    p = gcry_random_bytes (i, GCRY_STRONG_RANDOM);
    /* replace zero bytes by new values */
    for (;;) {
        int j, k;
        byte * pp;

        /* count the zero bytes */
        for (j = k = 0; j < i; j++) {
            if (!p[j])
                k++;
	}
        if (!k)
            break; /* okay: no zero bytes */
        k += k / 128; /* better get some more */
        pp = gcry_random_bytes (k, GCRY_STRONG_RANDOM);
        for (j = 0; j < i && k; j++) {
            if (!p[j])
                p[j] = pp[--k];
	}
        cdk_free (pp);
    }
    memcpy (frame + n, p, i);
    cdk_free (p);
    n += i;
    frame[n++] = 0;
    frame[n++] = dek->algo;
    memcpy (frame + n, dek->key, dek->keylen);
    n += dek->keylen;
    frame[n++] = chksum >> 8;
    frame[n++] = chksum;
    rc = gcry_mpi_scan (&a, GCRYMPI_FMT_USG, frame, nframe, &nframe);
    if (rc)
        rc = CDK_Gcry_Error;
    cdk_free (frame);
    if( !rc ) {
        rc = cdk_sesskey_new( r_esk );
        if( rc ) {
            gcry_mpi_release( a );
            return rc;
        }
        (*r_esk)->a = a;
    }
    return rc;
}


cdk_error_t
cdk_dek_decode_pkcs1( cdk_dek_t *ret_dek, cdk_sesskey_t esk )
{
    cdk_dek_t dek;
    byte frame[4096];
    size_t nframe, n;
    u16 csum = 0, csum2 = 0;
    int rc;

    if( !ret_dek || !esk )
        return CDK_Inv_Value;
    
    nframe = sizeof frame-1;
    rc = gcry_mpi_print (GCRYMPI_FMT_USG, frame, nframe, &nframe, esk->a);
    if( rc )
        return CDK_Gcry_Error;
    dek = cdk_salloc( sizeof *dek, 1 );
    if( !dek )
        return CDK_Out_Of_Core;

    /* Now get the DEK (data encryption key) from the frame
     *
     *     0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * (gcry_mpi_print already removed the leading zero).
     *
     * RND are non-zero randow bytes.
     * A   is the cipher algorithm
     * DEK is the encryption key (session key) with length k
     * CSUM
     */
    n = 0;
    if( frame[n] != 2 ) {
        cdk_free (dek);
        return CDK_Inv_Mode;
    }
    for( n++; n < nframe && frame[n]; n++ )
        ;
    n++;
    dek->keylen = nframe - (n + 1) - 2;
    dek->algo = frame[n++];
    if( dek->keylen != cdk_cipher_get_algo_keylen( dek->algo ) ) {
        cdk_free( dek );
        return CDK_Inv_Algo;
    }
    csum =  frame[nframe-2] << 8;
    csum |= frame[nframe-1];
    memcpy( dek->key, frame + n, dek->keylen );
    for( n = 0; n < dek->keylen; n++ )
        csum2 += dek->key[n];
    if( csum != csum2 ) {
        cdk_free( dek );
        return CDK_Chksum_Error;
    }
    *ret_dek = dek;
    return 0;
}


/* Do some tests before it calls do_encode_md that depends on the
   public key algorithm that is used. */
cdk_error_t
_cdk_digest_encode_pkcs1( byte ** r_md, size_t * r_mdlen, int pk_algo,
                          const byte * md, int digest_algo, unsigned nbits )
{
    int rc = 0;
    int dlen = cdk_md_get_algo_dlen( digest_algo );
    byte * p;

    if( !md || !r_md || !r_mdlen )
        return CDK_Inv_Value;

    if( !dlen )
        return CDK_Inv_Algo;
    if( is_DSA( pk_algo ) ) {
        *r_md = p = cdk_malloc( dlen + 1 );
        if( !p )
            return CDK_Out_Of_Core;
        *r_mdlen = dlen;
        memcpy( p, md, dlen );
        return 0;
    }
    else {
        byte * asn = NULL;
        size_t asnlen = 0;

        rc = cdk_md_get_asnoid( digest_algo, NULL, &asnlen );
        if( !rc ) {
            asn = cdk_malloc( asnlen + 1 );
            if( !asn )
                return CDK_Out_Of_Core;
        }
        if( !rc )
            rc = cdk_md_get_asnoid( digest_algo, asn, &asnlen );
        if( !rc )
            rc = do_encode_md( r_md, r_mdlen, md, digest_algo, dlen,
                               nbits, asn, asnlen );
        cdk_free( asn );
        return rc;
    }
    return 0;
}


static char *
passphrase_prompt (cdk_pkt_seckey_t sk)
{
    u32 keyid = cdk_pk_get_keyid (sk->pk, NULL);
    int bits = cdk_pk_get_nbits (sk->pk), pk_algo = sk->pubkey_algo;
    const char * algo = "???", * fmt;
    char * p;
  
    if (is_RSA (pk_algo))
        algo = "RSA";
    else if (is_ELG (pk_algo))
        algo = "ELG";
    else if (is_DSA (pk_algo))
        algo = "DSA";

    fmt = "%d-bit %s key, ID %08lX\nEnter Passphrase: ";
    p = cdk_calloc( 1, 64 + strlen( fmt ) + 1 );
    if( !p )
        return NULL;
    sprintf( p, fmt, bits, algo, keyid );
    return p;
}


cdk_error_t
_cdk_sk_unprotect_auto( cdk_ctx_t hd, cdk_pkt_seckey_t sk )
{
    char * pw = NULL, * p = NULL;
    int rc = 0;
  
    if( sk->is_protected ) {
        p = passphrase_prompt( sk );
        pw = _cdk_passphrase_get( hd, p );
        if( pw )
            rc = cdk_sk_unprotect( sk, pw );
        _cdk_passphrase_free( pw, pw? strlen( pw ) : 0 );
        cdk_free( p );
    }
    return rc;
}


cdk_error_t
cdk_dek_extract( cdk_dek_t * ret_dek, cdk_ctx_t hd,
                 cdk_pkt_pubkey_enc_t enc, cdk_pkt_seckey_t sk )
{
    cdk_dek_t dek = NULL;
    cdk_sesskey_t skey = NULL;
    int rc = 0;

    if( !enc || !sk || !ret_dek )
        return CDK_Inv_Value;
  
    if( sk->is_protected )
        rc = _cdk_sk_unprotect_auto( hd, sk );
    if( !rc )
        rc = cdk_pk_decrypt( sk, enc, &skey );
    if( !rc )
        rc = cdk_dek_decode_pkcs1( &dek, skey );
    cdk_sesskey_free( skey );
    if( rc ) {
        cdk_dek_free( dek );
        dek = NULL;
    }
    *ret_dek = dek;
    return rc;
}


cdk_error_t
cdk_sesskey_new( cdk_sesskey_t * r_sk )
{
    cdk_sesskey_t sk;
    
    if( !r_sk )
        return CDK_Inv_Value;
    sk = cdk_calloc( 1, sizeof **r_sk );
    if( !sk )
        return CDK_Out_Of_Core;
    *r_sk = sk;
    return 0;
}


void
cdk_sesskey_free( cdk_sesskey_t sk )
{
    if( sk ) {
        gcry_mpi_release( sk->a );
        cdk_free( sk );
    }
}


cdk_error_t
cdk_dek_new( cdk_dek_t * r_dek )
{
    cdk_dek_t dek;

    if( !r_dek )
        return CDK_Inv_Value;
    *r_dek = NULL;
    dek = cdk_salloc( sizeof *dek, 1 );
    if( !dek )
        return CDK_Out_Of_Core;
    *r_dek = dek;
    return 0;
}


cdk_error_t
cdk_dek_set_cipher( cdk_dek_t dek, int algo )
{
    if( !dek )
        return CDK_Inv_Value;
    if( !algo )
        algo = CDK_CIPHER_CAST5;
    if( cdk_cipher_test_algo( algo ) )
        return CDK_Inv_Algo;
    dek->algo = algo;
    dek->keylen = cdk_cipher_get_algo_keylen( dek->algo );
    return 0;
}


cdk_error_t
cdk_dek_set_key( cdk_dek_t dek, const byte * key, size_t keylen )
{
    cdk_cipher_hd_t hd;
    int i;

    if( !dek )
        return CDK_Inv_Value;
    if( keylen > 0 && keylen != dek->keylen )
        return CDK_Inv_Mode;

    if( !key && !keylen ) {
        hd = cdk_cipher_new( dek->algo, 1 );
        if( !hd )
            return CDK_Inv_Algo;
        gcry_randomize( dek->key, dek->keylen, GCRY_STRONG_RANDOM );
        for( i = 0; i < 8; i++ ) {
            if( !cdk_cipher_setkey( hd, dek->key, dek->keylen ) ) {
                cdk_cipher_close( hd );
                return 0;
            }
            gcry_randomize( dek->key, dek->keylen, GCRY_STRONG_RANDOM );
        }
        return CDK_Weak_Key;
    }
    memcpy( dek->key, key, dek->keylen );
    return 0;
}


void
cdk_dek_set_mdc_flag( cdk_dek_t dek, int val )
{
    if( dek )
        dek->use_mdc = val;
}


void
cdk_dek_free( cdk_dek_t dek )
{
    cdk_free( dek );
}


static int
hash_passphrase( cdk_dek_t dek, const char * pw, cdk_s2k_t s2k, int create )
{
    cdk_md_hd_t md;
    int pass, i;
    int used = 0, pwlen = 0;

    if (!dek || !pw || !s2k)
        return CDK_Inv_Value;

    if (!s2k->hash_algo)
        s2k->hash_algo = CDK_MD_SHA1;
    pwlen = strlen (pw);

    dek->keylen = cdk_cipher_get_algo_keylen (dek->algo);
    md = cdk_md_open( s2k->hash_algo, GCRY_MD_FLAG_SECURE );
    if (!md)
        return CDK_Inv_Algo;

    for (pass = 0; used < dek->keylen; pass++) {
        if (pass) {
            cdk_md_reset (md);
            for (i = 0; i < pass; i++) /* preset the hash context */
                cdk_md_putc (md, 0);
	}
        if (s2k->mode == 1 || s2k->mode == 3) {
            int len2 = pwlen + 8;
            u32 count = len2;
            if (create && !pass) {
                gcry_randomize (s2k->salt, 8, 1);
                if (s2k->mode == 3)
                    s2k->count = 96; /* 65536 iterations */
	    }
            if (s2k->mode == 3) {
                count = (16ul + (s2k->count & 15)) << ((s2k->count >> 4) + 6);
                if (count < len2)
                    count = len2;
	    }
            /* a little bit complicated because we need a ulong for count */
            while (count > len2) { /* maybe iterated+salted */
                cdk_md_write (md, s2k->salt, 8);
                cdk_md_write (md, pw, pwlen);
                count -= len2;
	    }
            if (count < 8)
                cdk_md_write (md, s2k->salt, count);
            else {
                cdk_md_write (md, s2k->salt, 8);
                count -= 8;
                cdk_md_write (md, pw, count);
	    }
	}
        else
            cdk_md_write (md, pw, pwlen);
        cdk_md_final (md);
        i = cdk_md_get_algo_dlen (s2k->hash_algo);
        if (i > dek->keylen - used)
            i = dek->keylen - used;
        memcpy (dek->key + used, cdk_md_read (md, s2k->hash_algo), i);
        used += i;
    }
    cdk_md_close (md);
    return 0;
}


cdk_error_t
cdk_dek_from_passphrase( cdk_dek_t * ret_dek, int cipher_algo, cdk_s2k_t s2k,
                         int mode, const char * pw )
{
    cdk_dek_t dek;
    int rc;

    if( !ret_dek )
        return CDK_Inv_Value;
    rc = cdk_dek_new( &dek );
    if( !rc )
        rc = cdk_dek_set_cipher( dek, cipher_algo );
    if( rc ) {
        cdk_dek_free( dek );
        return rc;
    }
    if( !*pw && mode == 2 )
        dek->keylen = 0;
    else
        hash_passphrase( dek, pw, s2k, mode == 2 );
    *ret_dek = dek;
    return 0;
}


cdk_error_t
cdk_s2k_new( cdk_s2k_t * ret_s2k, int mode, int algo, const byte * salt )
{
    cdk_s2k_t s2k;
    int rc;

    if( !ret_s2k )
        return CDK_Inv_Value;
    if( mode != 0x00 && mode != 0x01 && mode != 0x03 )
        return CDK_Inv_Mode;
    
    rc = cdk_md_test_algo( algo );
    if( rc )
        return rc;
    s2k = cdk_calloc( 1, sizeof *s2k );
    if( !s2k )
        return CDK_Out_Of_Core;
    s2k->mode = mode;
    s2k->hash_algo = algo;
    if( salt )
        memcpy( s2k->salt, salt, 8 );
    *ret_s2k = s2k;
    return 0;
}


void
cdk_s2k_free( cdk_s2k_t s2k )
{
    cdk_free( s2k );
}







