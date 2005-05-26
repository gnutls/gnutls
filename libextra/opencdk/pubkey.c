/* -*- Mode: C; c-file-style: "bsd" -*-
 * pubkey.c - Public key API
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


static gcry_mpi_t *
convert_to_gcrympi( cdk_mpi_t m[4], int ncount )
{
    gcry_mpi_t * d;
    size_t nbytes = 0;
    int i = 0, rc = 0;

    if( !m || ncount > 4 )
        return NULL;
    d = cdk_calloc( ncount, sizeof *d );
    if( !d )
        return NULL;
    for( i = 0; i < ncount; i++ ) {
        nbytes = m[i]->bytes + 2;
        if( gcry_mpi_scan( &d[i], GCRYMPI_FMT_PGP, m[i]->data, nbytes, &nbytes ) ) {
            rc = CDK_Gcry_Error;
            break;
	}
    }
    if( rc ) {
        _cdk_free_mpibuf( i, d );
        d = NULL;
    }
    return d;
}


static int
seckey_to_sexp( gcry_sexp_t * r_skey, cdk_pkt_seckey_t sk )
{
    gcry_sexp_t sexp = NULL;
    gcry_mpi_t * mpk = NULL, * msk = NULL;
    cdk_pkt_pubkey_t pk;
    const char * fmt = NULL;
    int ncount = 0, nscount = 0;
    int rc = 0;

    if( !r_skey || !sk || !sk->pk )
        return CDK_Inv_Value;

    pk = sk->pk;
    ncount = cdk_pk_get_npkey( pk->pubkey_algo );
    mpk = convert_to_gcrympi( pk->mpi, ncount );
    if( !mpk )
        return CDK_MPI_Error;
    nscount = cdk_pk_get_nskey( sk->pubkey_algo );
    msk = convert_to_gcrympi( sk->mpi, nscount );
    if( !msk )
        rc = CDK_MPI_Error;
    if( !rc && is_RSA( sk->pubkey_algo ) ) {
        fmt = "(private-key(openpgp-rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, mpk[0], mpk[1],
                             msk[0], msk[1], msk[2], msk[3] ) )
            rc = CDK_Gcry_Error;
    }
    else if( !rc && is_ELG( sk->pubkey_algo ) ) {
        fmt = "(private-key(openpgp-elg(p%m)(g%m)(y%m)(x%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, mpk[0], mpk[1],
                             mpk[2], msk[0] ) )
            rc = CDK_Gcry_Error;
    }
    else if( !rc && is_DSA( sk->pubkey_algo ) ) {
        fmt = "(private-key(openpgp-dsa(p%m)(q%m)(g%m)(y%m)(x%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, mpk[0], mpk[1], mpk[2],
                             mpk[3], msk[0] ) )
            rc = CDK_Gcry_Error;
    }
    else
        rc = CDK_Inv_Algo;

    _cdk_free_mpibuf( ncount, mpk );
    _cdk_free_mpibuf( nscount, msk );
    *r_skey = sexp;
    return rc;
}


static int
pubkey_to_sexp( gcry_sexp_t * r_key, cdk_pkt_pubkey_t pk )
{
    gcry_sexp_t sexp = NULL;
    gcry_mpi_t * m;
    const char * fmt = NULL;
    int ncount = 0;
    int rc = 0;

    if( !r_key || !pk )
        return CDK_Inv_Value;

    ncount = cdk_pk_get_npkey( pk->pubkey_algo );
    m = convert_to_gcrympi( pk->mpi, ncount );
    if( !m )
        return CDK_MPI_Error;
    if( is_RSA( pk->pubkey_algo ) ) {
        fmt = "(public-key(openpgp-rsa(n%m)(e%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1] ) )
            rc = CDK_Gcry_Error;
    }
    else if( is_ELG( pk->pubkey_algo ) ) {
        fmt = "(public-key(openpgp-elg(p%m)(g%m)(y%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1], m[2] ) )
            rc = CDK_Gcry_Error;
    }
    else if( is_DSA( pk->pubkey_algo ) ) {
        fmt = "(public-key(openpgp-dsa(p%m)(q%m)(g%m)(y%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1], m[2], m[3] ) )
            rc = CDK_Gcry_Error;
    }
    else
        rc = CDK_Inv_Algo;
    _cdk_free_mpibuf( ncount, m );
    *r_key = sexp;
    return rc;
}


static int
enckey_to_sexp( gcry_sexp_t * r_sexp, gcry_mpi_t esk )
{
    gcry_sexp_t sexp = NULL;
    int rc = 0;

    if( !r_sexp || !esk )
        return CDK_Inv_Value;
    if( gcry_sexp_build( &sexp, NULL, "%m", esk ) )
        rc = CDK_Gcry_Error;
    *r_sexp = sexp;
    return rc;
}


static int
digest_to_sexp( gcry_sexp_t * r_md, int algo, const byte * md, size_t mdlen )
{
    gcry_sexp_t sexp = NULL;
    gcry_mpi_t m = NULL;
    size_t nbytes = 0;
    int rc = 0;

    if( !r_md || !md )
        return CDK_Inv_Value;
    nbytes = mdlen ? mdlen : cdk_md_get_algo_dlen( algo );
    if( !nbytes )
        return CDK_Inv_Algo;
    if( gcry_mpi_scan( &m, GCRYMPI_FMT_USG, md, nbytes, &nbytes ) )
        return CDK_Gcry_Error;
    if( gcry_sexp_build( &sexp, NULL, "%m", m ) )
        rc = CDK_Gcry_Error;
    if( !rc )
        *r_md = sexp;
    gcry_mpi_release( m );
    return rc;
}


static int
sexp_to_bitmpi( gcry_sexp_t sexp, const char * val, cdk_mpi_t * ret_buf )
{
    gcry_sexp_t list = NULL;
    gcry_mpi_t m = NULL;
    cdk_mpi_t buf = NULL;
    size_t nbits = 0, nbytes = 0;
    int rc = 0;

    if( !sexp || !val || !ret_buf )
        return CDK_Inv_Value;

    list = gcry_sexp_find_token( sexp, val, 0 );
    if( !list )
        return CDK_Gcry_Error;
    m = gcry_sexp_nth_mpi( list, 1, 0 );
    if( !m ) {
        gcry_sexp_release( list );
        return CDK_Gcry_Error;
    }
    nbits = gcry_mpi_get_nbits( m );
    nbytes = (nbits + 7) / 8;
    buf = cdk_calloc( 1, sizeof *buf + nbytes );
    if( !buf ) {
        rc = CDK_Out_Of_Core;
        goto leave;
    }
    buf->data[0] = nbits >> 8;
    buf->data[1] = nbits;
    if( gcry_mpi_print( GCRYMPI_FMT_USG, NULL, nbytes, &nbytes, m ) )
        rc = CDK_Gcry_Error;
    else
        if( gcry_mpi_print( GCRYMPI_FMT_USG, buf->data + 2, nbytes, &nbytes, m ) )
            rc = CDK_Gcry_Error;
    if( !rc ) {
        buf->bytes = nbytes;
        buf->bits = nbits;
        *ret_buf = buf;
    }

 leave:
    gcry_mpi_release( m );
    gcry_sexp_release( list );
    return rc;
}


static int
sexp_to_sig( cdk_pkt_signature_t sig, gcry_sexp_t sexp)
{
    int rc = 0;

    if( !sig || !sexp )
        return CDK_Inv_Value;

    if( is_RSA( sig->pubkey_algo ) )
        return sexp_to_bitmpi( sexp, "s", &sig->mpi[0] );
    else if( is_DSA( sig->pubkey_algo) || is_ELG( sig->pubkey_algo ) ) {
        rc = sexp_to_bitmpi( sexp, "r", &sig->mpi[0] );
        if( !rc )
            rc = sexp_to_bitmpi( sexp, "s", &sig->mpi[1] );
        return rc;
    }
    return CDK_Inv_Algo;
}


static int
sig_to_sexp( gcry_sexp_t * r_sig, cdk_pkt_signature_t sig )
{
    gcry_sexp_t sexp = NULL;
    gcry_mpi_t * m;
    const char * fmt;
    int ncount = 0;
    int rc = 0;

    if( !r_sig || !sig )
        return CDK_Inv_Value;

    ncount = cdk_pk_get_nsig( sig->pubkey_algo );
    m = convert_to_gcrympi( sig->mpi, ncount );
    if( !m )
        return CDK_MPI_Error;
    if( is_RSA( sig->pubkey_algo ) ) {
        fmt = "(sig-val(openpgp-rsa(s%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0] ) )
            rc = CDK_Gcry_Error;
    }
    else if( is_ELG( sig->pubkey_algo ) ) {
        fmt = "(sig-val(openpgp-elg(r%m)(s%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1] ) )
            rc = CDK_Gcry_Error;
    }
    else if( is_DSA( sig->pubkey_algo ) ) {
        fmt = "(sig-val(openpgp-dsa(r%m)(s%m)))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1] ) )
            rc = CDK_Gcry_Error;
    }
    else
        rc = CDK_Inv_Algo;
    _cdk_free_mpibuf( ncount, m );
    *r_sig = sexp;
    return rc;
}


static int
sexp_to_pubenc( cdk_pkt_pubkey_enc_t enc, gcry_sexp_t sexp)
{
    int rc;

    if( !sexp || !enc )
        return CDK_Inv_Value;

    if( is_RSA( enc->pubkey_algo) )
        return sexp_to_bitmpi( sexp, "a", &enc->mpi[0] );
    else if( is_ELG( enc->pubkey_algo) ) {
        rc = sexp_to_bitmpi( sexp, "a", &enc->mpi[0] );
        if( !rc )
            rc = sexp_to_bitmpi( sexp, "b", &enc->mpi[1] );
        return rc;
    }
    return CDK_Inv_Algo;
}


static int
pubenc_to_sexp( gcry_sexp_t * r_sexp, cdk_pkt_pubkey_enc_t enc)
{
    gcry_sexp_t sexp = NULL;
    gcry_mpi_t * m;
    const char * fmt;
    int ncount;
    int rc = 0;

    if( !r_sexp || !enc )
        return CDK_Inv_Value;

    ncount = cdk_pk_get_nenc( enc->pubkey_algo );
    m = convert_to_gcrympi( enc->mpi, ncount );
    if( !m )
        return CDK_MPI_Error;
    if( is_RSA( enc->pubkey_algo ) ) {
        fmt = "(enc-val(openpgp-rsa((a%m))))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0] ) )
            rc = CDK_Gcry_Error;
    }
    else if( is_ELG( enc->pubkey_algo ) ) {
        fmt = "(enc-val(openpgp-elg((a%m)(b%m))))";
        if( gcry_sexp_build( &sexp, NULL, fmt, m[0], m[1] ) )
            rc = CDK_Gcry_Error;
    }
    else
        rc = CDK_Inv_Algo;
    _cdk_free_mpibuf( ncount, m );
    *r_sexp = sexp;
    return rc;
}


static int
is_unprotected( cdk_pkt_seckey_t sk )
{
    if( sk->is_protected && !sk->mpi[0] )
        return 0;
    return 1;
}


/**
 * cdk_pk_encrypt:
 * @pk: the public key
 * @pke: the public key encrypted packet
 * @esk: the actual session key
 *
 * Encrypt the session key in @esk and write its encrypted content
 * into the @pke struct.
 **/
cdk_error_t
cdk_pk_encrypt( cdk_pkt_pubkey_t pk, cdk_pkt_pubkey_enc_t pke,
                cdk_sesskey_t esk )
{
    gcry_sexp_t s_data = NULL, s_pkey = NULL, s_ciph = NULL;
    int rc;

    if( !pk || !esk || !pke )
        return CDK_Inv_Value;

    if( !KEY_CAN_ENCRYPT( pk->pubkey_algo ) )
        return CDK_Inv_Algo;

    rc = enckey_to_sexp( &s_data, esk->a );
    if( !rc )
        rc = pubkey_to_sexp( &s_pkey, pk );
    if( !rc )
        rc = gcry_pk_encrypt( &s_ciph, s_data, s_pkey );
    if( !rc )
        rc = sexp_to_pubenc( pke, s_ciph );

    gcry_sexp_release( s_data );
    gcry_sexp_release( s_pkey );
    gcry_sexp_release( s_ciph );
    return rc;
}


/**
 * cdk_pk_decrypt:
 * @sk: the secret key
 * @pke: public key encrypted packet
 * @r_sk: the object to store the plain session key
 *
 * Decrypt the encrypted session key from @pke into @r_sk.
 **/
cdk_error_t
cdk_pk_decrypt( cdk_pkt_seckey_t sk, cdk_pkt_pubkey_enc_t pke,
                cdk_sesskey_t * r_sk )
{
    gcry_sexp_t s_data = NULL, s_skey = NULL, s_plain = NULL;
    int rc;

    if( !sk || !r_sk || !pke )
        return CDK_Inv_Value;

    if( !is_unprotected( sk ) )
        return CDK_Inv_Mode;
  
    rc = seckey_to_sexp( &s_skey, sk );
    if( !rc )
        rc = pubenc_to_sexp( &s_data, pke );
    if( !rc && gcry_pk_decrypt( &s_plain, s_data, s_skey ) )
        rc = CDK_Gcry_Error;
    if( !rc ) {
        rc = cdk_sesskey_new( r_sk );
        if( !rc )
            (*r_sk)->a = gcry_sexp_nth_mpi( s_plain, 0, 0 );
    }

    gcry_sexp_release( s_data );
    gcry_sexp_release( s_skey );
    gcry_sexp_release( s_plain );
    return rc;
}


/**
 * cdk_pk_sign:
 * @sk: secret key
 * @sig: signature
 * @md: the message digest
 *
 * Sign the message digest from @md and write the result into @sig.
 **/
cdk_error_t
cdk_pk_sign( cdk_pkt_seckey_t sk, cdk_pkt_signature_t sig, const byte * md )
{
    gcry_sexp_t s_skey = NULL, s_sig = NULL, s_hash = NULL;
    byte * encmd = NULL;
    size_t enclen = 0;
    int nbits, rc;

    if( !sk || !sk->pk || !sig || !md )
        return CDK_Inv_Value;

    if( !is_unprotected( sk ) )
        return CDK_Inv_Mode;
  
    if( !KEY_CAN_SIGN( sig->pubkey_algo ) )
        return CDK_Inv_Algo;

    nbits = cdk_pk_get_nbits( sk->pk );
    rc = _cdk_digest_encode_pkcs1( &encmd, &enclen, sk->pk->pubkey_algo, md,
                                   sig->digest_algo, nbits );
    if( !rc )
        rc = seckey_to_sexp( &s_skey, sk );
    if( !rc )
        rc = digest_to_sexp( &s_hash, sig->digest_algo, encmd, enclen );
    if( !rc && gcry_pk_sign( &s_sig, s_hash, s_skey ) )
        rc = CDK_Gcry_Error;
    if( !rc )
        rc = sexp_to_sig( sig, s_sig );
    sig->digest_start[0] = md[0];
    sig->digest_start[1] = md[1];

    gcry_sexp_release( s_skey );
    gcry_sexp_release( s_hash );
    gcry_sexp_release( s_sig );
    cdk_free( encmd );
    return rc;
}


/**
 * cdk_pk_verify:
 * @pk: the public key
 * @sig: signature
 * @md: the message digest
 *
 * Verify the signature in @sig and compare it with the message digest in @md.
 **/
cdk_error_t
cdk_pk_verify( cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig, const byte * md)
{
    gcry_sexp_t s_pkey = NULL, s_sig = NULL, s_hash = NULL;
    byte * encmd = NULL;
    size_t enclen = 0;
    int nbits, rc;

    if( !pk || !sig || !md )
        return CDK_Inv_Value;

    nbits = cdk_pk_get_nbits( pk );
    rc = pubkey_to_sexp( &s_pkey, pk );
    if( !rc )
        rc = sig_to_sexp( &s_sig, sig );
    if( !rc )
        rc = _cdk_digest_encode_pkcs1( &encmd, &enclen, pk->pubkey_algo, md,
                                       sig->digest_algo, nbits );
    if( !rc )
        rc = digest_to_sexp( &s_hash, sig->digest_algo, encmd, enclen );
    if( !rc && gcry_pk_verify( s_sig, s_hash, s_pkey ) )
        rc = CDK_Bad_Sig;

    gcry_sexp_release( s_sig );
    gcry_sexp_release( s_hash );
    gcry_sexp_release( s_pkey );
    cdk_free( encmd );
    return rc;
}


int
cdk_pk_get_nbits( cdk_pkt_pubkey_t pk )
{
    if( !pk || !pk->mpi[0] )
        return 0;
    return pk->mpi[0]->bits;
}


int
cdk_pk_get_npkey( int algo )
{
    size_t bytes;

    if (algo == 16)
        algo = 20; /* XXX: libgcrypt returns 0 for 16 */
    if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &bytes))
    	return 0;
    
    return bytes;
}


int
cdk_pk_get_nskey( int algo )
{  
size_t bytes;

    if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &bytes))
    	return 0;
    
    bytes -= cdk_pk_get_npkey( algo );
    return bytes;
}


int
cdk_pk_get_nsig( int algo )
{
size_t bytes;

    if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSIGN, NULL, &bytes))
    	return 0;
    return bytes;
}


int
cdk_pk_get_nenc( int algo )
{
size_t bytes;

    if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NENCR, NULL, &bytes))
    	return 0;
    return bytes;
}


int
_cdk_pk_algo_usage( int algo )
{
    int usage = 0;

    switch( algo ) {
    case CDK_PK_RSA  : usage = PK_USAGE_SIGN | PK_USAGE_ENCR; break;
    case CDK_PK_RSA_E: usage = PK_USAGE_ENCR; break;
    case CDK_PK_RSA_S: usage = PK_USAGE_SIGN; break;
    case CDK_PK_ELG  : usage = PK_USAGE_SIGN | PK_USAGE_ENCR; break;
    case CDK_PK_ELG_E: usage = PK_USAGE_ENCR; break;
    case CDK_PK_DSA  : usage = PK_USAGE_SIGN; break; 
    }
    return usage;  
}


int
_cdk_pk_test_algo( int algo, unsigned int usage_flags )
{
    size_t n = usage_flags;
  
    if( algo < 0 || algo > 110 )
        return GPG_ERR_INV_PARAMETER;
    return gcry_pk_algo_info( algo, GCRYCTL_TEST_ALGO, NULL, &n );    
}


static int
read_mpi( cdk_mpi_t a, byte * buf, size_t * r_count, size_t * r_nbits )
{
    if( !a || !buf || !r_count )
        return CDK_Inv_Value;
  
    if( a->bytes + 2 > *r_count )
        return CDK_General_Error;
    *r_count = a->bytes + 2;
    memcpy( buf, a->data, *r_count );
    if( r_nbits )
        *r_nbits = a->bits;
    return 0;
}

  
cdk_error_t
cdk_pk_get_mpi( cdk_pkt_pubkey_t pk, int idx,
                byte * buf, size_t * r_count, size_t * r_nbits )
{
    if( !pk || idx < 0 || !r_count )
        return CDK_Inv_Value;
    if( idx > cdk_pk_get_npkey( pk->pubkey_algo ) )
        return CDK_Inv_Value;
    return read_mpi( pk->mpi[idx], buf, r_count, r_nbits );
}


cdk_error_t
cdk_sk_get_mpi( cdk_pkt_seckey_t sk, int idx,
                byte * buf, size_t * r_count, size_t * r_nbits)
{
    if( !sk || idx < 0 || !r_count)
        return CDK_Inv_Value;
    if( idx > cdk_pk_get_nskey( sk->pubkey_algo ) )
        return CDK_Inv_Value;
    return read_mpi( sk->mpi[idx], buf, r_count, r_nbits );
}


static u16
checksum_mpi( cdk_mpi_t m )
{
    int i;
    u16 chksum = 0;

    if( !m )
        return 0;
    for( i = 0; i < m->bytes + 2; i++)
        chksum += m->data[i];
    return chksum;
}


cdk_error_t
cdk_sk_unprotect( cdk_pkt_seckey_t sk, const char * pw )
{
    cdk_cipher_hd_t hd;
    cdk_dek_t dek = NULL;
    cdk_mpi_t a;
    u16 chksum = 0;
    size_t ndata, nbits;
    int j, i, dlen, pos = 0, nskey;
    int rc;
    byte * data = NULL;

    if( !sk )
        return CDK_Inv_Value;

    nskey = cdk_pk_get_nskey( sk->pubkey_algo );
    if( sk->is_protected ) {
        rc = cdk_dek_from_passphrase( &dek, sk->protect.algo,
                                      sk->protect.s2k, 0, pw );
        if( rc )
            return rc;
        hd = cdk_cipher_open( sk->protect.algo, 1,
                              dek->key, dek->keylen,
                              sk->protect.iv, sk->protect.ivlen );
        if( !hd ) {
            cdk_free( dek );
            return CDK_Inv_Algo;
        }
        wipemem( dek, sizeof dek );
        cdk_dek_free( dek );
        chksum = 0;
        if( sk->version == 4 ) {
            ndata = sk->enclen;
            data = cdk_salloc( ndata, 1 );
            if( !data )
                return CDK_Out_Of_Core;
            cdk_cipher_decrypt( hd, data, sk->encdata, ndata );
            if( sk->protect.sha1chk ) {
                /* This is the new SHA1 checksum method to detect tampering
                   with the key as used by the Klima/Rosa attack */
                sk->csum = 0;
                chksum = 1;
                dlen = cdk_md_get_algo_dlen( CDK_MD_SHA1 );
                if( ndata < dlen ) {
                    cdk_free( data );
                    return CDK_Inv_Packet;
                }
                else {
                    cdk_md_hd_t md = cdk_md_open( CDK_MD_SHA1, 1 );
                    if( !md )
                        return CDK_Gcry_Error;
                    cdk_md_write( md, data, ndata - dlen );
                    cdk_md_final( md );
                    if( !memcmp( cdk_md_read( md, CDK_MD_SHA1 ),
                                 data + ndata - dlen, dlen ) )
                        chksum = 0;	/* digest does match */
                    cdk_md_close( md );
		}
	    }
            else {
                for( i = 0; i < ndata - 2; i++)
                    chksum += data[i];
                sk->csum = data[ndata - 2] << 8 | data[ndata - 1];
	    }
            if( sk->csum == chksum ) {
                for( i = 0; i < nskey; i++ ) {
                    nbits = data[pos] << 8 | data[pos + 1];
                    ndata = (nbits + 7) / 8;
                    a = sk->mpi[i] = cdk_salloc( sizeof *a + ndata + 2, 1 );
                    if( !a ) {
                        cdk_free( data );
                        return CDK_Out_Of_Core;
                    }
                    a->bits = nbits;
                    a->bytes = ndata;
                    for( j = 0; j < ndata + 2; j++ )
                        a->data[j] = data[pos++];
		}
	    }
            wipemem( data, sk->enclen );
            cdk_free( data );
	}
        else {
            chksum = 0;
            for( i = 0; i < nskey; i++ ) {
                a = sk->mpi[i];
                cdk_cipher_sync( hd );
                cdk_cipher_decrypt( hd, a->data+2, a->data+2, a->bytes );
                chksum += checksum_mpi( a );
	    }
	}
        cdk_cipher_close( hd );
    }
    else {
        chksum = 0;
        for( i = 0; i < nskey; i++ )
            chksum += checksum_mpi( sk->mpi[i] );
    }
    if( chksum != sk->csum )
        return CDK_Chksum_Error;
    sk->is_protected = 0;
    return 0;
}


cdk_error_t
cdk_sk_protect( cdk_pkt_seckey_t sk, const char * pass )
{
    cdk_cipher_hd_t hd;
    cdk_md_hd_t md;
    cdk_mpi_t a;
    cdk_dek_t dek;
    cdk_s2k_t s2k;
    byte * p;
    size_t enclen = 0, nskey, i;
    int rc;

    rc = cdk_s2k_new( &s2k, 3, CDK_MD_SHA1, NULL );
    if( rc )
        return rc;
    rc = cdk_dek_from_passphrase( &dek, CDK_CIPHER_3DES, s2k, 2, pass );
    if( rc )
        return rc;
    
    nskey = cdk_pk_get_nskey( sk->pubkey_algo  );
    for( i = 0; i < nskey; i++ ) {
        enclen += 2;
        enclen += sk->mpi[i]->bytes;
    }
    p = sk->encdata = cdk_calloc( 1, enclen + 20 + 1  );
    if( !p )
        return CDK_Out_Of_Core;
    enclen = 0;
    for( i = 0; i < nskey; i++ ) {
        a = sk->mpi[i];
        p[enclen++] = a->bits >> 8;
        p[enclen++] = a->bits;
        memcpy( p + enclen, a->data, a->bytes  );
        enclen += a->bytes;
    }
    enclen += 20;
    sk->enclen = enclen;
    sk->protect.s2k = s2k;
    sk->protect.algo = CDK_CIPHER_3DES;
    sk->protect.ivlen = cdk_cipher_get_algo_blklen( sk->protect.algo  );
    gcry_randomize( sk->protect.iv, sk->protect.ivlen, GCRY_STRONG_RANDOM  );
    hd = cdk_cipher_open( sk->protect.algo, 1,
                          dek->key, dek->keylen,
                          sk->protect.iv, sk->protect.ivlen );
    if( !hd ) {
        cdk_free( p );
        return CDK_Gcry_Error;
    }

    md = cdk_md_open( CDK_MD_SHA1, GCRY_CIPHER_SECURE  );
    if( !md ) {
        cdk_cipher_close( hd  );
        cdk_free( p  );
        return CDK_Gcry_Error;
    }
    sk->protect.sha1chk = 1;
    sk->is_protected = 1;
    sk->csum = 0;
    cdk_md_write( md, p, enclen - 20 );
    cdk_md_final( md );
    memcpy( p + enclen - 20, cdk_md_read( md, 0 ), 20 );
    cdk_md_close( md );
    rc = cdk_cipher_encrypt( hd, p, p, enclen );
    cdk_cipher_close( hd );
    cdk_dek_free( dek );
    return rc;
}


/**
 * cdk_pk_from_secret_key:
 * @sk: the secret key
 * @ret_pk: the new public key
 *
 * Create a new public key from a secret key.
 **/
cdk_error_t
cdk_pk_from_secret_key( cdk_pkt_seckey_t sk, cdk_pkt_pubkey_t* ret_pk )
{
    if( !sk )
        return CDK_Inv_Value;
    return _cdk_copy_pubkey( ret_pk, sk->pk );
}


int
cdk_pk_revoke_import( cdk_keydb_hd_t db, const char * revcert )
{
    /* due to the fact the keydb code can't insert or modify packets
       it is not possible to handle this step yet */
    return 0;
}


int
cdk_pk_revoke_create( cdk_pkt_seckey_t sk, int code, const char * inf,
                      char ** ret_revcert )
{
    cdk_md_hd_t md;
    cdk_subpkt_t node;
    cdk_pkt_signature_t sig;
    char * p = NULL, * dat;
    int n;
    
    if( !sk || !ret_revcert )
        return CDK_Inv_Value;
    if( code < 0 || code > 3 )
        return CDK_Inv_Value;

    sig = cdk_calloc( 1, sizeof * sig );
    if( !sig )
        return CDK_Out_Of_Core;
    _cdk_sig_create( sk->pk, sig );
    n = 1;
    if( inf ) {
        n += strlen( p );
        p = cdk_utf8_encode( inf );
    }
    dat = cdk_calloc( 1, n+1 );
    if( !dat ) {
        _cdk_free_signature( sig );
        return CDK_Out_Of_Core;
    }
    dat[0] = code;
    if( inf )
        memcpy( dat+1, p, strlen( p ) );
    cdk_free( p );

    node = cdk_subpkt_new( n );
    if( node ) {
        cdk_subpkt_init( node, CDK_SIGSUBPKT_REVOC_REASON, dat, n );
        cdk_subpkt_add( sig->hashed, node );
    }
    cdk_free( dat );

    md = cdk_md_open( CDK_MD_SHA1, 0 );
    if( !md ) {
        _cdk_free_signature( sig );
        return CDK_Gcry_Error;
    }
    _cdk_hash_pubkey( sk->pk, md, 0 );
    _cdk_free_signature( sig );
    return 0;
}


int
_cdk_sk_get_csum( cdk_pkt_seckey_t sk )
{
    u16 csum = 0, i;

    if( !sk )
        return 0;
    for( i = 0; i < cdk_pk_get_nskey( sk->pubkey_algo ); i++ )
        csum += checksum_mpi( sk->mpi[i] );
    return csum;
}


int
cdk_pk_get_fingerprint( cdk_pkt_pubkey_t pk, byte * fpr )
{
    cdk_md_hd_t hd;
    int md_algo;
    int dlen = 0;

    if( !pk || !fpr )
        return CDK_Inv_Value;

    if( pk->version < 4 && is_RSA( pk->pubkey_algo ) )
        md_algo = CDK_MD_MD5; /* special */
    else
        md_algo = pk->version < 4 ? CDK_MD_RMD160 : CDK_MD_SHA1;
    dlen = cdk_md_get_algo_dlen( md_algo );
    hd = cdk_md_open( md_algo, 0 );
    if( !hd )
        return CDK_Gcry_Error;
    _cdk_hash_pubkey( pk, hd, 1 );
    cdk_md_final( hd );
    memcpy( fpr, cdk_md_read( hd, md_algo ), dlen );
    cdk_md_close( hd );
    if( dlen == 16 )
        memset( fpr + 16, 0, 4 );
    return 0;
}


u32
cdk_pk_fingerprint_get_keyid( const byte * fpr, size_t fprlen, u32 * keyid )
{
    u32 lowbits = 0;

    /* in this case we say the key is a V3 RSA key and we can't
       use the fingerprint to get the keyid. */
    if( fpr && fprlen == 16 )
        return 0;
    else if( keyid && fpr ) {
        keyid[0] = _cdk_buftou32( fpr + 12 );
        keyid[1] = _cdk_buftou32( fpr + 16 );
        lowbits = keyid[1];
    }
    else if( fpr )
        lowbits = _cdk_buftou32( fpr + 16 );
    return lowbits;
}


u32
cdk_pk_get_keyid( cdk_pkt_pubkey_t pk, u32 * keyid )
{
    u32 lowbits = 0;
    byte buf[24];

    if( pk &&( !pk->keyid[0] || !pk->keyid[1] ) ) {
        if( pk->version < 4 && is_RSA( pk->pubkey_algo ) ) {
            size_t n = pk->mpi[0]->bytes;
            const byte * p = pk->mpi[0]->data + 2;
            pk->keyid[0] = p[n-8] << 24 | p[n-7] << 16 | p[n-6] << 8 | p[n-5];
            pk->keyid[1] = p[n-4] << 24 | p[n-3] << 16 | p[n-2] << 8 | p[n-1];
	}
        else if( pk->version == 4 ) {
            cdk_pk_get_fingerprint( pk, buf );
            pk->keyid[0] = _cdk_buftou32( buf + 12 );
            pk->keyid[1] = _cdk_buftou32( buf + 16 );
	}
    }
    lowbits = pk ? pk->keyid[1] : 0;
    if( keyid && pk ) {
        keyid[0] = pk->keyid[0];
        keyid[1] = pk->keyid[1];
    }
    return lowbits;
}


u32
cdk_sk_get_keyid( cdk_pkt_seckey_t sk, u32 * keyid )
{
    u32 lowbits = 0;
    
    if( sk && sk->pk ) {
        lowbits = cdk_pk_get_keyid( sk->pk, keyid );
        sk->keyid[0] = sk->pk->keyid[0];
        sk->keyid[1] = sk->pk->keyid[1];
    }
    return lowbits;
}


u32
cdk_sig_get_keyid( cdk_pkt_signature_t sig, u32 * keyid )
{
    u32 lowbits = sig ? sig->keyid[1] : 0;
  
    if( keyid && sig ) {
        keyid[0] = sig->keyid[0];
        keyid[1] = sig->keyid[1];
    }
    return lowbits;
}


u32
_cdk_pkt_get_keyid( cdk_packet_t pkt, u32 * keyid )
{
    u32 lowbits;

    if( !pkt )
        return 0;
    
    switch( pkt->pkttype ) {
    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
        lowbits = cdk_pk_get_keyid( pkt->pkt.public_key, keyid );
        break;
      
    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_SECRET_SUBKEY:
        lowbits = cdk_sk_get_keyid( pkt->pkt.secret_key, keyid );
        break;

    case CDK_PKT_SIGNATURE:
        lowbits = cdk_sig_get_keyid( pkt->pkt.signature, keyid );
        break;
      
    default:
        lowbits = 0;
    }
    return lowbits;
}


int
_cdk_pkt_get_fingerprint( cdk_packet_t pkt, byte * fpr )
{
    if( !pkt || !fpr )
        return CDK_Inv_Value;
    
    switch( pkt->pkttype ) {
    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
        return cdk_pk_get_fingerprint( pkt->pkt.public_key, fpr );

    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_SECRET_SUBKEY:
        return cdk_pk_get_fingerprint( pkt->pkt.secret_key->pk, fpr );

    default:
        return CDK_Inv_Packet;
    }
    return 0;
}
