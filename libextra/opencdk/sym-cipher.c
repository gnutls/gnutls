/* -*- Mode: C; c-file-style: "bsd" -*-
 * sym-cipher.c
 *        Copyright (C) 2003 Timo Schulz
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


#include <stdio.h>
#include <string.h>
#include "opencdk.h"
#include "main.h"
#include "cipher.h"


struct cdk_cipher_hd_s {
    gcry_cipher_hd_t hd;
    int algo;
};

inline
static int cdk_cipher_to_gcry( int algo)
{
    switch( algo ) {
    case CDK_CIPHER_BLOWFISH: return GCRY_CIPHER_BLOWFISH;
    case CDK_CIPHER_TWOFISH:  return GCRY_CIPHER_TWOFISH;
    case CDK_CIPHER_3DES:     return GCRY_CIPHER_3DES;
    case CDK_CIPHER_CAST5:    return GCRY_CIPHER_CAST5;
    case CDK_CIPHER_AES:      return GCRY_CIPHER_AES;
    case CDK_CIPHER_AES192:   return GCRY_CIPHER_AES192;
    case CDK_CIPHER_AES256:   return GCRY_CIPHER_AES256;
    default: return -1;
    }
}

cdk_cipher_hd_t
cdk_cipher_new( int algo, int pgp_sync )
{
    cdk_cipher_hd_t hd;
    unsigned int flags = 0;
    gcry_error_t err;
    
    if( cdk_cipher_test_algo( algo ) )
        return NULL;
    hd = cdk_calloc( 1, sizeof * hd );
    if( !hd )
        return NULL;

    if( pgp_sync )
        flags = GCRY_CIPHER_ENABLE_SYNC;

    hd->algo = algo;

    err = gcry_cipher_open( &hd->hd, cdk_cipher_to_gcry(algo), 
	GCRY_CIPHER_MODE_CFB, flags);
    if( err ) {
        cdk_free( hd );
        return NULL;
    }
    return hd;
}


cdk_cipher_hd_t
cdk_cipher_open( int algo, int pgp_sync,
                 const byte * key, size_t keylen,
                 const byte * ivbuf, size_t ivlen )
{
    cdk_cipher_hd_t hd;
    gcry_error_t err;

    hd = cdk_cipher_new( algo, pgp_sync );
    if( hd ) {
        err = gcry_cipher_setkey( hd->hd, key, keylen );
        if( !err)
            err = gcry_cipher_setiv( hd->hd, ivbuf, ivlen );
        if( err) {
            cdk_cipher_close( hd );
            hd = NULL;
        }
    }
    return hd;
}
    

void
cdk_cipher_close( cdk_cipher_hd_t hd )
{
    if( !hd )
        return;
    gcry_cipher_close( hd->hd);
    cdk_free( hd );
}


int
cdk_cipher_decrypt( cdk_cipher_hd_t hd, byte * outbuf, const byte *inbuf,
                    size_t nbytes )
{
gcry_error_t err;

    if( !hd )
        return CDK_Inv_Value;
    err = gcry_cipher_decrypt( hd->hd, outbuf, nbytes, inbuf, nbytes);

    if (err) return CDK_Gcry_Error;
    else return 0;
}


int
cdk_cipher_encrypt( cdk_cipher_hd_t hd, byte * outbuf, const byte *inbuf,
                    size_t nbytes )
{
gcry_error_t err;

    if( !hd )
        return CDK_Inv_Value;
    err = gcry_cipher_encrypt( hd->hd, outbuf, nbytes, inbuf, nbytes);

    if (err) return CDK_Gcry_Error;
    else return 0;
}


void
cdk_cipher_sync( cdk_cipher_hd_t hd )
{
    gcry_cipher_sync( hd->hd);
}


int
cdk_cipher_setiv( cdk_cipher_hd_t hd, const byte *ivbuf, size_t ivlen )
{
    if( !hd )
        return CDK_Inv_Value;

    gcry_cipher_setiv( hd->hd, ivbuf, ivlen);
    return 0;
}


int
cdk_cipher_setkey( cdk_cipher_hd_t hd, const byte *keybuf, size_t keylen )
{
    if( !hd )
        return CDK_Inv_Value;

    gcry_cipher_setkey( hd->hd, keybuf, keylen);
    return 0;
}


int
cdk_cipher_get_algo_blklen( int algo )
{
    return gcry_cipher_get_algo_blklen( cdk_cipher_to_gcry( algo));
}


int
cdk_cipher_get_algo_keylen( int algo )
{
    return gcry_cipher_get_algo_keylen( cdk_cipher_to_gcry( algo));
}


int
cdk_cipher_test_algo( int algo )
{
    return gcry_cipher_test_algo( cdk_cipher_to_gcry( algo));
}
