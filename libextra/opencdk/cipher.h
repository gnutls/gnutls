/* -*- Mode: C; c-file-style: "bsd" -*-
 * cipher.h
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

#ifndef CDK_CIPHER_H
#define CDK_CIPHER_H

#define MAX_BLOCKSIZE 16


typedef int (*cipher_setkey_t) (void *c,
                                const unsigned char *key,
                                unsigned keylen);

typedef void (*cipher_encrypt_t) (void *c,
                                  unsigned char *outbuf,
                                  const unsigned char *inbuf);

typedef void (*cipher_decrypt_t) (void *c,
                                  unsigned char *outbuf,
                                  const unsigned char *inbuf);

typedef struct {
    const char *name;
    int id;
    size_t blocksize;
    size_t keylen;
    size_t contextsize;
    cipher_setkey_t setkey;
    cipher_encrypt_t encrypt;
    cipher_decrypt_t decrypt;
} cipher_spec_t;

extern cipher_spec_t cipher_spec_blowfish;
extern cipher_spec_t cipher_spec_twofish;
extern cipher_spec_t cipher_spec_3des;
extern cipher_spec_t cipher_spec_cast5;
extern cipher_spec_t cipher_spec_aes;
extern cipher_spec_t cipher_spec_aes192;
extern cipher_spec_t cipher_spec_aes256;


cdk_cipher_hd_t cdk_cipher_new( int algo, int pgp_sync );
cdk_cipher_hd_t cdk_cipher_open( int algo, int pgp_sync,
                                 const byte * key, size_t keylen,
                                 const byte * ivbuf, size_t ivlen );    
void cdk_cipher_close( cdk_cipher_hd_t hd );
int cdk_cipher_encrypt( cdk_cipher_hd_t hd,
                        byte * outbuf, const byte *inbuf, size_t n );
int cdk_cipher_decrypt( cdk_cipher_hd_t hd,
                        byte * outbuf, const byte *inbuf, size_t n );
void cdk_cipher_sync( cdk_cipher_hd_t hd );
int cdk_cipher_setiv( cdk_cipher_hd_t hd, const byte *ivbuf, size_t n );
int cdk_cipher_setkey( cdk_cipher_hd_t hd, const byte *keybuf, size_t n );
int cdk_cipher_get_algo_blklen( int algo );
int cdk_cipher_get_algo_keylen( int algo );
int cdk_cipher_test_algo( int algo );
    
#endif /*CDK_CIPHER_H*/



