/* -*- Mode: C; c-file-style: "bsd" -*-
 * filters.h - Filter structs
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef CDK_FILTERS_H
#define CDK_FILTERS_H

enum {
    STREAMCTL_READ  = 0,
    STREAMCTL_WRITE = 1,
    STREAMCTL_FREE  = 2
};

typedef struct {
    cdk_cipher_hd_t hd;
    cdk_md_hd_t mdc;
    int mdc_method;
    cdk_dek_t dek;
    u32 datalen;
    struct {
        int on;
        size_t size;
    } blkmode;
    cdk_stream_t s;
} cipher_filter_t;

typedef struct {
    int digest_algo;
    cdk_md_hd_t md;
} md_filter_t;

typedef struct {
    const char * le; /* line endings */
    const char * hdrlines;
    u32 crc;
    int crc_okay;
    int idx, idx2;
} armor_filter_t;

typedef struct {
    int mode;
    unsigned rfc1991:1;
    char * filename;
    cdk_md_hd_t md;
    struct {
        int on;
        size_t size;
    } blkmode;
} literal_filter_t;

typedef struct {
    size_t inbufsize;
    byte inbuf[8192];
    size_t outbufsize;
    byte outbuf[8192];
    int algo; /* compress algo */
    int level;
} compress_filter_t;

typedef struct {
    const char * lf;
} text_filter_t;


/*-- armor.c -*/
int _cdk_filter_armor( void * opaque, int ctl, FILE * in, FILE * out );

/*-- cipher.c --*/
int _cdk_filter_hash( void * opaque, int ctl, FILE * in, FILE * out );
int _cdk_filter_cipher( void * opaque, int ctl, FILE * in, FILE * out );

/*-- plaintext.c --*/
int _cdk_filter_literal( void * opaque, int ctl, FILE * in, FILE * out );
int _cdk_filter_text( void * opaque, int ctl, FILE * in, FILE * out );

/*-- compress.c --*/
int _cdk_filter_compress( void * opaque, int ctl, FILE * in, FILE * out );

#endif /* CDK_FILTERS_H */

        
