/* -*- Mode: C; c-file-style: "bsd" -*-
 * stream.h - internal definiton for the STREAM object
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
 * along with OpenCDK; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef CDK_STREAM_H
#define CDK_STREAM_H

enum {
    fDUMMY    = 0,
    fARMOR    = 1,
    fCIPHER   = 2,
    fLITERAL = 3,
    fCOMPRESS= 4,
    fHASH    = 5,
    fTEXT    = 6
};

typedef int (*filter_fnct_t) (void * opaque, int ctl, FILE * in, FILE * out);

struct stream_filter_s {
    struct stream_filter_s * next;
    filter_fnct_t fnct;
    void * opaque;
    FILE * tmp;
    union {
        armor_filter_t afx;
        cipher_filter_t cfx;
        literal_filter_t pfx;
        compress_filter_t zfx;
        text_filter_t tfx;
        md_filter_t mfx;
    } u;
    struct {
        unsigned enabled:1;
        unsigned rdonly:1;
    } flags;
    unsigned type;
    unsigned ctl;
};


struct cdk_stream_s {
    struct stream_filter_s * filters;
    int fmode;
    int error;
    size_t blkmode;
    struct {
        unsigned filtrated:1;
        unsigned eof:1;
        unsigned write:1;
        unsigned temp:1;
        unsigned reset:1;
        unsigned no_filter:1;
        unsigned compressed:3;
    } flags;
    struct {
        unsigned char buf[8192];
        unsigned on:1;
        size_t size;
    } cache;
    char * fname;
    FILE * fp;
};

#endif /* CDK_STREAM_H */
