/* -*- Mode: C; c-file-style: "bsd" -*-
 * context.h
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef CDK_CONTEXT_H
#define CDK_CONTEXT_H

#include "types.h"

struct cdk_listkey_s {
    unsigned init:1;
    cdk_stream_t inp;
    cdk_keydb_hd_t db;
    int type;
    union {
        char * patt;
        cdk_strlist_t fpatt;  
    } u;
    cdk_strlist_t t;   
};

struct cdk_sesskey_s {
    gcry_mpi_t a;
};  

struct cdk_verify_result_s {
    int sig_ver;
    int sig_len;
    int sig_status;
    int sig_flags;
    unsigned int keyid[2];
    unsigned int created;
    unsigned int expires;
    int pubkey_algo;
    int digest_algo;
    char * notation;
    unsigned char * sig_data;
};

struct cdk_s2k_s {
    int mode;
    unsigned char hash_algo;
    unsigned char salt[8];
    unsigned int count;
};

struct cdk_ctx_s {
    int trust_model;
    int cipher_algo;
    int digest_algo;
    struct {
        int algo;
        int level;
    } compress;
    struct {
        int mode;
        int digest_algo;
        int cipher_algo;
    } _s2k;
    struct {
        unsigned armor:1;
        unsigned textmode:1;
        unsigned compress:1;
        unsigned mdc:1;
        unsigned compat:1;
        unsigned rfc1991:1;
        unsigned overwrite;
        unsigned force_digest:1;
    } opt;
    struct {
        _cdk_verify_result_t verify;
    } result;
    struct {
        cdk_pkt_seckey_t sk;
        unsigned on:1;
    } cache;
    cdk_dek_t dek;
    cdk_s2k_t s2k;
    struct {
        cdk_keydb_hd_t sec;
        cdk_keydb_hd_t pub;
    } db;
    void (*callback) (void * opaque, int type, const char * s);
    void * callback_value;
    char *(*passphrase)(void * opaque, const char * prompt);
    void * passphrase_value;
};

struct cdk_prefitem_s {
    unsigned char type;
    unsigned char value;
};

struct cdk_desig_revoker_s {
    struct cdk_desig_revoker_s * next;
    unsigned char class;
    unsigned char algid;
    unsigned char fpr[20];
};

struct cdk_subpkt_s {
    struct cdk_subpkt_s * next;
    unsigned int size;
    unsigned char type;
    unsigned char d[1];  
};

struct cdk_mpi_s {
    unsigned short bits;
    unsigned short bytes;
    unsigned char data[1];
};

struct key_idx_s {
    unsigned int offset;
    unsigned int keyid[2];
    unsigned char fpr[20]; 
};


struct cdk_dbsearch_s 
{
    union {
        char * pattern;
        unsigned int keyid[2];
        unsigned char fpr[20];
    } u;
    int type;
};
typedef struct cdk_dbsearch_s *cdk_dbsearch_t;


struct key_table_s {
    struct key_table_s * next;
    unsigned int offset;
    cdk_dbsearch_t desc;   
};



struct cdk_keydb_hd_s {
    int type;
    cdk_stream_t buf; /* NULL if the name item is valid */
    cdk_stream_t idx;
    cdk_dbsearch_t dbs;
    char * name;
    char * idx_name;
    struct key_table_s * cache;
    int ncache;
    unsigned int secret:1;
    unsigned int isopen:1;
    unsigned int no_cache:1;
    unsigned int search:1;
};


struct cdk_keylist_s {
    struct cdk_keylist_s * next;
    union {
        cdk_pkt_pubkey_t pk;
        cdk_pkt_seckey_t sk;
    } key;
    int type;  
};

struct cdk_dek_s {
    int algo;
    int keylen;
    int use_mdc;
    unsigned rfc1991:1;
    unsigned char key[32]; /* 256-bit */
};

struct cdk_strlist_s {
    struct cdk_strlist_s * next;
    char d[1]; 
};

#endif /* CDK_CONTEXT_H */
