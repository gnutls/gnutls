/* -*- Mode: C; c-file-style: "bsd" -*- */
/* trustdb.c - High level interface for ownertrust handling
 *        Copyright (C) 2001, 2002, 2003 Timo Schulz 
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"

#define TRUST_MASK      15
#define RECORD_SIZE     40
#define MIN_TRUSTDB_VER  3


enum {
    TDB_RECORD_TRUST = 12,
    TDB_RECORD_VALID = 13,
};

struct tdb_record_s {
    int recno;
    union {
        struct {
            byte reserved;
            byte fpr[20];
            int ownertrust;
            byte depth;
            u32 validlist;
        } trust;
        struct {
            byte reserved;
            byte fpr[20];
            u32 next;
            int valid;
        } valid;
    } u;
};
typedef struct tdb_record_s *tdb_record_t;


static void
trustdb_rec_release( tdb_record_t rec )
{
    if( rec ) {
        rec->recno = 0;
        cdk_free( rec );
    }
}


static tdb_record_t
trustdb_rec_new( void )
{
    tdb_record_t rec;

    rec = cdk_calloc( 1, sizeof *rec );
    if( !rec )
        return NULL;
    return rec;
}


static int
trustdb_check( cdk_stream_t a, int req_ver )
{
    int rc = 0;
    int c = 0, nread;
    byte magic[3];

    cdk_stream_seek( a, 0 );
    c = cdk_stream_getc( a );
    if( c == EOF || c != 1 )
        return CDK_General_Error;
    nread = cdk_stream_read( a, magic, 3 );
    if( nread == EOF )
        return CDK_File_Error;
    c = cdk_stream_getc( a );
    if( c == EOF )
        rc = CDK_General_Error;
    else if( c < req_ver )
        rc = CDK_Wrong_Format;
    return rc;
}


static int
trustdb_rec_parse( cdk_stream_t buf, tdb_record_t r )
{
    size_t n;
    int recno;

    if( !buf || !r )
        return CDK_Inv_Value;

    recno = cdk_stream_getc( buf );
    if( recno == EOF )
        return EOF;

    switch( recno ) {
    case TDB_RECORD_TRUST:	/* trust record: new */
        r->recno = 12;
        r->u.trust.reserved = cdk_stream_getc (buf);
        n = cdk_stream_read (buf, r->u.trust.fpr, 20);
        r->u.trust.ownertrust = cdk_stream_getc (buf);
        r->u.trust.depth = cdk_stream_getc (buf);
        r->u.trust.validlist = 0;
        n = 4;
        while (n--)
            cdk_stream_getc (buf);
        n = RECORD_SIZE - 28;
        while (n--)
            cdk_stream_getc (buf);
        if (r->u.trust.ownertrust == EOF)
            return CDK_EOF;
        break;

    case TDB_RECORD_VALID:	/* valid record: new */
        r->recno = 13;
        r->u.valid.reserved = cdk_stream_getc (buf);
        n = cdk_stream_read (buf, r->u.valid.fpr, 20);
        r->u.valid.valid = cdk_stream_getc (buf);
        r->u.valid.next = 0;
        n = 4;
        while (n--)
            cdk_stream_getc (buf);
        n = RECORD_SIZE - 27;
        while (n--)
            cdk_stream_getc (buf);
        if (r->u.valid.valid == EOF)
            return CDK_EOF;
        break;

    default:
        n = RECORD_SIZE - 1;
        while (n--)
            cdk_stream_getc (buf);
        break;
    }
    r->recno = recno;
    return 0;
}


tdb_record_t
trustdb_rec_byfpr( cdk_stream_t buf, int type,
                   const byte * fpr, size_t fprlen )
{
    tdb_record_t rec;

    if (!fpr || !buf)
        return NULL;

    rec = trustdb_rec_new ();
    if( !rec )
        return NULL;

    while( trustdb_rec_parse( buf, rec ) != EOF ) {
        if( rec->recno != type )
            continue;
        switch( type ) {
	case TDB_RECORD_VALID:
            if( !memcmp( fpr, rec->u.valid.fpr, fprlen ) )
                return rec;
            break;

	case TDB_RECORD_TRUST:
            if( !memcmp( rec->u.trust.fpr, fpr, fprlen ) )
                return rec;
            break;
	}
    }
    trustdb_rec_release ( rec );
    rec = NULL;
    return rec;
}


int
cdk_trustdb_get_ownertrust( cdk_stream_t inp, cdk_pkt_pubkey_t pk,
			    int *r_val, int *r_flags )
{
    tdb_record_t rec = NULL;
    byte fpr[20];
    int flags = 0;
    int rc;

    if( !inp || !r_val || !r_flags || !pk )
        return CDK_Inv_Value;

    rc = trustdb_check( inp, MIN_TRUSTDB_VER );
    if( rc )
        return rc;
  
    *r_val = CDK_TRUST_UNKNOWN;
    cdk_pk_get_fingerprint( pk, fpr );
    cdk_stream_seek( inp, 0 );

    rec = trustdb_rec_byfpr( inp, TDB_RECORD_TRUST, fpr, 20 );
    if( rec ) {
        *r_val = rec->u.trust.ownertrust & TRUST_MASK;
        if( *r_val & CDK_TFLAG_REVOKED )
            flags |= CDK_TFLAG_REVOKED;
        if( *r_val & CDK_TFLAG_SUB_REVOKED )
            flags |= CDK_TFLAG_SUB_REVOKED;
        if( *r_val & CDK_TFLAG_DISABLED )
            flags |= CDK_TFLAG_DISABLED;
        *r_flags = flags;
        rc = 0;
    }
    trustdb_rec_release( rec );
    return rc;
}


int
cdk_trustdb_get_validity( cdk_stream_t inp, cdk_pkt_userid_t id, int *r_val )
{
    cdk_md_hd_t rmd;
    tdb_record_t rec;
    byte * fpr;
    int rc;

    if( !inp || !r_val || !id )
        return CDK_Inv_Value;

    rc = trustdb_check( inp, MIN_TRUSTDB_VER );
    if( rc )
        return rc;
  
    *r_val = CDK_TRUST_UNKNOWN;
    rmd = cdk_md_open( CDK_MD_RMD160, 0 );
    if( !rmd )
        return CDK_Gcry_Error;

    cdk_md_write( rmd, id->name, id->len );
    cdk_md_final( rmd );
    fpr = cdk_md_read( rmd, CDK_MD_RMD160 );

    cdk_stream_seek( inp, 0 );
    rec = trustdb_rec_byfpr( inp, TDB_RECORD_VALID, fpr, 20 );
    if( rec ) {
        *r_val = rec->u.valid.valid;
        rc = 0;
    }
    
    trustdb_rec_release( rec );
    cdk_md_close( rmd );
    return rc;
}
