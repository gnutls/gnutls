/* -*- Mode: C; c-file-style: "bsd" -*-
 * keydb.c - Key database routines
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "filters.h"
#include "stream.h"


#define KEYID_CMP( a, b ) ((a[0]) == (b[0]) && (a[1]) == (b[1]))
#define KEYDB_CACHE_ENTRIES 8

typedef struct key_table_s * key_table_t;
typedef struct key_idx_s * key_idx_t;


static void keydb_cache_free( key_table_t cache );
static int keydb_search_copy( cdk_dbsearch_t * r_dst, cdk_dbsearch_t src );
static int classify_data( const byte * buf, size_t len );
void keydb_search_free( cdk_dbsearch_t dbs );

     
static char *
keydb_idx_mkname( const char * file )
{
    char * fname;
    
    fname = cdk_calloc( 1, strlen( file ) + 5 );
    if( !fname )
        return NULL;
    sprintf( fname, "%s.idx", file );
    return fname;
}


/* This functions builds an index of the keyring into a separate file
   with the name keyring.ext.idx. It contains the offset of all public-
   and public subkeys. The format of the file is:
   --------
    4 octets offset of the packet
    8 octets keyid
   20 octets fingerprint
   --------
   We store the keyid and the fingerprint due to the fact we can't get
   the keyid from a v3 fingerprint directly.
*/
static int
keydb_idx_build( const char * file )
{
    cdk_packet_t pkt;
    cdk_stream_t inp, out = NULL;
    byte buf[8], fpr[20];
    char * fname;
    u32 keyid[2];
    int rc, pos;

    if( !file )
        return CDK_Inv_Value;

    pkt = cdk_calloc( 1, sizeof * pkt );
    if( !pkt )
        return CDK_Out_Of_Core;
    
    fname = keydb_idx_mkname( file );
    if( !fname ) {
        rc = CDK_Out_Of_Core;
        goto leave;
    }
  
    rc = cdk_stream_open( file, &inp );
    if( !rc )
        rc = cdk_stream_create( fname, &out );
    if( rc )
        goto leave;

    while( !cdk_stream_eof( inp ) ) {
        pos = cdk_stream_tell( inp );
        rc = cdk_pkt_read( inp, pkt );
        if( rc )
            break;
        if( pkt->pkttype == CDK_PKT_PUBLIC_KEY
            || pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY ) {
            _cdk_u32tobuf( pos, buf );
            cdk_stream_write( out, buf, 4 );
            cdk_pk_get_keyid( pkt->pkt.public_key, keyid );
            _cdk_u32tobuf( keyid[0], buf );
            _cdk_u32tobuf( keyid[1], buf + 4 );
            cdk_stream_write( out, buf, 8 );
            cdk_pk_get_fingerprint( pkt->pkt.public_key, fpr );
            cdk_stream_write( out, fpr, 20 );
        }
        cdk_pkt_free( pkt );
        cdk_pkt_init( pkt );
    }
    cdk_stream_close( out );
 leave:
    cdk_stream_close( inp );
    cdk_free( fname );
    cdk_free( pkt );
    return rc;
}


/**
 * cdk_keydb_idx_rebuild:
 * @hd: key database handle
 *
 * Rebuild the key index files for the given key database.
 **/
cdk_error_t
cdk_keydb_idx_rebuild( cdk_keydb_hd_t hd )
{
    int rc;
  
    if( !hd || !hd->name )
        return CDK_Inv_Value;
    if( hd->secret )
        return 0;
  
    cdk_stream_close( hd->idx );
    if( !hd->idx_name ) {
        hd->idx_name = keydb_idx_mkname( hd->name );
        if( !hd->idx_name )
            return CDK_Out_Of_Core;
    }
    rc = keydb_idx_build( hd->name );
    if( !rc )
        rc = cdk_stream_open( hd->idx_name, &hd->idx );
    return rc;
}


static int
keydb_idx_parse( cdk_stream_t inp, key_idx_t * r_idx )
{
    key_idx_t idx;
    byte buf[4];
    int i;

    if( !inp || !r_idx )
        return CDK_Inv_Value;
  
    idx = cdk_calloc( 1, sizeof * idx );
    if( !idx )
        return CDK_Out_Of_Core;

    while( !cdk_stream_eof( inp ) ) {
        i = cdk_stream_read( inp, buf, 4 );
        if( i == CDK_EOF )
            break;
        idx->offset = _cdk_buftou32( buf );
        cdk_stream_read( inp, buf, 4 );
        idx->keyid[0] = _cdk_buftou32( buf );
        cdk_stream_read( inp, buf, 4 );
        idx->keyid[1] = _cdk_buftou32( buf );
        cdk_stream_read( inp, idx->fpr, 20 );
#if 0
        _cdk_log_debug( "%08lu: keyid=%08lX fpr=", idx->offset,idx->keyid[1] );
        for( i = 0; i < 20; i++ )
            _cdk_log_debug( "%02X", idx->fpr[i] );
        _cdk_log_debug( "\n" );
#endif
        break; 
    }
    *r_idx = idx;
    return cdk_stream_eof( inp )? CDK_EOF : 0;  
}


static int
keydb_idx_search( cdk_stream_t inp, u32 * keyid,
                  const byte * fpr, u32 * r_off )
{
    key_idx_t idx;

    if( !inp || !r_off )
        return CDK_Inv_Value;
    if( (keyid && fpr) || (!keyid && !fpr) )
        return CDK_Inv_Mode;

    *r_off = 0xFFFFFFFF;
    cdk_stream_seek( inp, 0 );
    while( keydb_idx_parse( inp, &idx ) != CDK_EOF ) {
        if( keyid && KEYID_CMP( keyid, idx->keyid ) ) {
            *r_off = idx->offset;
            break; 
        }
        else if( fpr && !memcmp( idx->fpr, fpr, 20 ) ) {
            *r_off = idx->offset;
            break; 
        }
        cdk_free( idx );
        idx = NULL; 
    }
    cdk_free( idx );
    return *r_off != 0xFFFFFFFF ? 0 : CDK_EOF;
}


/**
 * cdk_keydb_new:
 * @r_hd: handle to store the new keydb object
 * @type: type of the keyring
 * @data: data which depends on the keyring type
 * @count: length of the data
 *
 * Create a new keydb object
 **/
cdk_error_t
cdk_keydb_new( cdk_keydb_hd_t * r_hd, int type, void * data, size_t count )
{
    cdk_keydb_hd_t hd;

    if( !r_hd )
        return CDK_Inv_Value;
    
    hd = cdk_calloc( 1, sizeof *hd );
    if( !hd )
        return CDK_Out_Of_Core;
  
    switch( type ) {
    case CDK_DBTYPE_PK_KEYRING:
    case CDK_DBTYPE_SK_KEYRING:
        hd->name = cdk_strdup( data );
        if( !hd->name ) {
            cdk_free( hd );
            return CDK_Out_Of_Core;
        }
        break;
      
    case CDK_DBTYPE_DATA:
        hd->buf = cdk_stream_tmp_from_mem( data, count );
        if( !hd->buf ) {
            cdk_free( hd );
            return CDK_Out_Of_Core;
        }
        break;

    default:
        cdk_free( hd );
        return CDK_Inv_Mode;
    }
    hd->type = type;
    if( type == CDK_DBTYPE_SK_KEYRING )
        hd->secret = 1;
    *r_hd = hd;
    return 0;
}


/**
 * cdk_keydb_free:
 * @hd: the keydb object
 *
 * Free the keydb object.
 **/
void
cdk_keydb_free( cdk_keydb_hd_t hd )
{
    if( !hd )
        return;
    if( hd->isopen && hd->name ) {
        hd->isopen = 0;
        cdk_free( hd->name );
        hd->name = NULL;
        cdk_stream_close( hd->buf );
        hd->buf = NULL;
    }
    if( !hd->secret ) {
        cdk_stream_close( hd->idx );
        hd->idx = NULL;
    }
    hd->no_cache = 0;
    hd->secret = 0;
    keydb_cache_free( hd->cache );
    hd->cache = NULL;
    keydb_search_free( hd->dbs );
    hd->dbs = NULL;
    cdk_free( hd );
}


/**
 * cdk_keydb_open:
 * @hd: keydb object
 * @ret_kr: the STREAM object which contains the data of the keyring
 *
 * Open a STREAM with the contents of the keyring from @hd
 **/
cdk_error_t
cdk_keydb_open( cdk_keydb_hd_t hd, cdk_stream_t * ret_kr )
{
    int rc = 0, ec;

    if( !hd || !ret_kr )
        return CDK_Inv_Value;

    if( hd->type == CDK_DBTYPE_DATA && hd->buf )
        cdk_stream_seek( hd->buf, 0 );
    else if( hd->type == CDK_DBTYPE_PK_KEYRING
             || hd->type == CDK_DBTYPE_SK_KEYRING ) {
        if( !hd->isopen && hd->name ) {
            rc = cdk_stream_open( hd->name, &hd->buf );
            if( rc )
                goto leave;
            if( cdk_armor_filter_use( hd->buf ) )
                cdk_stream_set_armor_flag( hd->buf, 0 );
            hd->isopen = 1;
            cdk_free( hd->idx_name );
            hd->idx_name = keydb_idx_mkname( hd->name );
            if( !hd->idx_name ) {
                rc = CDK_Out_Of_Core;
                goto leave;
            }
            ec = cdk_stream_open( hd->idx_name, &hd->idx );
            if( ec && !hd->secret ) {
                rc = keydb_idx_build( hd->name );
                if( !rc )
                    rc = cdk_stream_open( hd->idx_name, &hd->idx );
                if( !rc )
                    _cdk_log_debug( "create key index table\n" );
                if( rc ) {
                    /* this is no real error, it just means we can't create
                       the index at the given directory. maybe we've no write
                       access. in this case, we simply disable the index. */
                    _cdk_log_debug( "disable key index table\n" );
                    rc = 0;
                    hd->no_cache = 1;
                }
            }
        }
        else {
            /* We use the cache to search keys, so we always rewind the
               STREAM. Except when the _NEXT search mode is used because
               this mode is an enumeration and no seeking is needed. */
            if( !hd->search ||
                (hd->search && hd->dbs->type != CDK_DBSEARCH_NEXT) )
                cdk_stream_seek( hd->buf, 0 );
        }
    }
    else
        return CDK_Inv_Mode;
  
 leave:
    if( rc ) {
        cdk_stream_close( hd->buf );
        hd->buf = NULL;
    }
    *ret_kr = hd->buf;
    return rc;
}


static int
find_by_keyid( cdk_kbnode_t knode, cdk_dbsearch_t ks )
{
    cdk_kbnode_t node;
    u32 keyid[2];
    int found = 0;

    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
            || node->pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY
            || node->pkt->pkttype == CDK_PKT_SECRET_KEY
            || node->pkt->pkttype == CDK_PKT_SECRET_SUBKEY ) {
            _cdk_pkt_get_keyid( node->pkt, keyid );
            switch( ks->type ) {
            case CDK_DBSEARCH_SHORT_KEYID:
                if( keyid[1] == ks->u.keyid[1] ) {
                    found = 1;
                    break;
                }
                break;

            case CDK_DBSEARCH_KEYID:
                if( KEYID_CMP( keyid, ks->u.keyid ) ) {
                    found = 1;
                    break;
                }
                break;

            default: /* invalid mode */
                return 0;
            }
        }
    }
    return found;
}


static int
find_by_fpr( cdk_kbnode_t knode, cdk_dbsearch_t ks )
{
    cdk_kbnode_t node;
    int found = 0;
    byte fpr[20];
  
    if( ks->type != CDK_DBSEARCH_FPR )
        return found;

    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
            || node->pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY
            || node->pkt->pkttype == CDK_PKT_SECRET_KEY
            || node->pkt->pkttype == CDK_PKT_SECRET_SUBKEY ) {
            _cdk_pkt_get_fingerprint( node->pkt, fpr );
            if( !memcmp( ks->u.fpr, fpr, 20 ) ) {
                found = 1;
                break;
            }
        }
    }
    return found;
}


static int
find_by_pattern( cdk_kbnode_t knode, cdk_dbsearch_t ks )
{
    cdk_kbnode_t node;
    size_t uidlen;
    char * name;
    int found = 0;

    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype != CDK_PKT_USER_ID )
            continue;
        uidlen = node->pkt->pkt.user_id->len;
        name = node->pkt->pkt.user_id->name;
        switch( ks->type ) {
        case CDK_DBSEARCH_EXACT:
            if( name && (strlen( ks->u.pattern ) == uidlen
                         && !strncmp( ks->u.pattern, name, uidlen ) ) ) {
                found = 1;
                break;
            }
            break;

        case CDK_DBSEARCH_SUBSTR:
            if( uidlen > 65536 )
                break;
            if( name && strlen( ks->u.pattern ) > uidlen )
                break;
            if( name && _cdk_memistr( name, uidlen, ks->u.pattern ) ) {
                found = 1;
                break;
            }
            break;

        default: /* invalid mode */
            return 0;
        }
    }
    return found;
}


void
keydb_search_free( cdk_dbsearch_t dbs )
{
    if( !dbs )
        return;
    if( dbs->type == CDK_DBSEARCH_EXACT || dbs->type == CDK_DBSEARCH_SUBSTR )
        cdk_free( dbs->u.pattern );
    dbs->type = 0;
    cdk_free( dbs );    
}


static void
keydb_cache_free( key_table_t cache )
{
    key_table_t c2;

    while( cache ) {
        c2 = cache->next;
        cache->offset = 0;
        keydb_search_free( cache->desc );
        cdk_free( cache );
        cache = c2;
    }
}


static key_table_t
keydb_cache_find( key_table_t cache, cdk_dbsearch_t desc )
{
    key_table_t t;
  
    for( t = cache; t; t = t->next ) {
        if( t->desc->type != desc->type )
            continue;
        switch( t->desc->type ) {
        case CDK_DBSEARCH_SHORT_KEYID:
        case CDK_DBSEARCH_KEYID:
            if( KEYID_CMP( t->desc->u.keyid, desc->u.keyid ) )
                return t;
            break;

        case CDK_DBSEARCH_EXACT:
            if( strlen( t->desc->u.pattern ) == strlen( desc->u.pattern )
                && !strcmp( t->desc->u.pattern, desc->u.pattern ) )
                return t;
            break;

        case CDK_DBSEARCH_SUBSTR:
            if( strstr( t->desc->u.pattern, desc->u.pattern ) )
                return t;
            break;

        case CDK_DBSEARCH_FPR:
            if( !memcmp( t->desc->u.fpr, desc->u.fpr, 20 ) )
                return t;
            break;
        }
    }
    return NULL;
}
  

static int
keydb_cache_add (cdk_keydb_hd_t hd, cdk_dbsearch_t dbs, u32 offset)
{
    key_table_t k;

    if( !hd )
        return CDK_Inv_Value;
    if( hd->ncache > KEYDB_CACHE_ENTRIES )
        return 0;
    k = cdk_calloc( 1, sizeof *k );
    if( !k )
        return CDK_Out_Of_Core;
    k->offset = offset;
    keydb_search_copy( &k->desc, dbs );
    k->next = hd->cache;
    hd->cache = k;
    hd->ncache++;
    _cdk_log_debug ("add entry [o=%d t=%d] to the cache\n", offset, dbs->type);
    return 0;
}

      
static int
keydb_search_copy (cdk_dbsearch_t * r_dst, cdk_dbsearch_t src)
{
    cdk_dbsearch_t dst;
  
    if (!r_dst || !src)
        return CDK_Inv_Value;
    
    dst = cdk_calloc( 1, sizeof *dst );
    if( !dst )
        return CDK_Out_Of_Core;
    dst->type = src->type;
    switch( src->type ) {
    case CDK_DBSEARCH_EXACT:
    case CDK_DBSEARCH_SUBSTR:
        dst->u.pattern = cdk_strdup( src->u.pattern );
        if( !dst->u.pattern )
            return CDK_Out_Of_Core;
        break;

    case CDK_DBSEARCH_SHORT_KEYID:
    case CDK_DBSEARCH_KEYID:
        dst->u.keyid[0] = src->u.keyid[0];
        dst->u.keyid[1] = src->u.keyid[1];
        break;

    case CDK_DBSEARCH_FPR:
        memcpy( dst->u.fpr, src->u.fpr, 20 );
        break;
    }
    *r_dst = dst;
    return 0;
}


/**
 * cdk_keydb_search_start:
 * @db: key database handle
 * @type: specifies the search type
 * @desc: description which depends on the type
 *
 * Create a new keydb search object.
 **/
cdk_error_t
cdk_keydb_search_start( cdk_keydb_hd_t db, int type, void * desc )
{
    cdk_dbsearch_t dbs;
    u32 * keyid;
    char * p, tmp[3];
    int i;

    if( !db )
        return CDK_Inv_Value;
    if( type != CDK_DBSEARCH_NEXT && !desc )
        return CDK_Inv_Mode;
    
    dbs = cdk_calloc( 1, sizeof *dbs );
    if( !dbs )
        return CDK_Out_Of_Core;
    dbs->type = type;
    switch( type ) {
    case CDK_DBSEARCH_EXACT:
    case CDK_DBSEARCH_SUBSTR:
        cdk_free( dbs->u.pattern );
        dbs->u.pattern = cdk_strdup( desc );
        if( !dbs->u.pattern ) {
            cdk_free( dbs );
            return CDK_Out_Of_Core;
        }
        break;

    case CDK_DBSEARCH_SHORT_KEYID:
        keyid = desc;
        dbs->u.keyid[1] = keyid[0];
        break;
      
    case CDK_DBSEARCH_KEYID:
        keyid = desc;
        dbs->u.keyid[0] = keyid[0];
        dbs->u.keyid[1] = keyid[1];
        break;

    case CDK_DBSEARCH_FPR:
        memcpy( dbs->u.fpr, desc, 20 );
        break;

    case CDK_DBSEARCH_NEXT:
        break;

    case CDK_DBSEARCH_AUTO:
        /* override the type with the actual db search type. */
        dbs->type = classify_data( desc, strlen( desc ) );
        switch( dbs->type ) {
        case CDK_DBSEARCH_SUBSTR:
        case CDK_DBSEARCH_EXACT:
            cdk_free( dbs->u.pattern );
            p = dbs->u.pattern = cdk_strdup( desc );
            if( !p ) {
                cdk_free( dbs );
                return CDK_Out_Of_Core;
            }
            break;

        case CDK_DBSEARCH_SHORT_KEYID:
        case CDK_DBSEARCH_KEYID:
            p = desc;
            if( !strncmp( p, "0x", 2 ) )
                p += 2;
            if( strlen( p ) == 8 ) {
                dbs->u.keyid[0] = 0;
                dbs->u.keyid[1] = strtoul( p, NULL, 16 );
            }
            else if( strlen( p ) == 16 ) {
                dbs->u.keyid[0] = strtoul( p    , NULL, 16 );
                dbs->u.keyid[1] = strtoul( p + 8, NULL, 16 );
            }
            else { /* should never happen */
                cdk_free( dbs );
                return CDK_Inv_Mode;
            }
            break;

        case CDK_DBSEARCH_FPR:
            p = desc;
            if( strlen( p ) != 40 ) {
                cdk_free( dbs );
                return CDK_Inv_Mode;
            }
            for( i = 0; i < 20; i++ ) {
                tmp[0] = p[2*i];
                tmp[1] = p[2*i+1];
                tmp[2] = 0x00;
                dbs->u.fpr[i] = strtoul( tmp, NULL, 16 );
            }
            break;
        }
        break;

    default:
        cdk_free( dbs );
        return CDK_Inv_Mode;
    }
    keydb_search_free( db->dbs );
    db->dbs = dbs;
    return 0;
}


static int
keydb_pos_from_cache( cdk_keydb_hd_t hd, cdk_dbsearch_t ks,
                      int * r_cache_hit, u32 * r_off )
{
    key_table_t c;
    u32 off = 0;
    int cache_hit = 0;

    if( !hd || !r_cache_hit || !r_off )
        return CDK_Inv_Value;
  
    c = keydb_cache_find( hd->cache, ks );
    if( c ) {
        _cdk_log_debug( "found entry in cache.\n" );
        cache_hit = 1;
        off = c->offset;
    }

    if( hd->idx && !c ) {
        if( ks->type == CDK_DBSEARCH_KEYID ) {
            if( keydb_idx_search( hd->idx, ks->u.keyid, NULL, &off ) )
                return CDK_Error_No_Key;
            _cdk_log_debug( "found keyid entry in idx table.\n" );
            cache_hit = 1;
        }
        else if( ks->type == CDK_DBSEARCH_FPR ) {
            if( keydb_idx_search( hd->idx, NULL, ks->u.fpr, &off ) )
                return CDK_Error_No_Key;
            _cdk_log_debug( "found fpr entry in idx table.\n" );
            cache_hit = 1;
        }
    }
    *r_off = off;
    *r_cache_hit = cache_hit;
    return 0;
}


/**
 * cdk_keydb_search:
 * @hd: the keydb object
 * @ret_key: kbnode object to store the key
 *
 * Search for a key in the given keyring.  If the key was found,
 * @ret_key contains the key data.
 **/
cdk_error_t
cdk_keydb_search( cdk_keydb_hd_t hd, cdk_kbnode_t * ret_key )
{
    cdk_stream_t kr = NULL;
    cdk_kbnode_t knode = NULL;
    cdk_dbsearch_t ks;
    u32 off = 0;
    size_t pos = 0;
    int key_found = 0, cache_hit = 0;
    int rc = 0;

    if( !hd || !ret_key )
        return CDK_Inv_Value;

    *ret_key = NULL;
    hd->search = 1;
    rc = cdk_keydb_open( hd, &kr );
    if( rc )
        return rc;
    rc = keydb_pos_from_cache( hd, hd->dbs, &cache_hit, &off );
    if( rc )
        return rc;
    
    ks = hd->dbs;
    while( !key_found && !rc ) {
        if( cache_hit && ks->type != CDK_DBSEARCH_NEXT )
            cdk_stream_seek( kr, off );
        pos = cdk_stream_tell( kr );
        rc = cdk_keydb_get_keyblock( kr, &knode );
        if( rc ) {
            if( rc == CDK_EOF && knode )
                rc = 0;
            if( !knode && rc == CDK_EOF )
                rc = CDK_Error_No_Key;
            if( rc )
                break;
        }

        switch( ks->type ) {
        case CDK_DBSEARCH_SHORT_KEYID:
        case CDK_DBSEARCH_KEYID:
            key_found = find_by_keyid( knode, ks );
            break;

        case CDK_DBSEARCH_FPR:
            key_found = find_by_fpr( knode, ks );
            break;
          
	case CDK_DBSEARCH_EXACT:
	case CDK_DBSEARCH_SUBSTR:
            key_found = find_by_pattern( knode, ks );
            break;

        case CDK_DBSEARCH_NEXT:
            key_found = knode? 1 : 0;
            break;
	}

        if( key_found ) {
            if( !keydb_cache_find( hd->cache, ks ) )
                keydb_cache_add( hd, ks, pos );
            break;
        }

        cdk_kbnode_release( knode );
        knode = NULL;
    }

    hd->search = 0;
    *ret_key = key_found? knode : NULL;
    return rc;
}


cdk_error_t
cdk_keydb_get_bykeyid( cdk_keydb_hd_t hd, u32 * keyid, cdk_kbnode_t * ret_pk )
{
    int rc;

    if( !hd || !keyid || !ret_pk )
        return CDK_Inv_Value;

    rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_KEYID, keyid );
    if( !rc )
        rc = cdk_keydb_search( hd, ret_pk );
    return rc;
}


cdk_error_t
cdk_keydb_get_byfpr( cdk_keydb_hd_t hd, const byte * fpr, cdk_kbnode_t * r_pk )
{
    int rc;

    if( !hd || !fpr || !r_pk )
        return CDK_Inv_Value;

    rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_FPR, (byte *)fpr );
    if( !rc )
        rc = cdk_keydb_search( hd, r_pk );
    return rc;
}


cdk_error_t
cdk_keydb_get_bypattern( cdk_keydb_hd_t hd, const char * patt,
			 cdk_kbnode_t * ret_pk )
{
    int rc;

    if( !hd || !patt || !ret_pk )
        return CDK_Inv_Value;

    rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_SUBSTR, (char *)patt );
    if( !rc )
        rc = cdk_keydb_search( hd, ret_pk );
    return rc;
}


static int
keydb_check_key( cdk_packet_t pkt )
{
    cdk_pkt_pubkey_t pk;
    int is_sk = 0, valid = 0;
  
    if( pkt->pkttype == CDK_PKT_PUBLIC_KEY
        || pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY )
        pk = pkt->pkt.public_key;
    else if( pkt->pkttype == CDK_PKT_SECRET_KEY
             || pkt->pkttype == CDK_PKT_SECRET_SUBKEY ) {
        pk = pkt->pkt.secret_key->pk;
        is_sk = 1;
    }
    else
        return 0;
    valid = !pk->is_revoked && !pk->has_expired;
    if( is_sk )
        return valid;
    return valid && !pk->is_invalid;
}


static cdk_kbnode_t
keydb_find_byusage( cdk_kbnode_t root, int req_usage, int is_pk )
{
    cdk_kbnode_t node;
    int pkttype = 0, req_type = 0;

    req_type = is_pk? CDK_PKT_PUBLIC_KEY : CDK_PKT_SECRET_KEY;
    if( !req_usage )
        return cdk_kbnode_find( root, req_type );

    node = cdk_kbnode_find( root, req_type );
    if( node && !keydb_check_key( node->pkt ) )
        return NULL;

    /* xxx: if there are more subkeys, use the one with the requested
            usage and the newest timestamp. */
    for( node = root; node; node = node->next ) {
        pkttype = node->pkt->pkttype;
        if( is_pk && (node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
                      || node->pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY)
            && keydb_check_key( node->pkt )
            && (node->pkt->pkt.public_key->pubkey_usage & req_usage) )
            return node;
        if( !is_pk && (node->pkt->pkttype == CDK_PKT_SECRET_KEY
                       || node->pkt->pkttype == CDK_PKT_SECRET_SUBKEY)
            && keydb_check_key( node->pkt )
            && (node->pkt->pkt.secret_key->pk->pubkey_usage & req_usage) )
            return node;
    }
    return NULL;
}


static cdk_kbnode_t
keydb_find_bykeyid( cdk_kbnode_t root, u32 * keyid )
{
    cdk_kbnode_t node;
    u32 kid[2];

    for( node = root; node; node = node->next ) {
        _cdk_pkt_get_keyid (node->pkt, kid);
        if( kid[1] == keyid[1] )
            return node;
    }
    return NULL;
}


int
_cdk_keydb_get_sk_byusage( cdk_keydb_hd_t hd, const char * name,
                           cdk_pkt_seckey_t* ret_sk, int usage )
{
    cdk_kbnode_t knode = NULL, node = NULL;
    cdk_pkt_seckey_t sk = NULL;
    int rc = 0;

    if( !ret_sk || !usage )
        return CDK_Inv_Value;
    if( !hd )
        return CDK_Error_No_Keyring;

    rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_AUTO, (char *)name );
    if( !rc )
        rc = cdk_keydb_search( hd, &knode );
    if( rc )
        goto leave;
    node = keydb_find_byusage( knode, usage, 0 );
    if( !node ) {
        rc = CDK_Unusable_Key;
        goto leave;
    }

    sk = node->pkt->pkt.secret_key;
    _cdk_kbnode_clone( node );
    cdk_kbnode_release( knode );

leave:
    *ret_sk = sk;
    return rc;
}


int
_cdk_keydb_get_pk_byusage( cdk_keydb_hd_t hd, const char * name,
                           cdk_pkt_pubkey_t* ret_pk, int usage )
{
    cdk_kbnode_t knode, node = NULL;
    cdk_pkt_pubkey_t pk = NULL;
    const char * s;
    int rc = 0;

    if( !ret_pk || !usage )
        return CDK_Inv_Value;
    if( !hd )
        return CDK_Error_No_Keyring;

    rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_AUTO, (char *)name );
    if( !rc )
        rc = cdk_keydb_search( hd, &knode );
    if( rc )
        goto leave;    
    node = keydb_find_byusage( knode, usage, 1 );
    if( !node ) {
        rc = CDK_Unusable_Key;
        goto leave;
    }

    _cdk_copy_pubkey( &pk, node->pkt->pkt.public_key );
    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype == CDK_PKT_USER_ID ) {
            s = node->pkt->pkt.user_id->name;
            if( pk && !pk->uid && _cdk_memistr( s, strlen( s ), name ) ) {
                _cdk_copy_userid( &pk->uid, node->pkt->pkt.user_id );
                break;
	    }
	}
    }
    cdk_kbnode_release( knode );

leave:
    *ret_pk = pk;
    return rc;
}


cdk_error_t
cdk_keydb_get_pk( cdk_keydb_hd_t hd, u32 * keyid, cdk_pkt_pubkey_t* r_pk )
{
    cdk_kbnode_t knode = NULL, node = NULL;
    cdk_pkt_pubkey_t pk = NULL;
    int rc = 0;

    if( !keyid || !r_pk )
        return CDK_Inv_Value;
    if( !hd )
        return CDK_Error_No_Keyring;

    rc = cdk_keydb_search_start( hd, !keyid[0]?
                                 CDK_DBSEARCH_SHORT_KEYID : CDK_DBSEARCH_KEYID,
                                 keyid );
    if( !rc )
        rc = cdk_keydb_search( hd, &knode );
    if( rc )
        goto leave;
    node = keydb_find_bykeyid( knode, keyid );
    if( !node ) {
        rc = CDK_Error_No_Key;
        goto leave;
    }
    _cdk_copy_pubkey( &pk, node->pkt->pkt.public_key );
    cdk_kbnode_release( knode );

leave:
    *r_pk = pk;
    return rc;
}


cdk_error_t
cdk_keydb_get_sk( cdk_keydb_hd_t hd, u32 * keyid, cdk_pkt_seckey_t* ret_sk )
{
    cdk_kbnode_t snode, node;
    cdk_pkt_seckey_t sk = NULL;
    int rc = 0;

    if( !keyid || !ret_sk )
        return CDK_Inv_Value;
    if( !hd )
        return CDK_Error_No_Keyring;

    rc = cdk_keydb_get_bykeyid( hd, keyid, &snode );
    if( rc )
        goto leave;

    node = keydb_find_bykeyid( snode, keyid );
    if( !node ) {
        rc = CDK_Error_No_Key;
        goto leave;
    }

    sk = node->pkt->pkt.secret_key;
    _cdk_kbnode_clone( node );
    cdk_kbnode_release( snode );

 leave:
    *ret_sk = sk;
    return rc;
}


static int
is_selfsig( cdk_kbnode_t node, u32 * keyid )
{
    cdk_pkt_signature_t sig;
    
    if( node->pkt->pkttype != CDK_PKT_SIGNATURE )
        return 0;
    sig = node->pkt->pkt.signature;
    if( (sig->sig_class == 0x13 || sig->sig_class == 0x10) &&
        sig->keyid[0] == keyid[0] && sig->keyid[1] == keyid[1] )
        return 1;
    return 0;
}

    
static int
keydb_merge_selfsig( cdk_kbnode_t key, u32 * keyid )
{
    cdk_kbnode_t node, kbnode, unode;
    cdk_subpkt_t s = NULL;
    cdk_pkt_signature_t sig = NULL;
    cdk_pkt_userid_t uid = NULL;
    const byte * symalg = NULL, * hashalg = NULL, * compalg = NULL;
    size_t nsymalg = 0, nhashalg = 0, ncompalg = 0, n = 0;
    int key_usage = 0, key_expire = 0;

    if (!key)
        return CDK_Inv_Value;

    for( node = key; node; node = node->next ) {
        if( !is_selfsig( node, keyid ) )
            continue;
        unode = cdk_kbnode_find_prev( key, node, CDK_PKT_USER_ID );
        if( !unode )
            return CDK_Error_No_Key;
        uid = unode->pkt->pkt.user_id;
        sig = node->pkt->pkt.signature;
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_PRIMARY_UID );
        if( s )
            uid->is_primary = 1;
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_FEATURES );
        if( s && s->size == 1 && s->d[0] & 0x01 )
            uid->mdc_feature = 1;
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_KEY_EXPIRE );
        if( s && s->size == 4 )
            key_expire = _cdk_buftou32( s->d );
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_KEY_FLAGS );
        if( s ) {
            if( s->d[0] & 3 ) /* cert + sign data */
                key_usage |= PK_USAGE_SIGN;
            if( s->d[0] & 12 ) /* encrypt comm. + storage */
                key_usage |= PK_USAGE_ENCR;
        }
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_PREFS_SYM );
        if( s ) {
            symalg = s->d;
            nsymalg = s->size;
            n += s->size + 1;
        }
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_PREFS_HASH );
        if( s ) {
            hashalg = s->d;
            nhashalg = s->size;
            n += s->size + 1;
        }
        s = cdk_subpkt_find( sig->hashed, CDK_SIGSUBPKT_PREFS_ZIP );
        if( s ) {
            compalg = s->d;
            ncompalg = s->size;
            n += s->size + 1;
        }
        if( !n || !hashalg || !compalg || !symalg )
            uid->prefs = NULL;
        else {
            uid->prefs = cdk_calloc( 1, sizeof (*uid->prefs) * (n + 1) );
            if( !uid->prefs )
                return CDK_Out_Of_Core;
            n = 0;
            for( ; nsymalg; nsymalg--, n++ ) {
                uid->prefs[n].type = CDK_PREFTYPE_SYM;
                uid->prefs[n].value = *symalg++;
            }
            for( ; nhashalg; nhashalg--, n++ ) {
                uid->prefs[n].type = CDK_PREFTYPE_HASH;
                uid->prefs[n].value = *hashalg++;
            }
            for( ; ncompalg; ncompalg--, n++ ) {
                uid->prefs[n].type = CDK_PREFTYPE_ZIP;
                uid->prefs[n].value = *compalg++;
            }
            /* end of list marker */
            uid->prefs[n].type = CDK_PREFTYPE_NONE;
            uid->prefs[n].value = 0;
            uid->prefs_size = n;

            kbnode = cdk_kbnode_find_prev( key, node, CDK_PKT_PUBLIC_KEY );
            if( kbnode ) {
                cdk_pkt_pubkey_t pk = kbnode->pkt->pkt.public_key;
                if( uid->prefs && n ) {
                    pk->prefs = _cdk_copy_prefs( uid->prefs );
                    pk->prefs_size = n;
                }
                if( key_expire ) {
                    pk->expiredate = pk->timestamp + key_expire;
                    pk->has_expired = pk->expiredate> _cdk_timestamp ()?0 :1;
                }
                if( key_usage && !pk->pubkey_usage )
                    pk->pubkey_usage = key_usage;
                pk->is_invalid = 0;
            }
        }
    }
    return 0;
}


static int
keydb_parse_allsigs( cdk_kbnode_t knode, cdk_keydb_hd_t hd, int check )
{
    cdk_kbnode_t node, kb;
    cdk_pkt_signature_t sig;
    cdk_pkt_pubkey_t pk;
    struct cdk_subpkt_s * s = NULL;
    u32 expiredate = 0, curtime = _cdk_timestamp ();
    u32 keyid[2];
    int rc = 0;

    if( !knode )
        return CDK_Inv_Value;
    if( check && !hd )
        return CDK_Inv_Mode;

    kb = cdk_kbnode_find( knode, CDK_PKT_SECRET_KEY );
    if( kb )
        return 0;

    /* reset */
    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype == CDK_PKT_USER_ID )
            node->pkt->pkt.user_id->is_revoked = 0;
        else if( node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
                 || node->pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY )
            node->pkt->pkt.public_key->is_revoked = 0;
    }

    kb = cdk_kbnode_find( knode, CDK_PKT_PUBLIC_KEY );
    if( !kb )
        return CDK_Inv_Packet;
    cdk_pk_get_keyid( kb->pkt->pkt.public_key, keyid );
  
    for( node = knode; node; node = node->next) {
        if( node->pkt->pkttype == CDK_PKT_SIGNATURE ) {
            sig = node->pkt->pkt.signature;
            /* Revocation certificates for primary keys */
            if( sig->sig_class == 0x20 ) {
                kb = cdk_kbnode_find_prev( knode, node, CDK_PKT_PUBLIC_KEY );
                if( kb ) {
                    kb->pkt->pkt.public_key->is_revoked = 1;
                    if( check )
                        _cdk_pk_check_sig (hd, kb, node, NULL);
		}
                else
                    return CDK_Error_No_Key;
	    }
            /* Revocation certificates for subkeys */
            else if( sig->sig_class == 0x28 ) {
                kb = cdk_kbnode_find_prev (knode, node, CDK_PKT_PUBLIC_SUBKEY);
                if( kb ) {
                    kb->pkt->pkt.public_key->is_revoked = 1;
                    if( check )
                        _cdk_pk_check_sig( hd, kb, node, NULL );
		}
                else
                    return CDK_Error_No_Key;
	    }
            /* Revocation certifcates for user ID's */
            else if( sig->sig_class == 0x30 ) {
                if( sig->keyid[0] != keyid[0] || sig->keyid[1] != keyid[1] )
                    continue; /* revokes an earlier signature, no userID. */
                kb = cdk_kbnode_find_prev (knode, node, CDK_PKT_USER_ID);
                if( kb ) {
                    kb->pkt->pkt.user_id->is_revoked = 1;
                    if( check )
                        _cdk_pk_check_sig( hd, kb, node, NULL );
		}
                else
                    return CDK_Error_No_Key;
	    }
            /* Direct certificates for primary keys */
            else if( sig->sig_class == 0x1F ) {
                kb = cdk_kbnode_find_prev( knode, node, CDK_PKT_PUBLIC_KEY );
                if( kb ) {
                    pk = kb->pkt->pkt.public_key;
                    pk->is_invalid = 0;
                    s = cdk_subpkt_find( node->pkt->pkt.signature->hashed,
                                         CDK_SIGSUBPKT_KEY_EXPIRE );
                    if( s ) {
                        expiredate = _cdk_buftou32( s->d );
                        pk->expiredate = pk->timestamp + expiredate;
                        pk->has_expired = pk->expiredate > curtime? 0 : 1;
		    }
                    if( check )
                        _cdk_pk_check_sig( hd, kb, node, NULL );
		}
                else
                    return CDK_Error_No_Key;
	    }
            /* Direct certificates for subkeys */
            else if( sig->sig_class == 0x18 ) {
                kb = cdk_kbnode_find_prev( knode, node, CDK_PKT_PUBLIC_SUBKEY);
                if( kb ) {
                    pk = kb->pkt->pkt.public_key;
                    pk->is_invalid = 0;
                    s = cdk_subpkt_find( node->pkt->pkt.signature->hashed,
                                         CDK_SIGSUBPKT_KEY_EXPIRE );
                    if( s ) {
                        expiredate = _cdk_buftou32( s->d );
                        pk->expiredate = pk->timestamp + expiredate;
                        pk->has_expired = pk->expiredate > curtime? 0 : 1;
		    }
                    if( check )
                        _cdk_pk_check_sig( hd, kb, node, NULL );
		}
                else
                    return CDK_Error_No_Key;
	    }
	}
    }
    node = cdk_kbnode_find( knode, CDK_PKT_PUBLIC_KEY );
    if( node && node->pkt->pkt.public_key->version == 3 ) {
        /* v3 public keys have no additonal signatures for the key directly.
           we say the key is valid when we have at least a self signature. */
        pk = node->pkt->pkt.public_key;
        for( node = knode; node; node = node->next ) {
            if( is_selfsig( node, keyid ) ) {
                pk->is_invalid = 0;
                break;
            }
        }
    }
    if( node && (node->pkt->pkt.public_key->is_revoked
                 || node->pkt->pkt.public_key->has_expired) ) {
        /* if the primary key has been revoked, mark all subkeys as invalid
           because without a primary key they are not useable */
        for( node = knode; node; node = node->next ) {
            if( node->pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY )
                node->pkt->pkt.public_key->is_invalid = 1;
        }
    }
    return rc;
}


cdk_error_t
cdk_keydb_get_keyblock( cdk_stream_t inp, cdk_kbnode_t * r_knode )
{
    cdk_packet_t pkt = NULL;
    cdk_kbnode_t knode = NULL, node = NULL;
    cdk_desig_revoker_t revkeys = NULL;
    u32 keyid[2], main_keyid[2];
    int rc = 0, old_off;
    int key_seen = 0, got_key = 0;

    if( !inp || !r_knode )
        return CDK_Inv_Value;

    memset( keyid, 0, sizeof keyid );
    memset( main_keyid, 0, sizeof main_keyid );
  
    while( 1 ) {
        pkt = cdk_calloc( 1, sizeof *pkt );
        if( !pkt )
            return CDK_Out_Of_Core;
        old_off = cdk_stream_tell( inp );
        rc = cdk_pkt_read( inp, pkt );
        if( rc )
            break;
        if( pkt->pkttype == CDK_PKT_PUBLIC_KEY
            || pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY
            || pkt->pkttype == CDK_PKT_SECRET_KEY
            || pkt->pkttype == CDK_PKT_SECRET_SUBKEY) {
            if (key_seen && (pkt->pkttype == CDK_PKT_PUBLIC_KEY
                             || pkt->pkttype == CDK_PKT_SECRET_KEY) ) {
                cdk_stream_seek( inp, old_off );
                break;
	    }
            if( pkt->pkttype == CDK_PKT_PUBLIC_KEY
                || pkt->pkttype == CDK_PKT_SECRET_KEY ) {
                _cdk_pkt_get_keyid( pkt, main_keyid );
                key_seen = 1;
            }
            else if( pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY
                     || pkt->pkttype == CDK_PKT_SECRET_SUBKEY ) {
                if( pkt->pkttype == CDK_PKT_PUBLIC_SUBKEY ) {
                    pkt->pkt.public_key->main_keyid[0] = main_keyid[0];
                    pkt->pkt.public_key->main_keyid[1] = main_keyid[1];
		}
                else {
                    pkt->pkt.secret_key->main_keyid[0] = main_keyid[0];
                    pkt->pkt.secret_key->main_keyid[1] = main_keyid[1];
		}
	    }
            /* we save this for the signature */
            _cdk_pkt_get_keyid( pkt, keyid );
            got_key = 1;
	}
        else if( pkt->pkttype == CDK_PKT_USER_ID )
            ;
        else if( pkt->pkttype == CDK_PKT_SIGNATURE ) {
            pkt->pkt.signature->key[0] = keyid[0];
            pkt->pkt.signature->key[1] = keyid[1];
            if( pkt->pkt.signature->sig_class == 0x1F &&
                pkt->pkt.signature->revkeys )
                revkeys = pkt->pkt.signature->revkeys;
	}
        node = cdk_kbnode_new( pkt );
        if( !knode )
            knode = node;
        else
            _cdk_kbnode_add( knode, node );
    }

    if( got_key ) {
        keydb_merge_selfsig( knode, main_keyid );
        rc = keydb_parse_allsigs( knode, NULL, 0 );
        if( revkeys ) {
            node = cdk_kbnode_find( knode, CDK_PKT_PUBLIC_KEY );
            if( node )
                node->pkt->pkt.public_key->revkeys = revkeys;
        }
    }
    *r_knode = got_key ? knode : NULL;
    return rc;
}


cdk_error_t
cdk_keydb_pk_cache_sigs( cdk_kbnode_t pk, cdk_keydb_hd_t hd )
{
    if( !pk || !hd )
        return CDK_Inv_Value;
    return keydb_parse_allsigs( pk, hd, 1 );
}


static int
classify_data( const byte * buf, size_t len )
{
    int type = 0;
    int i;

    if( buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X') ) { /* hex prefix */
        buf += 2;
        len -= 2;
    }

    if( len == 8 || len == 16 || len == 40 ) {
        for( i = 0; i < len; i++ ) {
            if( !isxdigit( buf[i] ) )
                break;
        }
        if( i == len ) {
            switch( len ) {
            case 8: type = CDK_DBSEARCH_SHORT_KEYID; break;
            case 16: type = CDK_DBSEARCH_KEYID; break;
            case 40: type = CDK_DBSEARCH_FPR; break;
            }
        }
    }
    if( !type )
        type = CDK_DBSEARCH_SUBSTR;
    return type;
}


cdk_error_t
cdk_keydb_export( cdk_keydb_hd_t hd, cdk_stream_t out, cdk_strlist_t remusr )
{
    cdk_kbnode_t knode, node;
    cdk_strlist_t r;
    int old_ctb = 0;
    int rc = 0;

    for( r = remusr; r; r = r->next ) {
        rc = cdk_keydb_search_start( hd, CDK_DBSEARCH_AUTO, r->d );
        if( !rc )
            rc = cdk_keydb_search( hd, &knode );
        if( rc )
            break;
        for( node = knode; node; node = node->next ) {
            /* those packets are not intended for the real wolrd */
            if( node->pkt->pkttype == CDK_PKT_RING_TRUST )
                continue;
            /* we never export local signed signatures */
            if( node->pkt->pkttype == CDK_PKT_SIGNATURE &&
                !node->pkt->pkt.signature->flags.exportable )
                continue;
            /* filter out invalid signatures */
            if( node->pkt->pkttype == CDK_PKT_SIGNATURE
                && !KEY_CAN_SIGN (node->pkt->pkt.signature->pubkey_algo) )
                continue;
            if( node->pkt->pkttype == CDK_PKT_PUBLIC_KEY
                && node->pkt->pkt.public_key->version == 3 )
                old_ctb = 1;
            node->pkt->old_ctb = old_ctb;
            rc = cdk_pkt_write( out, node->pkt );
            if( rc )
                break;
	}
        cdk_kbnode_release( knode );
        knode = NULL;
    }
    return rc;
}


static cdk_packet_t
find_key_packet( cdk_kbnode_t knode, int * r_is_sk )
{
    cdk_packet_t pkt;

    pkt = cdk_kbnode_find_packet( knode, CDK_PKT_PUBLIC_KEY );
    if( !pkt ) {
        pkt = cdk_kbnode_find_packet( knode, CDK_PKT_SECRET_KEY );
        if( r_is_sk )
            *r_is_sk = pkt? 1 : 0;
    }
    return pkt;
}


cdk_error_t
cdk_keydb_import( cdk_keydb_hd_t hd, cdk_kbnode_t knode, int *result )
{
    cdk_kbnode_t node, chk = NULL;
    cdk_packet_t pkt;
    cdk_stream_t out;
    u32 keyid[2];
    int rc = 0, is_sk = 0;

    if( !hd || !knode )
        return CDK_Inv_Value;
  
    memset( result, 0, 4 * sizeof (int) );
    pkt = find_key_packet( knode, &is_sk );
    if( !pkt )
        return CDK_Inv_Packet;
    result[is_sk] = 1;
    _cdk_pkt_get_keyid( pkt, keyid );
    cdk_keydb_get_bykeyid( hd, keyid, &chk );
    if( chk ) { /* fixme: search for new signatures */
        cdk_kbnode_release( chk );
        return 0;
    }
  
    if( hd->buf ) {
        cdk_stream_close( hd->buf );
        hd->buf = NULL;
    }

    rc = _cdk_stream_append( hd->name, &out );
    if( rc )
        return rc;
  
    for( node = knode; node; node = node->next ) {
        if( node->pkt->pkttype == CDK_PKT_RING_TRUST )
            continue; /* No uniformed syntax for this packet */
        rc = cdk_pkt_write( out, node->pkt );
        if( rc )
            break;
    }
    if( !rc )
        result[is_sk? 3 : 2] = 1;
    cdk_stream_close( out );
    if( !hd->no_cache )
        cdk_keydb_idx_rebuild( hd );
    return rc;
}


int
cdk_keydb_check_sk( cdk_keydb_hd_t hd, u32 * keyid )
{
    cdk_stream_t db;
    cdk_packet_t pkt;
    u32 kid[2];
    int rc;
    
    if( !hd || !keyid )
        return CDK_Inv_Value;
    if( !hd->secret )
        return CDK_Inv_Mode;
    pkt = cdk_calloc( 1, sizeof * pkt );
    if( !pkt )
        return CDK_Out_Of_Core;
    rc = cdk_keydb_open( hd, &db );
    if( rc )
        return rc;
    cdk_pkt_init( pkt );
    while( !cdk_pkt_read( db, pkt ) ) {
        if( pkt->pkttype != CDK_PKT_SECRET_KEY
            && pkt->pkttype != CDK_PKT_SECRET_SUBKEY )
            goto next;
        cdk_sk_get_keyid( pkt->pkt.secret_key, kid );
        if( KEYID_CMP( kid, keyid ) ) {
            cdk_pkt_free( pkt );
            cdk_free( pkt );
            return 0;
        }
    next:
        cdk_pkt_free( pkt );
        cdk_pkt_init( pkt );
    }
    cdk_free( pkt );
    return CDK_Error_No_Key;
}


/**
 * cdk_listkey_start:
 * @r_ctx: pointer to store the new context
 * @db: the key database handle
 * @patt: string pattern
 * @fpatt: recipients from a stringlist to show
 *
 * Prepare a key listing with the given parameters. Two modes are supported.
 * The first mode uses string pattern to determine if the key should be
 * returned or not. The other mode uses a string list to request the key
 * which should be listed.
 **/
cdk_error_t
cdk_listkey_start( cdk_listkey_t * r_ctx, cdk_keydb_hd_t db,
                   const char * patt, cdk_strlist_t fpatt )
{
    cdk_listkey_t ctx;
    cdk_stream_t inp;
    int rc;
    
    if( !r_ctx || !db )
        return CDK_Inv_Value;
    if( (patt && fpatt) || (!patt && !fpatt) )
        return CDK_Inv_Mode;
    rc = cdk_keydb_open( db, &inp );
    if( rc )
        return rc;
    ctx = cdk_calloc( 1, sizeof * ctx );
    if( !ctx )
        return CDK_Out_Of_Core;
    ctx->db = db;
    ctx->inp = inp;
    if( patt ) {
        ctx->u.patt = cdk_strdup( patt );
        if( !ctx->u.patt )
            return CDK_Out_Of_Core;
    }
    else if( fpatt ) {
        cdk_strlist_t l;
        for( l = fpatt; l; l = l->next )
            cdk_strlist_add( &ctx->u.fpatt, l->d );
    }
    ctx->type = patt? 1 : 0;
    ctx->init = 1;
    *r_ctx = ctx;
    return 0;
}


/**
 * cdk_listkey_close:
 * @ctx: the list key context
 *
 * Free the list key context.
 **/
void
cdk_listkey_close( cdk_listkey_t ctx )
{
    if( ctx ) {
        if( ctx->type )
            cdk_free( ctx->u.patt );
        else
            cdk_strlist_free( ctx->u.fpatt );
        cdk_free( ctx );
    }
}


/**
 * cdk_listkey_next:
 * @ctx: list key context
 * @ret_key: the pointer to the new key node object
 *
 * Retrieve the next key from the pattern of the key list context.
 **/
cdk_error_t
cdk_listkey_next( cdk_listkey_t ctx, cdk_kbnode_t * ret_key )
{
    if( !ctx || !ret_key )
        return CDK_Inv_Value;
    if( !ctx->init )
        return CDK_Inv_Mode;

    if( ctx->type && ctx->u.patt[0] == '*' )
        return cdk_keydb_get_keyblock( ctx->inp, ret_key );
    else if( ctx->type ) {
        cdk_kbnode_t node;
        struct cdk_dbsearch_s ks;
        int rc;
        
        for( ;; ) {
            rc = cdk_keydb_get_keyblock( ctx->inp, &node );
            if( rc )
                return rc;
            memset( &ks, 0, sizeof ks );
            ks.type = CDK_DBSEARCH_SUBSTR;
            ks.u.pattern = ctx->u.patt;
            if( find_by_pattern( node, &ks ) ) {
                *ret_key = node;
                return 0;
            }
            cdk_kbnode_release( node );
            node = NULL;
        }
    }
    else {
        if( !ctx->t )
            ctx->t = ctx->u.fpatt;
        else if( ctx->t->next )
            ctx->t = ctx->t->next;
        else
            return CDK_EOF;
        return cdk_keydb_get_bypattern( ctx->db, ctx->t->d, ret_key );
    }
    return CDK_General_Error;
}

