/* -*- Mode: C; c-file-style: "bsd" -*-
 * stream.c - provides a STREAM object
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
 * along with OpenCDK; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "stream.h"
#include "types.h"


static int stream_flush( cdk_stream_t s );
static int stream_filter_write( cdk_stream_t s );
static int stream_cache_flush( cdk_stream_t s, FILE * fp );


/**
 * cdk_stream_open: create a new stream based on an existing file.
 * @file: The file to open
 * @ret_s: The new STREAM object
 **/
cdk_error_t
cdk_stream_open( const char * file, cdk_stream_t * ret_s )
{
    cdk_stream_t s;

    if( !file || !ret_s )
        return CDK_Inv_Value;

    _cdk_log_debug( "open stream `%s'\n", file );
    *ret_s = NULL;
    s = cdk_calloc( 1, sizeof *s );
    if( !s )
        return CDK_Out_Of_Core;
    s->fname = cdk_strdup( file );
    if( !s->fname ) {
        cdk_free( s );
        return CDK_Out_Of_Core;
    }
    s->fp = fopen( file, "rb" );
    if( !s->fp ) {
        cdk_free( s->fname );
        cdk_free( s );
        return CDK_File_Error;
    }
    s->flags.write = 0;
    *ret_s = s;
    return 0;
}


/**
 * cdk_stream_new: Create a new stream into into the given file.
 * @file: The name of the new file
 * @ret_s: The new STREAM object
 **/
cdk_error_t
cdk_stream_new( const char * file, cdk_stream_t * ret_s )
{
    cdk_stream_t s;

    if( !ret_s )
        return CDK_Inv_Value;

    _cdk_log_debug( "new stream `%s'\n", file? file : "[temp]" );
    *ret_s = NULL;
    s = cdk_calloc( 1, sizeof *s );
    if( !s )
        return CDK_Out_Of_Core;  
    s->flags.write = 1;
    if( !file )
        s->flags.temp = 1;
    else {
        s->fname = cdk_strdup( file );
        if( !s->fname ) {
            cdk_free( s );
            return CDK_Out_Of_Core;
        }
    }
    s->fp = tmpfile( );
    if( !s->fp ) {
        cdk_free( s->fname );
        cdk_free( s );
        return CDK_File_Error;
    }
    *ret_s = s;
    return 0;
}


/**
 * cdk_stream_create: create a new stream.
 * @file: the filename
 * @ret_s: the object
 *
 * The difference to cdk_stream_new is, that no filtering can be used with
 * this kind of stream and everything is written directly to the stream.
 **/
cdk_error_t
cdk_stream_create( const char * file, cdk_stream_t * ret_s )
{
    cdk_stream_t s;

    if( !file || !ret_s )
        return CDK_Inv_Value;
    
    _cdk_log_debug( "create stream `%s'\n", file );
    *ret_s = NULL;
    s = cdk_calloc( 1, sizeof * s );
    if( !s )
        return CDK_Out_Of_Core;
    s->flags.write = 1;
    s->flags.filtrated = 1;
    s->fname = cdk_strdup( file );
    if( !s->fname ) {
        cdk_free( s );
        return CDK_Out_Of_Core;
    }
    s->fp = fopen( file, "w+b" );
    if( !s->fp ) {
        cdk_free( s->fname );
        cdk_free( s );
        return CDK_Out_Of_Core;
    }
    *ret_s = s;
    return 0;
}
    

cdk_stream_t
cdk_stream_tmp( void )
{
    cdk_stream_t s;
    int rc = cdk_stream_new( NULL, &s );
    if( !rc )
        return s;
    return NULL;
}


cdk_stream_t
cdk_stream_tmp_from_mem( const void * buf, size_t count )
{
    cdk_stream_t s;
    int nwritten;

    s = cdk_stream_tmp( );
    if( !s )
        return NULL;
  
    nwritten = cdk_stream_write( s, buf, count );
    if( nwritten == EOF ) {
        cdk_stream_close( s );
        return NULL;
    }
    cdk_stream_seek( s, 0 );
    return s;
}

  

cdk_stream_t
_cdk_stream_fpopen( FILE * fp, unsigned write_mode )
{
  cdk_stream_t s;

  s = cdk_calloc( 1, sizeof *s );
  if( !s )
    return NULL;
  
  s->fp = fp;
  s->flags.filtrated = 1;
  s->flags.write = write_mode;

  return s;
}


cdk_error_t
_cdk_stream_append( const char * file, cdk_stream_t * ret_s )
{
    cdk_stream_t s;
    FILE * fp;
    int rc;

    if( !ret_s )
        return CDK_Inv_Value;
    rc = cdk_stream_open( file, &s );
    if( rc )
        return rc;
    fp = fopen( file, "a+b" );
    if( !fp ) {
        cdk_stream_close( s );
        return CDK_File_Error;
    }
    fclose( s->fp );
    s->fp = fp;
    s->flags.write = 1;
    *ret_s = s;
    return 0;
}

      
int
cdk_stream_control( cdk_stream_t s, int ctl, int val )
{
    if( !s )
        return CDK_Inv_Value;

    if( val == -1 ) {
        switch( ctl ) {
        case CDK_STREAMCTL_COMPRESSED: return s->flags.compressed;
        }
        return 0;
    }
    switch( ctl ) {
    case CDK_STREAMCTL_DISABLE: s->flags.no_filter = val; break;
    case CDK_STREAMCTL_COMPRESSED: s->flags.compressed = val; break;
    default                   : return CDK_Inv_Mode;
    }
    return 0;
}


cdk_error_t
cdk_stream_flush( cdk_stream_t s )
{
    int rc = 0;
  
    if( !s )
        return CDK_Inv_Value;

    if( !s->flags.filtrated ) {
        if( !cdk_stream_get_length( s ) )
            return 0;
        rc = cdk_stream_seek( s, 0 );
        if( !rc )
            rc = stream_flush( s );
        if( !rc ) {
            rc = stream_filter_write( s );
            if( rc )
                s->error = rc;
        }
        s->flags.filtrated = 1;
    }
    return rc;
}


void
cdk_stream_tmp_set_mode( cdk_stream_t s, int val )
{
    if( s && s->flags.temp )
        s->fmode = val;
}


/**
 * cdk_stream_close: Close a stream and flush all buffers.
 * @s: The STREAM object.
 *
 * This function work different for read or write streams. When the
 * stream is for reading, the filtering is already done and we can
 * simply close the file and all buffers.
 * But for the case it's a write stream, we need to apply all registered
 * filters now. The file is closed in the filter function and not here.
 **/
cdk_error_t
cdk_stream_close( cdk_stream_t s )
{
    struct stream_filter_s * f, * f2;
    int rc = 0;

    if( !s )
        return CDK_Inv_Value;
    
    _cdk_log_debug( "close stream `%s'\n", s->fname? s->fname : "[temp]" );
    
    if( !s->flags.filtrated && !s->error )
        rc = cdk_stream_flush( s );
    if( s->fname || s->flags.temp ) {
        rc = fclose( s->fp );
        s->fp = NULL;
        if( rc )
            rc = CDK_File_Error;
    }
    f = s->filters;
    while( f ) {
        f2 = f->next;
        if( f->fnct )
            f->fnct( f->opaque, STREAMCTL_FREE, NULL, NULL );
        cdk_free( f );
        f = f2;
    }
    if( s->fname ) {
        cdk_free( s->fname );
        s->fname = NULL;
    }
    cdk_free( s );
    return rc;
}


/**
 * cdk_stream_eof: Return if the associated file handle was set to EOF.
 * @s: The STREAM object.
 *
 * This function will only work with read streams.
 **/
int
cdk_stream_eof( cdk_stream_t s )
{
    return s? s->flags.eof : -1;
}


const char *
_cdk_stream_get_fname( cdk_stream_t s )
{
    return s? s->fname : NULL;
}


FILE *
_cdk_stream_get_fp( cdk_stream_t s )
{
    return s? s->fp : NULL;
}


int
_cdk_stream_get_errno( cdk_stream_t s )
{
    return s? s->error : CDK_Inv_Value;
}


/**
 * cdk_stream_get_length: Return the length of the associated file handle.
 * @s: The STREAM object.
 *
 * This file only works for read stream because it's likely that the
 * write stream is not flushed or even no data was inserted.
 **/
unsigned
cdk_stream_get_length( cdk_stream_t s )
{
    struct stat statbuf;
    int rc;

    if( !s )
        return (unsigned)-1;
    
    rc = stream_flush( s );
    if( rc ) {
        s->error = CDK_File_Error;
        return (unsigned)-1;
    }
    if( fstat( fileno( s->fp ), &statbuf ) ) {
        s->error = CDK_File_Error;
        return (unsigned)-1;
    }
    return statbuf.st_size;
}


static struct stream_filter_s *
filter_add2( cdk_stream_t s )
{
    struct stream_filter_s * f;

    assert( s );
    
    f = cdk_calloc( 1, sizeof *f );
    if( !f )
        return NULL;
    f->next = s->filters;
    s->filters = f;
    return f;
}


static struct stream_filter_s *
filter_search( cdk_stream_t s, filter_fnct_t fnc )
{
    struct stream_filter_s * f;

    assert( s );
    
    for( f = s->filters; f; f = f->next ) {
        if( f->fnct == fnc )
            return f;
    }
    return NULL;
}


struct stream_filter_s *
filter_add( cdk_stream_t s, filter_fnct_t fnc, int type )
{
    struct stream_filter_s * f;

    assert( s );
    
    s->flags.filtrated = 0;
    f = filter_search( s, fnc );
    if( f )
        return f;
    f = filter_add2( s );
    if( !f )
        return NULL;
    f->fnct = fnc;
    f->flags.enabled = 1;
    f->tmp = NULL;
    f->type = type;
    switch( type ) {
    case fARMOR    : f->opaque = &f->u.afx; break;
    case fCIPHER   : f->opaque = &f->u.cfx; break;
    case fLITERAL: f->opaque = &f->u.pfx; break;
    case fCOMPRESS : f->opaque = &f->u.zfx; break;
    case fHASH     : f->opaque = &f->u.mfx; break;
    case fTEXT     : f->opaque = &f->u.tfx; break;
    default        : f->opaque = NULL;
    }
    return f;
}


static int
stream_get_mode( cdk_stream_t s )
{
    assert( s );
    
    if( s->flags.temp )
        return s->fmode;
    return s->flags.write;
}


static filter_fnct_t
stream_id_to_filter( int type )
{
    switch( type ) {
    case fARMOR    : return _cdk_filter_armor;
    case fLITERAL: return _cdk_filter_literal;
    case fTEXT     : return _cdk_filter_text;
    case fCIPHER   : return _cdk_filter_cipher;
    case fCOMPRESS : return _cdk_filter_compress;
    default        : return NULL;
    }
}


/**
 * cdk_stream_filter_disable: Disable the filter with the type 'type'
 * @s: The STREAM object
 * @type: The numberic filter ID.
 *
 **/
cdk_error_t
cdk_stream_filter_disable( cdk_stream_t s, int type )
{
    struct stream_filter_s * f;
    filter_fnct_t fnc;

    if( !s )
        return CDK_Inv_Value;
    fnc = stream_id_to_filter( type  );
    f = filter_search( s, fnc );
    if( f )
        f->flags.enabled = 0;
    return 0;
}


static int
stream_fp_replace( cdk_stream_t s, FILE ** tmp )
{
    int rc;

    assert( s );
  
    rc = fclose( s->fp );
    if( rc )
        return CDK_File_Error;
    s->fp = *tmp;
    *tmp = NULL;
    return 0;
}


/* This function is exactly like filter_read, except the fact that we can't
   use tmpfile () all the time. That's why we open the real file when there
   is no last filter. */
static int
stream_filter_write( cdk_stream_t s )
{
    struct stream_filter_s * f;
    int rc = 0;

    assert( s );
    
    if( s->flags.filtrated )
        return CDK_Inv_Value;

    for( f = s->filters; f; f = f->next ) {
        if( !f->flags.enabled )
            continue;
        /* if there is no next filter, create the final output file */
        _cdk_log_debug( "filter [write]: last filter=%d fname=%s\n",
                        f->next? 1 : 0, s->fname );
        if( !f->next && s->fname )
            f->tmp = fopen( s->fname, "w+b" );
        else
            f->tmp = tmpfile( );
        if( !f->tmp ) {
            rc = CDK_File_Error;
            break;            
        }
        /* If there is no next filter, flush the cache. We also do this
           when the next filter is the armor filter because this filter
           is special and before it starts, all data should be written. */
        if( (!f->next || f->next->type == fARMOR) && s->cache.size ) {
            rc = stream_cache_flush( s, f->tmp );
            if( rc )
                break;
        }
        rc = f->fnct( f->opaque, f->ctl, s->fp, f->tmp );
        _cdk_log_debug( "filter [write]: type=%d rc=%d\n", f->type, rc );
        if( !rc )
            rc = stream_fp_replace( s, &f->tmp );
        if( !rc )
            rc = cdk_stream_seek( s, 0 );
        if( rc ) {
            fclose( f->tmp );
            break;
        }
    }
    return rc;
}


/* Here all data from the file handle is passed through all filters.
   The scheme works like this:
   Create a tempfile and use it for the output of the filter. Then the
   original file handle will be closed and replace with the temp handle.
   The file pointer will be set to the begin and the game starts again. */
static int
stream_filter_read( cdk_stream_t s )
{
    struct stream_filter_s * f;
    int rc = 0;

    assert( s );
    
    if( s->flags.filtrated )
        return 0;

    for( f = s->filters; f; f = f->next ) {
        if( !f->flags.enabled )
            continue;
        f->tmp = tmpfile( );
        if( !f->tmp ) {
            rc = CDK_File_Error;
            break;
        }
        rc = f->fnct( f->opaque, f->ctl, s->fp, f->tmp );
        _cdk_log_debug( "filter %s [read]: type=%d rc=%d\n",
                        s->fname? s->fname : "[temp]", f->type, rc );
        if( rc )
            break;
      
        /* if the filter is read-only, do not replace the FP because
           the contents were not altered in any way. */
        if( !f->flags.rdonly ) {
            rc = stream_fp_replace( s, &f->tmp );
            if( rc )
                break;
        }
        else {
            fclose( f->tmp );
            f->tmp = NULL;
        }
        rc = cdk_stream_seek( s, 0 );
        if( rc )
            break;
        /* Disable the filter after it was successfully used. The idea
           is the following: let's say the armor filter was pushed and
           later more filters were added. The second time the filter code
           will be executed, only the new filter should be started but
           not the old because we already used it. */
        f->flags.enabled = 0;
    }
    return rc;
}


void *
_cdk_stream_get_opaque( cdk_stream_t s, int fid )
{
    struct stream_filter_s * f;

    if( !s )
        return NULL;
    
    for( f = s->filters; f; f = f->next ) {
        if( f->type == fid )
            return f->opaque;
    }
    return NULL;
}


/**
 * cdk_stream_read: Try to read count bytes from the STREAM object.
 * @s: The STREAM object.
 * @buf: The buffer to insert the readed bytes.
 * @count: Request so much bytes.
 *
 * When this function is called the first time, it can take a while
 * because all filters need to be processed. Please remember that you
 * need to add the filters in reserved order.
 **/
int
cdk_stream_read( cdk_stream_t s, void * buf, size_t count )
{
    int nread;
    int rc;

    if( !s )
        return EOF;
    
    if( s->flags.write && !s->flags.temp )
        return EOF; /* this is a write stream */
  
    if( !s->flags.no_filter && !s->cache.on && !s->flags.filtrated ) {
        rc = stream_filter_read( s );
        if( rc ) {
            s->error = rc;
            return EOF;
        }
        s->flags.filtrated = 1;
    }
    if( !buf && !count )
        return 0;
    nread = fread( buf, 1, count, s->fp );  
    if( !nread )
        nread = EOF;
    if( feof( s->fp ) )
        s->flags.eof = 1;
    return nread;
}

      
int
cdk_stream_getc( cdk_stream_t s )
{
    unsigned char buf[2];
    int nread;

    if( !s )
        return EOF;
    
    nread = cdk_stream_read( s, buf, 1 );
    if( nread == EOF ) {
        s->error = CDK_File_Error;
        return EOF;
    }
    return buf[0];
}


/**
 * cdk_stream_write: Try to write count bytes into the stream.
 * @s: The STREAM object
 * @buf: The buffer with the values to write.
 * @count: The size of the buffer.
 *
 * In this function we simply write the bytes to the stream. We can't
 * use the filters here because it would mean they have to support
 * partial flushing.
 **/
int
cdk_stream_write( cdk_stream_t s, const void * buf, size_t count )
{
    int nwritten;

    if( !s )
        return CDK_Inv_Value;
    
    if( !s->flags.write )
        return CDK_Inv_Mode; /* this is a read stream */

    if( !buf && !count )
        return stream_flush( s );

    if( s->cache.on ) {
        if( s->cache.size + count > sizeof( s->cache.buf ) )
            return CDK_EOF;
        memcpy( s->cache.buf + s->cache.size, buf, count  );
        s->cache.size += count;
        return 0;
    }
  
    nwritten = fwrite( buf, 1, count, s->fp );
    if( !nwritten )
        nwritten = EOF;  
    return nwritten;
}


int
cdk_stream_putc( cdk_stream_t s, int c )
{
    unsigned char buf[2];
    int nwritten;

    if( !s )
        return EOF;
    buf[0] = c;
    nwritten = cdk_stream_write( s, buf, 1 );
    if( nwritten == EOF ) {
        s->error = CDK_File_Error;
        return EOF;
    }
    return 0;
}


long
cdk_stream_tell( cdk_stream_t s )
{
    return s? ftell( s->fp ): (long)-1;
}


cdk_error_t
cdk_stream_seek( cdk_stream_t s, long offset )
{
    int rc;

    if( !s )
        return CDK_Inv_Value;    
    if( offset < cdk_stream_get_length( s ) )
        s->flags.eof = 0;
    rc = fseek( s->fp, offset, SEEK_SET );
    if( rc )
        rc = CDK_File_Error;
    return rc;
}


static int
stream_flush( cdk_stream_t s )
{
    int rc;
    
    assert( s );
    
    rc = fflush( s->fp  );
    if( rc )
        rc = CDK_File_Error;
    return rc;
}


cdk_error_t
cdk_stream_set_armor_flag( cdk_stream_t s, int type )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;
    f = filter_add( s, _cdk_filter_armor, fARMOR );
    if( !f )
        return CDK_Out_Of_Core;
    f->u.afx.idx = f->u.afx.idx2 = type;
    f->ctl = stream_get_mode( s );
    return 0;
}


cdk_error_t
cdk_stream_set_literal_flag( cdk_stream_t s, int mode, const char * fname )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;
    f = filter_add( s, _cdk_filter_literal, fLITERAL );
    if( !f )
        return CDK_Out_Of_Core;
    f->u.pfx.mode = mode;
    f->u.pfx.filename = fname? cdk_strdup( fname ) : NULL;
    f->ctl = stream_get_mode( s );
    if( s->blkmode ) {
        f->u.pfx.blkmode.on = 1;
        f->u.pfx.blkmode.size = s->blkmode;
    }
    return 0;
}


cdk_error_t
cdk_stream_set_cipher_flag( cdk_stream_t s, cdk_dek_t dek, int use_mdc )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;
    f = filter_add( s, _cdk_filter_cipher, fCIPHER );
    if( !f )
        return CDK_Out_Of_Core;
    dek->use_mdc = use_mdc;
    f->ctl = stream_get_mode( s );
    f->u.cfx.dek = dek;
    f->u.cfx.mdc_method = use_mdc? GCRY_MD_SHA1 : 0;
    if( s->blkmode ) {
        f->u.cfx.blkmode.on = 1;
        f->u.cfx.blkmode.size = s->blkmode;
    }
    return 0;
}


cdk_error_t
cdk_stream_set_compress_flag( cdk_stream_t s, int algo, int level )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;
    f = filter_add( s, _cdk_filter_compress, fCOMPRESS );
    if( !f )
        return CDK_Out_Of_Core;
    f->ctl = stream_get_mode( s );
    f->u.zfx.algo = algo;
    f->u.zfx.level = level;
    return 0;
}


cdk_error_t
cdk_stream_set_text_flag( cdk_stream_t s, const char * lf )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;
    f = filter_add( s, _cdk_filter_text, fTEXT );
    if( !f )
        return CDK_Out_Of_Core;
    f->ctl = stream_get_mode( s );
    f->u.tfx.lf = lf;
    return 0;
}


cdk_error_t
cdk_stream_set_hash_flag( cdk_stream_t s, int algo )
{
    struct stream_filter_s * f;

    if( !s )
        return CDK_Inv_Value;    
    if( stream_get_mode( s ) )
        return CDK_Inv_Mode;
    f = filter_add( s, _cdk_filter_hash, fHASH );
    if( !f )
        return CDK_Out_Of_Core;
    f->ctl = stream_get_mode( s );
    f->u.mfx.digest_algo = algo;
    f->flags.rdonly = 1;
    return 0;
}


cdk_error_t
cdk_stream_set_cache( cdk_stream_t s, int val )
{
    if( !s )
        return CDK_Inv_Value;
    if( !s->flags.write )
        return CDK_Inv_Mode;
    s->cache.on = val;
    return 0;
}


static int
stream_cache_flush( cdk_stream_t s, FILE * fp )
{
    int nwritten;

    assert( s );
    
    if( s->cache.size > 0 ) {
        nwritten = fwrite( s->cache.buf, 1, s->cache.size, fp  );
        if( !nwritten )
            return CDK_File_Error;
        s->cache.size = 0;
        s->cache.on = 0;
        memset( s->cache.buf, 0, sizeof s->cache.buf  );
    }
    return 0;
}


cdk_error_t
cdk_stream_kick_off( cdk_stream_t inp, cdk_stream_t out )
{
    byte buf[8192];
    int nread, nwritten;
    int rc = 0;

    if( !inp || !out )
        return CDK_Inv_Value;
    while( !cdk_stream_eof( inp ) ) {
        nread = cdk_stream_read( inp, buf, sizeof buf-1 );
        if( nread == EOF )
            break;
        nwritten = cdk_stream_write( out, buf, nread );
        if( nwritten == EOF )
            rc = CDK_File_Error;
    }
    wipemem( buf, sizeof buf );
    return rc;
}


/**
 * cdk_stream_mmap:
 * @s: the stream
 * @ret_buf: the buffer to store the content
 * @ret_count: length of the buffer
 *
 * Map the data of the given stream into a memory section. @ret_count
 * contains the length of the buffer.
 **/
cdk_error_t
cdk_stream_mmap( cdk_stream_t s, byte ** ret_buf, size_t * ret_count )
{
    const u32 max_filesize = 16777216;
    u32 len, oldpos;
    int n, rc;
    char * p;

    if( !s || !ret_buf || !ret_count )
        return CDK_Inv_Value;

    *ret_count = 0;
    *ret_buf = NULL;
    oldpos = cdk_stream_tell( s );
    rc = cdk_stream_flush( s );
    if( !rc )
        rc = cdk_stream_seek( s, 0 );
    if( rc )
        return rc;
    len = cdk_stream_get_length( s );
    if( !len || len > max_filesize )
        return 0;
    p = *ret_buf = cdk_calloc( 1, len+1 );
    if( !p )
        return 0;
    *ret_count = len;
    n = cdk_stream_read( s, p, len );
    if( n != len )
        *ret_count = n;
    rc = cdk_stream_seek( s, oldpos );
    return rc;
}


/**
 * cdk_stream_peek:
 * @inp: the input stream handle
 * @s: buffer
 * @count: number of bytes to peek
 *
 * The function acts like cdk_stream_read with the difference that
 * the file pointer is moved to the old position after the bytes were read.
 **/
int
cdk_stream_peek( cdk_stream_t inp, byte *s, size_t count )
{
    unsigned off;
    int nbytes, rc;

    if( !inp || !s )
        return CDK_Inv_Value;
    off = cdk_stream_tell( inp );
    nbytes = _cdk_stream_gets( inp, s, count );
    rc = cdk_stream_seek( inp, off );
    if( rc )
        return 0;
    return nbytes;
}


int
_cdk_stream_gets( cdk_stream_t s, char * buf, size_t count )
{
    int c, i = 0;

    if( !s )
        return CDK_Inv_Value;
    while( !cdk_stream_eof( s ) && count > 0 ) {
        c = cdk_stream_getc( s );
        if( c == EOF || c == '\r' || c == '\n' ) {
            buf[i++] = '\0';
            break;
        }
        buf[i++] = c;
        count--;   
    }
    return i;
}


int
_cdk_stream_puts( cdk_stream_t s, const char * buf )
{
    return cdk_stream_write( s, buf, strlen( buf ) );
}


int
_cdk_stream_set_blockmode( cdk_stream_t s, size_t nbytes )
{
    if( !s )
        return CDK_Inv_Value;
    _cdk_log_debug( "set block mode for stream (size=%d)\n", nbytes );
    s->blkmode = nbytes;  
    return 0;
}


int
_cdk_stream_get_blockmode( cdk_stream_t s )
{
    return s? s->blkmode : 0;
}

