/* -*- Mode: C; c-file-style: "bsd" -*-
 * keyserver.c - Keyserver support
 *        Copyright (C) 2002 Timo Schulz
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
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# define closesocket close
#else
# include <windows.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "opencdk.h"
#include "main.h"


static int initialized = 0;


static void
init_sockets( void )
{
#ifdef __MINGW32__
    WSADATA wsdata;
  
    if( initialized )
        return;
    if( WSAStartup( 0x0101, &wsdata ) )
        _cdk_log_debug( "winsock init failed.\n" );
#endif
    initialized = 1;
}

  
static int
keyserver_hkp( const char * host, int port, u32 keyid, cdk_kbnode_t * ret_key )
{
    const char * fmt;
    struct hostent * hp;
    struct sockaddr_in saddr;
    cdk_stream_t a;
    char * buf, buffer[256];
    int nwritten, nread, state = 0;
    int rc = 0, fd;

    _cdk_log_debug( "connect to `%s'\n", host );
    hp = gethostbyname( host );
    if( !hp )
        return CDK_General_Error;

    memset( &saddr, 0, sizeof saddr );
    memcpy( &saddr.sin_addr, hp->h_addr, hp->h_length );
    saddr.sin_family = hp->h_addrtype;
    saddr.sin_port = htons( port );
  
    fd = socket( AF_INET, SOCK_STREAM, 0 );
    if( fd == -1 )
        return CDK_General_Error;

    setsockopt( fd, SOL_SOCKET, SO_REUSEADDR,( char *)1, 1 );
    if( connect( fd,( struct sockaddr *) &saddr, sizeof saddr ) == -1 ) {
        closesocket( fd );
        return CDK_General_Error; 
    }

    fmt = "GET /pks/lookup?op=get&search=0x%08lX HTTP/1.0\r\n"
          "Host: %s:%d\r\n"
          "\r\n";
    buf = cdk_calloc( 1, 64 + strlen( host ) + strlen( fmt ) );
    if( !buf ) {
        closesocket( fd );
        return CDK_Out_Of_Core;
    }
    sprintf( buf, fmt, keyid, host, port );
    _cdk_log_debug( "%s\n", buf );

    nwritten = send( fd, buf, strlen( buf ), 0 );
    if( nwritten == -1 ) {
        cdk_free( buf );
        closesocket( fd );
        return CDK_File_Error;
    }

    a = cdk_stream_tmp(  );
    if( !a ) {
        cdk_free( buf );
        closesocket( fd );
        return CDK_Out_Of_Core;
    }

    while( (nread = recv( fd, buffer, 255, 0 )) > 0 ) {
        buffer[nread] = '\0';
        /*_cdk_log_debug( "%s", buffer );*/
        cdk_stream_write( a, buffer, nread );
        if( strstr( buffer, "<pre>") || strstr( buffer, "</pre>" ) )
            state++;
    }
    cdk_free( buf );
  
    if( state != 2 )
        rc = CDK_Error_No_Key;
    if( !rc ) {
        cdk_stream_tmp_set_mode( a, 0 );
        cdk_stream_set_armor_flag( a, 0 );
        cdk_stream_seek( a, 0 );
        cdk_stream_read( a, NULL, 0 );
        rc = cdk_keydb_get_keyblock( a, ret_key );
    }
    if( rc == CDK_EOF && *ret_key )
        rc = 0;
    cdk_stream_close( a );
    closesocket( fd );
    return rc;
}


/**
 * cdk_keyserver_recv_key: 
 * @host: URL or hostname of the keyserver
 * @port: The port to use for the connection
 * @keyid: KeyID of the key to retrieve
 * @kid_type: KeyID type (long, short, fingerprint)
 * @r_knode: The key that was found wrapped in a KBNODE struct
 *
 * Receive a key from a keyserver.
 **/
cdk_error_t
cdk_keyserver_recv_key( const char * host, int port,
                        const byte * keyid, int kid_type,
                        cdk_kbnode_t * ret_key )
{
    u32 kid = 0;

    if( !host || !keyid || !ret_key )
        return CDK_Inv_Value;
    
    if( !initialized )
        init_sockets(  );
  
    if( !port )
        port = 11371;
  
    if( !strncmp( host, "http://", 7 ) )
        host += 7;
    else if( !strncmp( host, "hkp://", 6 ) )
        host += 6;
    else if( !strncmp( host, "x-hkp://", 8 ) )
        host += 8;

    switch( kid_type ) {
    case CDK_DBSEARCH_SHORT_KEYID: kid = _cdk_buftou32( keyid ); break;
    case CDK_DBSEARCH_KEYID      : kid = _cdk_buftou32( keyid + 4 ); break;
    case CDK_DBSEARCH_FPR        : kid = _cdk_buftou32( keyid + 16 ); break;
    default                      : return CDK_Inv_Mode;
    }
    
    return keyserver_hkp( host, port, kid, ret_key );
}
