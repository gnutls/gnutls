/* md.c
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

#include <stdio.h>
#include "opencdk.h"
#include "main.h"
#include "md.h"

struct cdk_md_hd_s {
    gcry_md_hd_t hd;
    int algo;
};  

inline 
static int cdk_md_to_gcry( int algo)
{
    switch(algo) {
    case CDK_MD_MD5:
    	return GCRY_MD_MD5;
    case CDK_MD_SHA1:
    	return GCRY_MD_SHA1;
    case CDK_MD_RMD160:
    	return GCRY_MD_RMD160;
    default:
	return -1;
    }

}

/* flags will be passed to gcrypt as is.
 */
cdk_md_hd_t
cdk_md_open( int algo, unsigned int flags )
{
    cdk_md_hd_t hd;
    gcry_error_t err;

    hd = cdk_calloc( 1, sizeof * hd );
    if( !hd )
        return NULL;
    hd->algo = algo;
    
    err = gcry_md_open( &hd->hd, cdk_md_to_gcry( algo), flags);
    
    if (err) {
        cdk_free( hd );
        return NULL;
    }

    return hd;
}


void
cdk_md_close( cdk_md_hd_t hd )
{
    if( hd ) {
	gcry_md_close( hd->hd);
        cdk_free( hd );
    }
}

int
cdk_md_test_algo( int algo )
{
    return gcry_md_test_algo( cdk_md_to_gcry(algo));
}


void
cdk_md_write( cdk_md_hd_t hd, const void * buf, size_t buflen )
{
    if( hd ) {
        gcry_md_write( hd->hd, (byte *)buf, buflen );
    }
}


void
cdk_md_putc( cdk_md_hd_t hd, int c )
{
    if (hd) {
    	gcry_md_putc( hd->hd, c);
    }
}


int
cdk_md_final( cdk_md_hd_t hd )
{
    if( hd ) {
        return gcry_md_final(hd->hd);
    }
    return CDK_Inv_Value;
}


byte *
cdk_md_read( cdk_md_hd_t hd, int algo )
{
int _algo;

    if (algo==0) _algo = 0;
    else _algo = cdk_md_to_gcry(algo);

    if (hd) {
    	return gcry_md_read( hd->hd, _algo);
    }
    return NULL;
}


cdk_md_hd_t
cdk_md_copy( cdk_md_hd_t hd )
{
    cdk_md_hd_t new;
    gcry_error_t err;

    new = cdk_calloc( 1, sizeof * hd );
    if( !new )
        return NULL;
    
    err = gcry_md_copy( &new->hd, hd->hd);
    
    if( err) {
        cdk_free( new);
        return NULL;
    }

    new->algo = hd->algo;
    
    return new;
}


int
cdk_md_get_algo_dlen( int algo )
{
    return gcry_md_get_algo_dlen( cdk_md_to_gcry( algo ));
}


int
cdk_md_get_asnoid( int algo, byte * buf, size_t *r_asnlen )
{
    return gcry_md_get_asnoid( cdk_md_to_gcry(algo), buf, r_asnlen);
}


int
cdk_md_reset( cdk_md_hd_t hd )
{
    if( hd ) {
        gcry_md_reset( hd->hd );
        return 0;
    }
    return CDK_Inv_Value;
}


int
cdk_md_get_algo( cdk_md_hd_t hd )
{
    if( hd )
        return hd->algo;
    return 0;
}
