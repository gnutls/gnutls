/* -*- Mode: C; c-file-style: "bsd" -*-
 * md.h
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CDK_MD_H
#define CDK_MD_H

cdk_md_hd_t cdk_md_open( int algo, unsigned int flags );
cdk_md_hd_t cdk_md_copy( cdk_md_hd_t md );
void cdk_md_write( cdk_md_hd_t md, const void *buf, size_t n );
void cdk_md_close( cdk_md_hd_t md );
void cdk_md_putc( cdk_md_hd_t md, int c );
int cdk_md_test_algo( int algo );
unsigned char * cdk_md_read( cdk_md_hd_t md, int algo );
int cdk_md_get_algo_dlen( int algo );
int cdk_md_final( cdk_md_hd_t md );
int cdk_md_get_algo( cdk_md_hd_t md );
int cdk_md_get_asnoid( int algo, unsigned char *buf, size_t *n );
int cdk_md_reset( cdk_md_hd_t md);

#endif /*CDK_MD_H*/


