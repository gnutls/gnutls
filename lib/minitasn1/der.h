/*
 *      Copyright (C) 2006 Free Software Foundation
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBTASN1.
 *
 * LIBTASN1 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * LIBTASN1 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with LIBTASN1; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

/*************************************************/
/* File: der.h                                   */
/* Description: list of definitions and exported */
/*   objects by coding.c and decoding.c          */
/*************************************************/

#ifndef _DER_H
#define _DER_H

#define UNIVERSAL        0x00
#define APPLICATION      0x40
#define CONTEXT_SPECIFIC 0x80
#define PRIVATE          0xC0
#define STRUCTURED       0x20


#define TAG_BOOLEAN          0x01
#define TAG_INTEGER          0x02
#define TAG_SEQUENCE         0x10
#define TAG_SET              0x11
#define TAG_OCTET_STRING     0x04
#define TAG_BIT_STRING       0x03
#define TAG_UTCTime          0x17
#define TAG_GENERALIZEDTime  0x18
#define TAG_OBJECT_ID        0x06
#define TAG_ENUMERATED       0x0A
#define TAG_NULL             0x05
#define TAG_GENERALSTRING    0x1B

#endif /* _DER_H */
