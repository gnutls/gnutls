/* scanner for DER encoded certificates */

/*
 * Copyright (C) 2000 Tarun Upadhyay <tarun@ebprovider.com>
 *
 * This file is part of GNUTLS Certificate API.
 *
 * GNUTLS Certificate API is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS Certificate API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* internally generated error codes */
#define READ_ERROR -1
#define DER_UNKNOWN -2

/* TAG values mappings - column 2 in ASN_TAGS */
#define DER_BOOLEAN 1
#define DER_INTEGER 2
#define DER_BIT_STRING 3
#define DER_NULL 5
#define DER_OBJECT_ID 6
#define DER_OBJECT_DESC 7
#define DER_STRING 13
#define DER_UTC_TIME 17
#define DER_SEQUENCE 30
#define DER_SET 31
#define DER_ARRAY 160

/* Does the tag contains other tags - column 3 in ASN_TAGS */
#define ASN_TAG_COMPOSITE 1

/* structure made for one tag in ASN_TAGS array */
typedef struct {
  int code; /* ASN1 code for the tag */
  int level; /* level at which the tag lives in the heirarchy */
  int type; /* Type of Tag */
  int composite; /* Does this tag contain other tags */
  int value_length; /* length of the value */
  int length; /* length of the whole tag */
} tag_attribs;
			   
/* Table to store attributes of each ASN tag
 * {
 *   TAG VALUE as in ASN 1.0,
 *   Type of Tag,
 *   Can this tag conatin other tags
 * }
 */
static const int ASN_TAGS[][3] = {
  {0x01, DER_BOOLEAN},
  {0x02, DER_INTEGER},
  {0x03, DER_BIT_STRING},
  {0x04, DER_BIT_STRING},
  {0x05, DER_NULL},
  {0x06, DER_OBJECT_ID},
  (0x07, DER_OBJECT_DESC),
  {0x13, DER_STRING},
  {0x16, DER_STRING},
  {0x17, DER_UTC_TIME},
  {0x30, DER_SEQUENCE, ASN_TAG_COMPOSITE},
  {0x31, DER_SET, ASN_TAG_COMPOSITE},
  {0xa0, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa1, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa2, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa3, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa4, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa5, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa6, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa7, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa8, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xa9, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xaa, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xab, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xac, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xad, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xae, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0xaf, DER_ARRAY, ASN_TAG_COMPOSITE},
  {0, 0}
};

