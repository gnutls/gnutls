/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EINA_INLINE_HASH_X_
#define EINA_INLINE_HASH_X_

/*
  djb2 hash algorithm was first reported by dan bernstein, and was the old
  default hash function for evas.
 */
static inline int
eina_hash_djb2(const char *key, int len)
{
   unsigned int hash_num = 5381;
   const unsigned char *ptr;

   if (!key) return 0;
   for (ptr = (unsigned char *)key; len; ptr++, len--)
     hash_num = ((hash_num << 5) + hash_num) ^ *ptr; /* hash * 33 ^ c */

   return (int)hash_num;
}

static inline int
eina_hash_djb2_len(const char *key, int *plen)
{
   unsigned int hash_num = 5381;
   int len = 0;
   const unsigned char *ptr;

   if (!key) return 0;

   for (ptr = (unsigned char *)key; *ptr; ptr++, len++)
     hash_num = ((hash_num << 5) + hash_num) ^ *ptr; /* hash * 33 ^ c */

   *plen = len + 1;

   return (int)hash_num;
}

static inline int
eina_hash_int32(const unsigned int *pkey, int len)
{
  unsigned int key = *pkey;

  (void) len;

  key = ~key + (key << 15);
  key = key ^ (key >> 12);
  key = key + (key << 2);
  key = key ^ (key >> 4);
  key = key * 2057;
  key = key ^ (key >> 16);
  return key;
}

static inline int
eina_hash_int64(const unsigned long int *pkey, int len)
{
  unsigned long int key = *pkey;

  (void) len;

  key = (~key) + (key << 18);
  key = key ^ (key >> 31);
  key = key * 21;
  key = key ^ (key >> 11);
  key = key + (key << 6);
  key = key ^ (key >> 22);
  return (int) key;
}

#endif
