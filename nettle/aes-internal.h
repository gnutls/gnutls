/* aes-internal.h
 *
 * The aes/rijndael block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#ifndef NETTLE_AES_INTERNAL_H_INCLUDED
#define NETTLE_AES_INTERNAL_H_INCLUDED

#include "aes.h"

/* Define to use only small tables. */
#ifndef AES_SMALL
# define AES_SMALL 0
#endif

#if AES_SMALL
# define AES_TABLE_SIZE 1
#else
# define AES_TABLE_SIZE 4
#endif

/* Name mangling */
#define _aes_crypt _nettle_aes_crypt

/* Assembler code using the table should get link errors if linked
 * against a small table. */
#if AES_SMALL
# define _aes_encrypt_table _nettle_aes_encrypt_table_small
# define _aes_decrypt_table _nettle_aes_decrypt_table_small
#else
# define _aes_encrypt_table _nettle_aes_encrypt_table
# define _aes_decrypt_table _nettle_aes_decrypt_table
#endif

struct aes_table
{
  uint8_t sbox[0x100];
  unsigned idx[3][4];

  /* Variant of the idx array suitable for the sparc
   * assembler code.
   *
   * sparc_idx[0][i] = idx[0][i] * 4 + 2
   * sparc_idx[1][i] = idx[2][i] * 4
   */
  
  unsigned sparc_idx [2][4]; 

  uint32_t table[AES_TABLE_SIZE][0x100];
};

void
_aes_crypt(const struct aes_ctx *ctx,
	   const struct aes_table *T,
	   unsigned length, uint8_t *dst,
	   const uint8_t *src);

/* Macros */
#define ROTBYTE(x) (((x) >> 8) | (((x) & 0xff) << 24))
#define ROTRBYTE(x) (((x) << 8) | (((x) >> 24) & 0xff))
#define SUBBYTE(x, box) (((box)[((x) & 0xff)]) | \
                        ((box)[(((x) >> 8) & 0xff)] << 8) | \
                        ((box)[(((x) >> 16) & 0xff)] << 16) | \
                        ((box)[(((x) >> 24) & 0xff)] << 24))

/* Internal tables */
extern const struct aes_table _aes_encrypt_table;
extern const struct aes_table _aes_decrypt_table;

#define aes_sbox (_aes_encrypt_table.sbox)

#endif /* NETTLE_AES_INTERNAL_H_INCLUDED */
