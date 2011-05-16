/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* Helper functions for ECC handling 
 * based on public domain code by Tom St. Dennis.
 */
#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_ecc.h>
#include <gnutls_algorithms.h>
#include <gnutls_errors.h>

int _gnutls_ecc_ansi_x963_export(ecc_curve_t curve, bigint_t x, bigint_t y, gnutls_datum_t * out)
{
   int numlen = _gnutls_ecc_curve_get_size(curve);
   int byte_size, ret;
   size_t size;
   
   if (numlen == 0)
     return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
   
   out->size = 1 + 2*numlen;
   
   out->data = gnutls_malloc(out->size);
   if (out->data == NULL)
     return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

   memset(out->data, 0, out->size);

   /* store byte 0x04 */
   out->data[0] = 0x04;

   /* pad and store x */
   byte_size = (_gnutls_mpi_get_nbits(x)+7)/8;
   size = out->size - (1+(numlen-byte_size));
   ret = _gnutls_mpi_print(x, &out->data[1+(numlen-byte_size)], &size);
   if (ret < 0)
     return gnutls_assert_val(ret);
   
   byte_size = (_gnutls_mpi_get_nbits(y)+7)/8;
   size = out->size - (1+(numlen+numlen-byte_size));
   ret = _gnutls_mpi_print(y, &out->data[1+numlen+numlen-byte_size], &size);
   if (ret < 0)
     return gnutls_assert_val(ret);

   /* pad and store y */
   return 0;
}


int _gnutls_ecc_ansi_x963_import(ecc_curve_t curve, const opaque *in, unsigned long inlen, bigint_t* x, bigint_t* y)
{
   int ret;
   int numlen = _gnutls_ecc_curve_get_size(curve);
 
   /* must be odd */
   if ((inlen & 1) == 0 || numlen == 0) 
     {
       return GNUTLS_E_INVALID_REQUEST;
     }

   /* check for 4, 6 or 7 */
   if (in[0] != 4 && in[0] != 6 && in[0] != 7) {
      return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
   }

   /* read data */
   ret = _gnutls_mpi_scan(x, in+1, (inlen-1)>>1);
   if (ret < 0)
     return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

   ret = _gnutls_mpi_scan(y, in+1+((inlen-1)>>1), (inlen-1)>>1);
   if (ret < 0)
     {
       _gnutls_mpi_release(x);
       return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
     }

   return 0;
}
