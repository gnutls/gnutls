/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifdef ENABLE_SRP

bigint_t _gnutls_calc_srp_B (bigint_t * ret_b, bigint_t g, bigint_t n,
                             bigint_t v);
bigint_t _gnutls_calc_srp_u (bigint_t A, bigint_t B, bigint_t N);
bigint_t _gnutls_calc_srp_S1 (bigint_t A, bigint_t b, bigint_t u, bigint_t v,
                              bigint_t n);
bigint_t _gnutls_calc_srp_A (bigint_t * a, bigint_t g, bigint_t n);
bigint_t _gnutls_calc_srp_S2 (bigint_t B, bigint_t g, bigint_t x, bigint_t a,
                              bigint_t u, bigint_t n);
int _gnutls_calc_srp_x (char *username, char *password, opaque * salt,
                        size_t salt_size, size_t * size, void *digest);
int _gnutls_srp_gn (opaque ** ret_g, opaque ** ret_n, int bits);

/* g is defined to be 2 */
#define SRP_MAX_HASH_SIZE 24

#endif
