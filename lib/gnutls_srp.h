/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

#ifdef ENABLE_SRP

int _gnutls_srp_gx (opaque * text, size_t textsize, opaque ** result,
		    mpi_t g, mpi_t prime, gnutls_alloc_function);
mpi_t _gnutls_calc_srp_B (mpi_t * ret_b, mpi_t g, mpi_t n, mpi_t v);
mpi_t _gnutls_calc_srp_u (mpi_t A, mpi_t B, mpi_t N);
mpi_t _gnutls_calc_srp_S1 (mpi_t A, mpi_t b, mpi_t u, mpi_t v, mpi_t n);
mpi_t _gnutls_calc_srp_A (mpi_t * a, mpi_t g, mpi_t n);
mpi_t _gnutls_calc_srp_S2 (mpi_t B, mpi_t g, mpi_t x, mpi_t a, mpi_t u,
			   mpi_t n);
int _gnutls_calc_srp_x (char *username, char *password, opaque * salt,
			size_t salt_size, size_t * size, void *digest);
int _gnutls_srp_gn (opaque ** ret_g, opaque ** ret_n, int bits);

/* g is defined to be 2 */
#define SRP_MAX_HASH_SIZE 24

#endif
