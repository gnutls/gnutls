/*
 *      Copyright (C) 2000,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

const mpi_t *_gnutls_get_dh_params(gnutls_dh_params);
mpi_t gnutls_calc_dh_secret(mpi_t * ret_x, mpi_t g, mpi_t prime);
mpi_t gnutls_calc_dh_key(mpi_t f, mpi_t x, mpi_t prime);
int _gnutls_dh_generate_prime(mpi_t * ret_g, mpi_t * ret_n, uint bits);
void gnutls_dh_params_deinit(gnutls_dh_params dh_params);
