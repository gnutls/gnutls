/*
 * Copyright (C) 2000,2002,2003 Nikos Mavroyanopoulos
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

const mpi_t *_gnutls_get_rsa_params(gnutls_rsa_params);
int _gnutls_peers_cert_less_512(gnutls_session session);
int _gnutls_rsa_generate_params(mpi_t * resarr, int *resarr_len, int bits);
void gnutls_rsa_params_deinit(gnutls_rsa_params rsa_params);
