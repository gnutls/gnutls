/*
 * Copyright (C) 2009 Free Software Foundation
 *
 * Author: Jonathan Bastien-Filiatrault
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

#ifndef GNUTLS_MBUFFERS_H
# define GNUTLS_MBUFFERS_H

#include "gnutls_int.h"

void _gnutls_mbuffer_init (mbuffer_head_st *buf);
void _gnutls_mbuffer_clear (mbuffer_head_st *buf);
int  _gnutls_mbuffer_enqueue (mbuffer_head_st *buf, const gnutls_datum_t *msg);
int  _gnutls_mbuffer_enqueue_copy (mbuffer_head_st *buf, const gnutls_datum_t *msg);
void _gnutls_mbuffer_get_head (mbuffer_head_st *buf, gnutls_datum_t *msg);
int  _gnutls_mbuffer_remove_bytes (mbuffer_head_st *buf, size_t bytes);

#endif
