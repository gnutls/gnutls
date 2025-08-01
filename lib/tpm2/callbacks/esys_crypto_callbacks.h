/*
 * Copyright (C) 2000-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2018 Red Hat, Inc.
 *
 * Author: David Dudas <david.dudas03@e-uvt.ro>
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_LIB_TPM2_ESYS_CALLBACKS_H
#define GNUTLS_LIB_TPM2_ESYS_CALLBACKS_H

typedef struct ESYS_CONTEXT ESYS_CONTEXT;

#ifdef HAVE_ESYS_SETCRYPTOCALLBACKS
int _gnutls_setup_tss2_callbacks(ESYS_CONTEXT *ctx);
#endif

#endif /* GNUTLS_LIB_TPM2_ESYS_CALLBACKS_H */
