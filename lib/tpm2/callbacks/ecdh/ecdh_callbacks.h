/*
 * Copyright © 2025 David Dudas
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

#ifndef GNUTLS_LIB_TPM2_ECDH_CALLBACKS_H
#define GNUTLS_LIB_TPM2_ECDH_CALLBACKS_H

typedef struct ESYS_CRYPTO_CALLBACKS ESYS_CRYPTO_CALLBACKS;

void _gnutls_set_tss2_ecdh_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks);

#endif /* GNUTLS_LIB_TPM2_ECDH_CALLBACKS_H */
