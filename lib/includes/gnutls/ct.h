/*
 * Copyright (C) 2023 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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

/* This file contains the types and prototypes for the X.509
 * certificate and CRL handling functions.
 */
/* This file contains the types and prototypes for handling
 * the Certificate Transparency (CT) v2.0 structures defined in RFC 9162
 */

#ifndef GNUTLS_CT_H
# define GNUTLS_CT_H

# include <gnutls/gnutls.h>
# include <gnutls/x509-ext.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gnutls_ct_logs_st *gnutls_ct_logs_t;

int gnutls_ct_logs_init(gnutls_ct_logs_t * logs);
void gnutls_ct_logs_deinit(gnutls_ct_logs_t logs);

#define GNUTLS_CT_KEY_AS_DER    0
#define GNUTLS_CT_KEY_AS_BASE64 1
int gnutls_ct_add_log(gnutls_ct_logs_t logs,
		      const char * name,
		      const char * description,
		      const gnutls_datum_t * key,
		      time_t not_before, time_t not_after,
		      unsigned flags);
int gnutls_ct_sct_validate(const gnutls_x509_ct_scts_t scts, unsigned idx,
			   const gnutls_ct_logs_t logs,
			   gnutls_x509_crt_t crt, gnutls_time_func time_func);
#ifdef __cplusplus
}
#endif

#endif /* GNUTLS_CT_H */
