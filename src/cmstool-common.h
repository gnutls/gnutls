/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef GNUTLS_SRC_CMSTOOL_COMMON_H
#define GNUTLS_SRC_CMSTOOL_COMMON_H

#include <certtool-common.h>

void load_data(common_info_st *cinfo, gnutls_datum_t *data);
void pkcs7_info(common_info_st *cinfo, unsigned display_data);
void pkcs7_generate(common_info_st *);
void pkcs7_sign_common(common_info_st *, unsigned embed, gnutls_pkcs7_sign_flags flags);
void pkcs7_verify_common(common_info_st * cinfo, const char *purpose, unsigned display_data, gnutls_certificate_verify_flags flags);
void smime_to_pkcs7(void);

extern FILE *infile;
extern FILE *outfile;

#endif /* GNUTLS_SRC_CMSTOOL_COMMON_H */
