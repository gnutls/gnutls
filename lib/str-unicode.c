/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include "str.h"
#include <uninorm.h>
#include <unistr.h>
#include <unictype.h>
#ifdef HAVE_LIBIDN
# include <idna.h>
# include <idn-free.h>
#endif

/**
 * gnutls_utf8_password_normalize:
 * @password: contain the UTF-8 formatted password
 * @password_len: the length of the provided password
 * @out: the result in an null-terminated allocated string
 * @flags: should be zero
 *
 * This function will convert the provided UTF-8 password according
 * to the normalization rules in RFC7613.
 *
 * If the flag %GNUTLS_UTF8_IGNORE_ERRS is specified, any UTF-8 encoding
 * errors will be ignored, and in that case the output will be a copy of the input.
 *
 * Returns: %GNUTLS_E_INVALID_UTF8_STRING on invalid UTF-8 data, or 0 on success.
 *
 * Since: 3.5.7
 **/
int gnutls_utf8_password_normalize(const unsigned char *password, unsigned password_len,
				   gnutls_datum_t *out, unsigned flags)
{
	size_t plen = strlen((char*)password);
	size_t ucs4_size = 0, nrm_size = 0;
	size_t final_size = 0;
	uint8_t *final = NULL;
	uint32_t *ucs4 = NULL;
	uint32_t *nrm = NULL;
	uint8_t *nrmu8 = NULL;
	unsigned i;
	int ret;

	if (plen == 0) {
		out->data = (uint8_t*)gnutls_strdup("");
		out->size = 0;
		if (out->data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		return 0;
	}

	/* check for invalid UTF-8 */
	if (u8_check((uint8_t*)password, plen) != NULL) {
		gnutls_assert();
		if (flags & GNUTLS_UTF8_IGNORE_ERRS) {
			out->data = gnutls_malloc(password_len+1);
			if (out->data == NULL)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			out->size = password_len;
			memcpy(out->data, password, password_len);
			out->data[password_len] = 0;
			return 0;
		} else {
			return GNUTLS_E_INVALID_UTF8_STRING;
		}
	}

	/* convert to UTF-32 */
	ucs4 = u8_to_u32((uint8_t*)password, plen, NULL, &ucs4_size);
	if (ucs4 == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_PARSING_ERROR;
		goto fail;
	}

	/* convert all spaces to the ASCII-space */
	for (i=0;i<ucs4_size;i++) {
		if (uc_is_general_category(ucs4[i], UC_CATEGORY_Zs)) {
			ucs4[i] = 0x20;
		}
	}

	/* normalize to NFC */
	nrm = u32_normalize(UNINORM_NFC, ucs4, ucs4_size, NULL, &nrm_size);
	if (nrm == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_PARSING_ERROR;
		goto fail;
	}

	/* convert back to UTF-8 */
	final_size = 0;
	nrmu8 = u32_to_u8(nrm, nrm_size, NULL, &final_size);
	if (nrmu8 == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_PARSING_ERROR;
		goto fail;
	}

	/* copy to output with null terminator */
	final = gnutls_malloc(final_size+1);
	if (final == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto fail;
	}

	memcpy(final, nrmu8, final_size);
	final[final_size] = 0;

	gnutls_free(ucs4);
	gnutls_free(nrm);
	gnutls_free(nrmu8);

	out->data = final;
	out->size = final_size;

	return 0;

 fail:
	gnutls_free(final);
	gnutls_free(ucs4);
	gnutls_free(nrm);
	gnutls_free(nrmu8);
	return ret;
}

#ifdef HAVE_LIBIDN
/*-
 * gnutls_idna_map:
 * @input: contain the UTF-8 formatted domain name
 * @ilen: the length of the provided string
 * @out: the result in an null-terminated allocated string
 * @flags: should be zero
 *
 * This function will convert the provided UTF-8 domain name, to
 * its IDNA2003 mapping.
 *
 * If GnuTLS is compiled without libidn2 support, then this function
 * will return %GNUTLS_E_UNIMPLEMENTED_FEATURE.
 *
 * Returns: %GNUTLS_E_INVALID_UTF8_STRING on invalid UTF-8 data, or 0 on success.
 *
 * Since: 3.5.7
 -*/
int gnutls_idna_map(const char *input, unsigned ilen, gnutls_datum_t *out, unsigned flags)
{
	char *idna = NULL;
	int rc, ret;
	gnutls_datum_t istr;

	if (ilen == 0) {
		out->data = (uint8_t*)gnutls_strdup("");
		out->size = 0;
		if (out->data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		return 0;
	}

	ret = _gnutls_set_strdatum(&istr, input, ilen);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	rc = idna_to_ascii_8z((char*)istr.data, &idna, 0);
	if (rc != IDNA_SUCCESS) {
		gnutls_assert();
		_gnutls_debug_log("unable to convert name '%s' to IDNA format: %s\n", istr.data, idna_strerror(rc));
		ret = GNUTLS_E_INVALID_UTF8_STRING;
		goto fail;
	}

	if (gnutls_malloc != malloc) {
		ret = _gnutls_set_strdatum(out, idna, strlen(idna));
	} else  {
		out->data = (unsigned char*)idna;
		out->size = strlen(idna);
		idna = NULL;
		ret = 0;
	}
 fail:
	idn_free(idna);
	gnutls_free(istr.data);
	return ret;
}
#else

# undef gnutls_idna_map
int gnutls_idna_map(const char *input, unsigned ilen, gnutls_datum_t *out, unsigned flags)
{
	return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
}
#endif /* HAVE_LIBIDN2 */
