/*
 * Copyright (C) 2016, 2017 Red Hat, Inc.
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
#ifdef HAVE_LIBIDN2
# include <idn2.h>
#elif defined HAVE_LIBIDN
# include <idna.h>
# include <idn-free.h>
#endif

/* rfc5892#section-2.6 exceptions
 */
inline static int is_allowed_exception(uint32_t ch)
{
	switch (ch) {
		case 0xB7:
		case 0x0375:
		case 0x05F3:
		case 0x05F4:
		case 0x30FB:
		case 0x0660:
		case 0x0661:
		case 0x0662:
		case 0x0663:
		case 0x0664:
		case 0x0665:
		case 0x0666:
		case 0x0667:
		case 0x0668:
		case 0x0669:
		case 0x06F0:
		case 0x06F1:
		case 0x06F2:
		case 0x06F3:
		case 0x06F4:
		case 0x06F5:
		case 0x06F6:
		case 0x06F7:
		case 0x06F8:
		case 0x06F9:
		case 0x0640:
		case 0x07FA:
		case 0x302E:
		case 0x302F:
		case 0x3031:
		case 0x3032:
		case 0x3033:
		case 0x3034:
		case 0x3035:
		case 0x303B:
			return 0; /* disallowed */
		case 0xDF:
		case 0x03C2:
		case 0x06FD:
		case 0x06FE:
		case 0x0F0B:
		case 0x3007:
			return 1; /* allowed */
		default:
			return -1; /* not exception */
	}
}

/* Checks whether the provided string is in the valid set of FreeFormClass (RFC7564
 * as an RFC7613 requirement), and converts all spaces to the ASCII-space. */
static int check_for_valid_freeformclass(uint32_t *ucs4, unsigned ucs4_size)
{
	unsigned i;
	int rc;
	uint32_t tmp[4];
	size_t tmp_size;
	uint32_t *nrm;
	uc_general_category_t cat;
	unsigned is_invalid;

	/* make the union of Valid categories, excluding any invalid (i.e., control) */
	cat = uc_general_category_or(UC_CATEGORY_Ll, UC_CATEGORY_Lu); /* LetterDigits */
	cat = uc_general_category_or(cat, UC_CATEGORY_Lo);
	cat = uc_general_category_or(cat, UC_CATEGORY_Nd);
	cat = uc_general_category_or(cat, UC_CATEGORY_Lm);
	cat = uc_general_category_or(cat, UC_CATEGORY_Mn);
	cat = uc_general_category_or(cat, UC_CATEGORY_Mc);
	cat = uc_general_category_or(cat, UC_CATEGORY_Lt); /* OtherLetterDigits */
	cat = uc_general_category_or(cat, UC_CATEGORY_Nl);
	cat = uc_general_category_or(cat, UC_CATEGORY_No);
	cat = uc_general_category_or(cat, UC_CATEGORY_Me);
	cat = uc_general_category_or(cat, UC_CATEGORY_Sm); /* Symbols */
	cat = uc_general_category_or(cat, UC_CATEGORY_Sc);
	cat = uc_general_category_or(cat, UC_CATEGORY_So);
	cat = uc_general_category_or(cat, UC_CATEGORY_Sk);
	cat = uc_general_category_or(cat, UC_CATEGORY_Pc); /* Punctuation */
	cat = uc_general_category_or(cat, UC_CATEGORY_Pd);
	cat = uc_general_category_or(cat, UC_CATEGORY_Ps);
	cat = uc_general_category_or(cat, UC_CATEGORY_Pe);
	cat = uc_general_category_or(cat, UC_CATEGORY_Pi);
	cat = uc_general_category_or(cat, UC_CATEGORY_Pf);
	cat = uc_general_category_or(cat, UC_CATEGORY_Po);
	cat = uc_general_category_or(cat, UC_CATEGORY_Zs); /* Spaces */
	cat = uc_general_category_and_not(cat, UC_CATEGORY_Cc); /* Not in Control */

	/* check for being in the allowed sets in rfc7564#section-4.3 */
	for (i=0;i<ucs4_size;i++) {
		is_invalid = 0;

		/* Disallowed 
		   o  Old Hangul Jamo characters, i.e., the OldHangulJamo ("I") category
		      [FIXME: not handled in this code]

		   o  Control characters, i.e., the Controls ("L") category

		   o  Ignorable characters, i.e., the PrecisIgnorableProperties ("M")
		 */
		if (uc_is_property_default_ignorable_code_point(ucs4[i]) ||
		    uc_is_property_not_a_character(ucs4[i])) {
			return gnutls_assert_val(GNUTLS_E_INVALID_UTF8_STRING);
		}


		/* Contextual rules - we do not implement them / we reject chars from these sets
		   o  A number of characters from the Exceptions ("F") category defined

		   o  Joining characters, i.e., the JoinControl ("H") category defined
		 */
		rc = is_allowed_exception(ucs4[i]);
		if (rc == 0 || uc_is_property_join_control(ucs4[i]))
			return gnutls_assert_val(GNUTLS_E_INVALID_UTF8_STRING);

		if (rc == 1) /* exceptionally allowed, continue */
			continue;


		/* Replace all spaces; an RFC7613 requirement
		 */
		if (uc_is_general_category(ucs4[i], UC_CATEGORY_Zs)) /* replace */
			ucs4[i] = 0x20;

		/* Valid */
		if ((ucs4[i] < 0x21 || ucs4[i] > 0x7E) && !uc_is_general_category(ucs4[i], cat))
			is_invalid = 1;

		/* HasCompat */
		if (is_invalid) {
			tmp_size = sizeof(tmp)/sizeof(tmp[0]);
			nrm = u32_normalize(UNINORM_NFKC, &ucs4[i], 1, tmp, &tmp_size);
			if (nrm == NULL || (tmp_size == 1 && nrm[0] == ucs4[i]))
				return gnutls_assert_val(GNUTLS_E_INVALID_UTF8_STRING);
		}
	}

	return 0;
}


/**
 * gnutls_utf8_password_normalize:
 * @password: contain the UTF-8 formatted password
 * @plen: the length of the provided password
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
int gnutls_utf8_password_normalize(const unsigned char *password, unsigned plen,
				   gnutls_datum_t *out, unsigned flags)
{
	size_t ucs4_size = 0, nrm_size = 0;
	size_t final_size = 0;
	uint8_t *final = NULL;
	uint32_t *ucs4 = NULL;
	uint32_t *nrm = NULL;
	uint8_t *nrmu8 = NULL;
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
 raw_copy:
			out->data = gnutls_malloc(plen+1);
			if (out->data == NULL)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			out->size = plen;
			memcpy(out->data, password, plen);
			out->data[plen] = 0;
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

	ret = check_for_valid_freeformclass(ucs4, ucs4_size);
	if (ret < 0) {
		gnutls_assert();
		if (flags & GNUTLS_UTF8_IGNORE_ERRS) {
			free(ucs4);
			goto raw_copy;
		}
		if (ret == GNUTLS_E_INVALID_UTF8_STRING)
			ret = GNUTLS_E_INVALID_PASSWORD_STRING;
		goto fail;
	}

	/* normalize to NFC */
	nrm = u32_normalize(UNINORM_NFC, ucs4, ucs4_size, NULL, &nrm_size);
	if (nrm == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_INVALID_PASSWORD_STRING;
		goto fail;
	}

	/* convert back to UTF-8 */
	final_size = 0;
	nrmu8 = u32_to_u8(nrm, nrm_size, NULL, &final_size);
	if (nrmu8 == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_INVALID_PASSWORD_STRING;
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

	free(ucs4);
	free(nrm);
	free(nrmu8);

	out->data = final;
	out->size = final_size;

	return 0;

 fail:
	gnutls_free(final);
	free(ucs4);
	free(nrm);
	free(nrmu8);
	return ret;
}

#if defined HAVE_LIBIDN2 || defined HAVE_LIBIDN
/**
 * gnutls_idna_map:
 * @input: contain the UTF-8 formatted domain name
 * @ilen: the length of the provided string
 * @out: the result in an null-terminated allocated string
 * @flags: should be zero
 *
 * This function will convert the provided UTF-8 domain name, to
 * its IDNA mapping in an allocated variable. Note that depending on the flags the used gnutls
 * library was compiled with, the output of this function may vary (i.e.,
 * may be IDNA2008, or IDNA2003).
 *
 * To force IDNA2008 specify the flag %GNUTLS_IDNA_FORCE_2008. In
 * the case GnuTLS is not compiled with the necessary dependencies,
 * %GNUTLS_E_UNIMPLEMENTED_FEATURE will be returned to indicate that
 * gnutls is unable to perform the requested conversion.
 *
 * Note also, that this function will return an empty string if an
 * empty string is provided as input.
 *
 * Returns: %GNUTLS_E_INVALID_UTF8_STRING on invalid UTF-8 data, or 0 on success.
 *
 * Since: 3.5.8
 **/
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

	if (_gnutls_str_is_print(input, ilen)) {
		return _gnutls_set_strdatum(out, input, ilen);
	}

#ifndef HAVE_LIBIDN2
	if (flags & GNUTLS_IDNA_FORCE_2008)
		return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
#endif

	ret = _gnutls_set_strdatum(&istr, input, ilen);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

#ifdef HAVE_LIBIDN2
#if IDN2_VERSION_NUMBER >= 0x00140000
	/* IDN2_NONTRANSITIONAL automatically converts to lowercase
	 * IDN2_NFC_INPUT converts to NFC before toASCII conversion
	 *
	 * Since IDN2_NONTRANSITIONAL implicitely does NFC conversion, we don't need
	 * the additional IDN2_NFC_INPUT. But just for the unlikely case that the linked
	 * library is not matching the headers when building and it doesn't support TR46,
	 * we provide IDN2_NFC_INPUT. */

	rc = idn2_lookup_u8((uint8_t *)istr.data, (uint8_t **)&idna, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
#else
	rc = idn2_lookup_u8((uint8_t *)istr.data, (uint8_t **)&idna, IDN2_NFC_INPUT);
#endif
	if (rc != IDN2_OK) {
		gnutls_assert();
		_gnutls_debug_log("unable to convert name '%s' to IDNA format: %s\n", istr.data, idn2_strerror(rc));
		ret = GNUTLS_E_INVALID_UTF8_STRING;
		goto fail;
	}
#else
	rc = idna_to_ascii_8z((char*)istr.data, &idna, 0);
	if (rc != IDNA_SUCCESS) {
		gnutls_assert();
		_gnutls_debug_log("unable to convert name '%s' to IDNA format: %s\n", istr.data, idna_strerror(rc));
		ret = GNUTLS_E_INVALID_UTF8_STRING;
		goto fail;
	}
#endif

	if (gnutls_malloc != malloc) {
		ret = _gnutls_set_strdatum(out, idna, strlen(idna));
	} else  {
		out->data = (unsigned char*)idna;
		out->size = strlen(idna);
		idna = NULL;
		ret = 0;
	}
 fail:
#ifdef HAVE_LIBIDN2
	idn2_free(idna);
#else
	idn_free(idna);
#endif
	gnutls_free(istr.data);
	return ret;
}

#ifdef HAVE_LIBIDN2
int _idn2_punycode_decode(
	size_t input_length,
	const char input[],
	size_t *output_length,
	uint32_t output[],
	unsigned char case_flags[]);

static int _idn2_to_unicode_8z8z(const char *src, char **dst)
{
	int rc, run;
	size_t out_len = 0;
	const char *e, *s;
	char *p = NULL;

	for (run = 0; run < 2; run++) {
		if (run) {
			p = malloc(out_len + 1);
			if (!p)
				return IDN2_MALLOC;
			*dst = p;
		}

		out_len = 0;
		for (e = s = src; *e; s = e) {
			while (*e && *e != '.')
				e++;

			if (e - s > 4 && s[0] == 'x' && s[1] == 'n' && s[2] == '-' && s[3] == '-') {
				size_t u32len = IDN2_LABEL_MAX_LENGTH * 4;
				uint32_t u32[IDN2_LABEL_MAX_LENGTH * 4];
				uint8_t u8[IDN2_LABEL_MAX_LENGTH + 1];
				size_t u8len;

				rc = _idn2_punycode_decode(e - s - 4, s + 4, &u32len, u32, NULL);
				if (rc != IDN2_OK)
					return rc;

				if (rc != IDN2_OK)
					return rc;

				u8len = sizeof(u8);
				if (u32_to_u8(u32, u32len, u8, &u8len) == NULL)
					return IDN2_ENCODING_ERROR;
				u8[u8len] = '\0';

				if (run)
					memcpy(*dst + out_len, u8, u8len);
				out_len += u8len;
			} else {
				if (run)
					memcpy(*dst + out_len, s, e - s);
				out_len += e - s;
			}

			if (*e) {
				e++;
				if (run)
					(*dst)[out_len] = '.';
				out_len++;
			}
		}
	}

	(*dst)[out_len] = 0;

	return IDN2_OK;
}
#endif

/**
 * gnutls_idna_reverse_map:
 * @input: contain the ACE (IDNA) formatted domain name
 * @ilen: the length of the provided string
 * @out: the result in an null-terminated allocated UTF-8 string
 * @flags: should be zero
 *
 * This function will convert an ACE (ASCII-encoded) domain name to a UTF-8 domain name.
 *
 * If GnuTLS is compiled without IDNA support, then this function
 * will return %GNUTLS_E_UNIMPLEMENTED_FEATURE.
 *
 * Note also, that this function will return an empty string if an
 * empty string is provided as input.
 *
 * Returns: A negative error code on error, or 0 on success.
 *
 * Since: 3.5.8
 **/
int gnutls_idna_reverse_map(const char *input, unsigned ilen, gnutls_datum_t *out, unsigned flags)
{
	char *u8 = NULL;
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

#ifdef HAVE_LIBIDN2
	/* currently libidn2 just converts single labels, thus a wrapper function */
	rc = _idn2_to_unicode_8z8z((char*)istr.data, &u8);
	if (rc != IDN2_OK) {
		gnutls_assert();
		_gnutls_debug_log("unable to convert ACE name '%s' to UTF-8 format: %s\n", istr.data, idn2_strerror(rc));
		ret = GNUTLS_E_INVALID_UTF8_STRING;
		goto fail;
	}
#else
	rc = idna_to_unicode_8z8z((char*)istr.data, &u8, IDNA_ALLOW_UNASSIGNED);
	if (rc != IDNA_SUCCESS) {
		gnutls_assert();
		_gnutls_debug_log("unable to convert ACE name '%s' to UTF-8 format: %s\n", istr.data, idna_strerror(rc));
		ret = GNUTLS_E_INVALID_UTF8_STRING;
		goto fail;
	}
#endif

	if (gnutls_malloc != malloc) {
		ret = _gnutls_set_strdatum(out, u8, strlen(u8));
	} else  {
		out->data = (unsigned char*)u8;
		out->size = strlen(u8);
		u8 = NULL;
		ret = 0;
	}
 fail:
#ifdef HAVE_LIBIDN2
	idn2_free(u8);
#else
	idn_free(u8);
#endif
	gnutls_free(istr.data);
	return ret;
}

#else

# undef gnutls_idna_map
int gnutls_idna_map(const char *input, unsigned ilen, gnutls_datum_t *out, unsigned flags)
{
	if (!_gnutls_str_is_print(input, ilen)) {
		return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
	}

	return _gnutls_set_strdatum(out, input, ilen);
}

int gnutls_idna_reverse_map(const char *input, unsigned ilen, gnutls_datum_t *out, unsigned flags)
{
	return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
}
#endif /* HAVE_LIBIDN2 */

int _gnutls_idna_email_map(const char *input, unsigned ilen, gnutls_datum_t *output)
{
	const char *p = input;

	while(*p != 0 && *p != '@') {
		if (!c_isprint(*p))
			return gnutls_assert_val(GNUTLS_E_INVALID_UTF8_EMAIL);
		p++;
	}

	if (_gnutls_str_is_print(input, ilen)) {
		return _gnutls_set_strdatum(output, input, ilen);
	}

	if (*p == '@') {
		unsigned name_part = p-input;
		int ret;
		gnutls_datum_t domain;

		ret = gnutls_idna_map(p+1, ilen-name_part-1, &domain, 0);
		if (ret < 0)
			return gnutls_assert_val(ret);

		output->data = gnutls_malloc(name_part+1+domain.size+1);
		if (output->data == NULL) {
			gnutls_free(domain.data);
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		}
		memcpy(output->data, input, name_part);
		output->data[name_part] = '@';
		memcpy(&output->data[name_part+1], domain.data, domain.size);
		output->data[name_part+domain.size+1] = 0;
		output->size = name_part+domain.size+1;
		gnutls_free(domain.data);
		return 0;
	} else {
		return gnutls_assert_val(GNUTLS_E_INVALID_UTF8_EMAIL);
	}
}
