/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

#if defined(HAVE_LIBUNISTRING)

# include <cmocka.h>

#define MATCH_FUNC(fname, password, normalized) \
static void fname(void **glob_state) \
{ \
	gnutls_datum_t out; \
	int ret = gnutls_utf8_password_normalize((uint8_t*)password, strlen(password), &out, 0); \
	if (normalized == NULL) { /* expect failure */ \
		assert_int_not_equal(ret, 0); \
		return; \
	} else { \
		assert_int_equal(ret, 0); \
	} \
	assert_int_equal(strcmp((char*)out.data, (char*)normalized), 0); \
	gnutls_free(out.data); \
}

#define INVALID_MATCH_FUNC(fname, password, normalized) \
static void inv_##fname(void **glob_state) \
{ \
	gnutls_datum_t out; \
	int ret = gnutls_utf8_password_normalize((uint8_t*)password, strlen(password), &out, GNUTLS_UTF8_IGNORE_ERRS); \
	if (normalized == NULL) { \
		assert_int_not_equal(ret, 0); \
		return; \
	} else { \
		assert_int_equal(ret, 0); \
	} \
	assert_int_equal(strcmp((char*)out.data, (char*)normalized), 0); \
	gnutls_free(out.data); \
}

MATCH_FUNC(test_ascii, "correct horse battery staple", "correct horse battery staple");
MATCH_FUNC(test_capitals, "Correct Horse Battery Staple", "Correct Horse Battery Staple");
MATCH_FUNC(test_multilang, "\xCF\x80\xC3\x9F\xC3\xA5", "πßå");
MATCH_FUNC(test_special_char, "\x4A\x61\x63\x6B\x20\x6F\x66\x20\xE2\x99\xA6\x73", "Jack of ♦s");
MATCH_FUNC(test_space_replacement, "foo bar", "foo bar");
MATCH_FUNC(test_invalid, "my cat is a \x09by", NULL);
MATCH_FUNC(test_normalization1, "char \x49\xCC\x87", "char \xC4\xB0");

INVALID_MATCH_FUNC(test_ascii, "correct horse battery staple", "correct horse battery staple");
INVALID_MATCH_FUNC(test_special_char, "\x4A\x61\x63\x6B\x20\x6F\x66\x20\xE2\x99\xA6\x73", "Jack of ♦s");
INVALID_MATCH_FUNC(test_invalid, "my cat is a \x09by", "my cat is a \x09by");

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ascii),
		cmocka_unit_test(test_capitals),
		cmocka_unit_test(test_multilang),
		cmocka_unit_test(test_special_char),
		cmocka_unit_test(test_space_replacement),
		cmocka_unit_test(test_invalid),
		cmocka_unit_test(test_normalization1),
		cmocka_unit_test(inv_test_ascii),
		cmocka_unit_test(inv_test_special_char),
		cmocka_unit_test(inv_test_invalid)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
#else
int main(void)
{
	gnutls_datum_t out;
	int ret = gnutls_utf8_password_normalize((uint8_t*)"xxx", strlen("xxx"), &out, 0);
	if (ret != GNUTLS_E_UNIMPLEMENTED_FEATURE)
		exit(1);
	exit(77);
}
#endif
