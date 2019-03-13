/* EINA - EFL data type library
 * Copyright (C) 2010 Tom Hacohen,
 *		Brett Nash
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <https://www.gnu.org/licenses/>.

 */

#include <Eina.h>
#include "eina_unicode.h"

/* FIXME: check if sizeof(wchar_t) == sizeof(Eina_Unicode) if so,
 * probably better to use the standard functions */

/* Maybe I'm too tired, but this is the only thing that actually worked. */
const Eina_Unicode _EINA_UNICODE_EMPTY_STRING[1] = { 0 };

EAPI const Eina_Unicode *EINA_UNICODE_EMPTY_STRING =
    _EINA_UNICODE_EMPTY_STRING;
/**
 * @brief Same as the standard strcmp just with Eina_Unicode instead of char.
 */
EAPI int
eina_unicode_strcmp(const Eina_Unicode * a, const Eina_Unicode * b)
{
	for (; *a && *a == *b; a++, b++);
	if (*a == *b)
		return 0;
	else if (*a < *b)
		return -1;
	else
		return 1;
}

/**
 * @brief Same as the standard strcpy just with Eina_Unicode instead of char.
 */
EAPI Eina_Unicode *eina_unicode_strcpy(Eina_Unicode * dest,
				       const Eina_Unicode * source)
{
	Eina_Unicode *ret = dest;

	while (*source)
		*dest++ = *source++;
	*dest = 0;
	return ret;
}

/**
 * @brief Same as the standard strncpy just with Eina_Unicode instead of char.
 */
EAPI Eina_Unicode *eina_unicode_strncpy(Eina_Unicode * dest,
					const Eina_Unicode * source,
					size_t n)
{
	Eina_Unicode *ret = dest;

	for (; n && *source; n--)
		*dest++ = *source++;
	for (; n; n--)
		*dest++ = 0;
	return ret;
}

/**
 * @brief Same as the standard strlen just with Eina_Unicode instead of char.
 */
EAPI size_t eina_unicode_strlen(const Eina_Unicode * ustr)
{
	const Eina_Unicode *end;
	for (end = ustr; *end; end++);
	return end - ustr;
}

/**
 * @brief Returns the length of a Eina_Unicode string, up to a limit.
 *
 * This function returns the number of characters in string, up to a maximum
 * of n.  If the terminating character is not found in the string, it returns
 * n.
 *
 * @param ustr String to search
 * @param n Max length to search
 * @return Number of characters or n.
 */
EAPI size_t eina_unicode_strnlen(const Eina_Unicode * ustr, int n)
{
	const Eina_Unicode *end;
	const Eina_Unicode *last = ustr + n;	/* technically not portable ;-) */
	for (end = ustr; end < last && *end; end++);
	return end - ustr;
}




/**
 * @brief Same as the standard strdup just with Eina_Unicode instead of char.
 */
EAPI Eina_Unicode *eina_unicode_strdup(const Eina_Unicode * text)
{
	Eina_Unicode *ustr;
	int len;

	len = eina_unicode_strlen(text);
	ustr = (Eina_Unicode *) calloc(len + 1, sizeof(Eina_Unicode));
	memcpy(ustr, text, len * sizeof(Eina_Unicode));

	return ustr;
}

/**
 * @brief Same as the standard strdup just with Eina_Unicode instead of char.
 */
EAPI Eina_Unicode *eina_unicode_strstr(const Eina_Unicode * haystack,
				       const Eina_Unicode * needle)
{
	const Eina_Unicode *i, *j;

	for (i = haystack; *i; i++) {
		haystack = i;	/* set this location as the base position */
		for (j = needle; *j && *i && *j == *i; j++, i++);

		if (!*j) {	/*if we got to the end of j this means we got a full match */
			return (Eina_Unicode *) haystack;	/* return the new base position */
		}
	}

	return NULL;
}

/**
 * @see eina_str_escape()
 */
EAPI Eina_Unicode *eina_unicode_escape(const Eina_Unicode * str)
{
	Eina_Unicode *s2, *d;
	const Eina_Unicode *s;

	s2 = malloc((eina_unicode_strlen(str) * 2) + 1);
	if (!s2)
		return NULL;

	for (s = str, d = s2; *s != 0; s++, d++) {
		if ((*s == ' ') || (*s == '\\') || (*s == '\'')) {
			*d = '\\';
			d++;
		}

		*d = *s;
	}
	*d = 0;
	return s2;
}
