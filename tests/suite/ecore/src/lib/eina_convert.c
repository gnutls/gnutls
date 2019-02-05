/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric BAIL, Vincent Torri
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_log.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_convert.h"
#include "eina_fp.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

static const char look_up_table[] = { '0', '1', '2', '3', '4',
	'5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f'
};

static int _eina_convert_log_dom = -1;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_convert_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_convert_log_dom, __VA_ARGS__)

#define HEXA_TO_INT(Hexa) (Hexa >= 'a') ? Hexa - 'a' + 10 : Hexa - '0'

static inline void reverse(char s[], int length)
{
	int i, j;
	char c;

	for (i = 0, j = length - 1; i < j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

EAPI Eina_Error EINA_ERROR_CONVERT_P_NOT_FOUND = 0;
EAPI Eina_Error EINA_ERROR_CONVERT_0X_NOT_FOUND = 0;
EAPI Eina_Error EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH = 0;

static const char EINA_ERROR_CONVERT_0X_NOT_FOUND_STR[] =
    "Error during string conversion to float, First '0x' was not found.";
static const char EINA_ERROR_CONVERT_P_NOT_FOUND_STR[] =
    "Error during string conversion to float, First 'p' was not found.";
static const char EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH_STR[] =
    "Error outrun string limit during conversion string conversion to float.";

/**
 * @endcond
 */

/**
 * @internal
 * @brief Initialize the convert module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the convert module of Eina. It is called by
 * eina_init().
 *
 * This function sets up the error module of Eina and registers the
 * errors #EINA_ERROR_CONVERT_0X_NOT_FOUND,
 * #EINA_ERROR_CONVERT_P_NOT_FOUND and
 * #EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH.
 *
 * @see eina_init()
 */
Eina_Bool eina_convert_init(void)
{
	_eina_convert_log_dom = eina_log_domain_register("eina_convert",
							 EINA_LOG_COLOR_DEFAULT);
	if (_eina_convert_log_dom < 0) {
		EINA_LOG_ERR
		    ("Could not register log domain: eina_convert");
		return EINA_FALSE;
	}
#define EEMR(n) n = eina_error_msg_static_register(n ## _STR)
	EEMR(EINA_ERROR_CONVERT_0X_NOT_FOUND);
	EEMR(EINA_ERROR_CONVERT_P_NOT_FOUND);
	EEMR(EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH);
#undef EEMR

	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the convert module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the convert module set up by
 * eina_convert_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_convert_shutdown(void)
{
	eina_log_domain_unregister(_eina_convert_log_dom);
	_eina_convert_log_dom = -1;
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Convert_Group Convert
 *
 * These functions allow you to convert integer or real numbers to
 * string or conversely.
 *
 * To use these functions, you have to call eina_init()
 * first, and eina_shutdown() when eina is not used anymore.
 *
 * @section Eina_Convert_From_Integer_To_Sring Conversion from integer to string
 *
 * To convert an integer to a string in the decimal base,
 * eina_convert_itoa() should be used. If the hexadecimal base is
 * wanted, eina_convert_xtoa() should be used. They all need a bufffer
 * sufficiently large to store all the cyphers.
 *
 * Here is an example of use:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <Eina.h>
 *
 * int main(void)
 * {
 *    char tmp[128];
 *
 *    if (!eina_init())
 *    {
 *        printf ("Error during the initialization of eina.\n");
 *        return EXIT_FAILURE;
 *    }
 *
 *    eina_convert_itoa(45, tmp);
 *    printf("value: %s\n", tmp);

 *    eina_convert_xtoa(0xA1, tmp);
 *    printf("value: %s\n", tmp);
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * Compile this code with the following command:
 *
 * @code
 * gcc -Wall -o test_eina_convert test_eina.c `pkg-config --cflags --libs eina`
 * @endcode
 *
 * @note
 * The alphabetical cyphers are in lower case.
 *
 * @section Eina_Convert_Double Conversion double / string
 *
 * To convert a double to a string, eina_convert_dtoa() should be
 * used. Like with the integer functions, a buffer must be used. The
 * resulting string ghas the following format (which is the result
 * obtained with snprintf() and the @%a modifier):
 *
 * @code
 * [-]0xh.hhhhhp[+-]e
 * @endcode
 *
 * To convert a string to a double, eina_convert_atod() should be
 * used. The format of the string must be as above. Then, the double
 * has the following mantiss and exponent:
 *
 * @code
 * mantiss  : [-]hhhhhh
 * exponent : 2^([+-]e - 4 * n)
 * @endcode
 *
 * with n being number of cypers after the point in the string
 * format. To obtain the double number from the mantiss and exponent,
 * use ldexp().
 *
 * Here is an example of use:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 * #include <math.h>
 *
 * #include <Eina.h>
 *
 * int main(void)
 * {
 *    char      tmp[128];
 *    long long int m = 0;
 *    long int  e = 0;
 *    double    r;
 *
 *    if (!eina_init())
 *    {
 *        printf ("Error during the initialization of eina.\n");
 *        return EXIT_FAILURE;
 *    }
 *
 *    printf("initial value : 40.56\n");
 *    eina_convert_dtoa(40.56, tmp);
 *    printf("result dtoa   : %s\n", tmp);

 *    eina_convert_atod(tmp, 128, &m, &e);
 *    r = ldexp((double)m, e);
 *    printf("result atod   : %f\n", r);
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * Compile this code with the following command:
 *
 * @code
 * gcc -Wall -o test_eina_convert test_eina.c `pkg-config --cflags --libs eina` -lm
 * @endcode
 *
 * @{
 */

/*
 * Come from the second edition of The C Programming Language ("K&R2") on page 64
 */

/**
 * @brief Convert an integer number to a string in decimal base.
 *
 * @param n The integer to convert.
 * @param s The buffer to store the converted integer.
 * @return The length of the string, including the nul terminated
 * character.
 *
 * This function converts @p n to a nul terminated string. The
 * converted string is in decimal base. As no check is done, @p s must
 * be a buffer that is sufficiently large to store the integer.
 *
 * The returned value is the length of the string, including the nul
 * terminated character.
 */
EAPI int eina_convert_itoa(int n, char *s)
{
	int i = 0;
	int r = 0;

	EINA_SAFETY_ON_NULL_RETURN_VAL(s, 0);

	if (n < 0) {
		n = -n;
		*s++ = '-';
		r = 1;
	}

	do {
		s[i++] = n % 10 + '0';
	} while ((n /= 10) > 0);

	s[i] = '\0';

	reverse(s, i);

	return i + r;
}

/**
 * @brief Convert an integer number to a string in hexadecimal base.
 *
 * @param n The integer to convert.
 * @param s The buffer to store the converted integer.
 * @return The length of the string, including the nul terminated
 * character.
 *
 * This function converts @p n to a nul terminated string. The
 * converted string is in hexadecimal base and the alphabetical
 * cyphers are in lower case. As no check is done, @p s must be a
 * buffer that is sufficiently large to store the integer.
 *
 * The returned value is the length of the string, including the nul
 * terminated character.
 */
EAPI int eina_convert_xtoa(unsigned int n, char *s)
{
	int i;

	EINA_SAFETY_ON_NULL_RETURN_VAL(s, 0);

	i = 0;
	do {
		s[i++] = look_up_table[n & 0xF];
	} while ((n >>= 4) > 0);

	s[i] = '\0';

	reverse(s, i);

	return i;
}

/**
 * @brief Convert a string to a double.
 *
 * @param src The string to convert.
 * @param length The length of the string.
 * @param m The mantisse.
 * @param e The exponent.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function converts the string @p s of length @p length that
 * represent a double in hexadecimal base to a double. It is used to
 * replace the use of snprintf() with the \%a modifier, which is
 * missing on some platform (like Windows (tm) or OpenBSD).
 *
 * The string must have the following format:
 *
 * @code
 * [-]0xh.hhhhhp[+-]e
 * @endcode
 *
 * where the h are the hexadecimal cyphers of the mantiss and e the
 * exponent (a decimal number). If n is the number of cypers after the
 * point, the returned mantiss and exponents are:
 *
 * @code
 * mantiss  : [-]hhhhhh
 * exponent : 2^([+-]e - 4 * n)
 * @endcode
 *
 * The mantiss and exponent are stored in the buffers pointed
 * respectively by @p m and @p e.
 *
 * If the string is invalid, the error is set to:
 *
 * @li #EINA_ERROR_CONVERT_0X_NOT_FOUND if no 0x is found,
 * @li #EINA_ERROR_CONVERT_P_NOT_FOUND if no p is found,
 * @li #EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH if @p length is not
 * correct.
 *
 * In those cases, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 */
EAPI Eina_Bool
eina_convert_atod(const char *src, int length, long long *m, long *e)
{
	const char *str = src;
	long long mantisse;
	long exponent;
	int nbr_decimals = 0;
	int sign = 1;

	EINA_SAFETY_ON_NULL_RETURN_VAL(src, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(m, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(e, EINA_FALSE);

	if (length <= 0)
		goto on_length_error;

	/* Compute the mantisse. */
	if (*str == '-') {
		sign = -1;
		str++;
		length--;
	}

	if (length <= 2)
		goto on_length_error;

	if (strncmp(str, "0x", 2)) {
		eina_error_set(EINA_ERROR_CONVERT_0X_NOT_FOUND);
		DBG("'0x' not found in '%s'", src);
		return EINA_FALSE;
	}

	str += 2;
	length -= 2;

	mantisse = HEXA_TO_INT(*str);

	str++;
	length--;
	if (length <= 0)
		goto on_length_error;

	if (*str == '.')
		for (str++, length--;
		     length > 0 && *str != 'p';
		     ++str, --length, ++nbr_decimals) {
			mantisse <<= 4;
			mantisse += HEXA_TO_INT(*str);
		}

	if (sign < 0)
		mantisse = -mantisse;

	/* Compute the exponent. */
	if (*str != 'p') {
		eina_error_set(EINA_ERROR_CONVERT_P_NOT_FOUND);
		DBG("'p' not found in '%s'", src);
		return EINA_FALSE;
	}

	sign = +1;

	str++;
	length--;
	if (length <= 0)
		goto on_length_error;

	if (strchr("-+", *str)) {
		sign = (*str == '-') ? -1 : +1;

		str++;
		length--;
	}

	for (exponent = 0; length > 0 && *str != '\0'; ++str, --length) {
		exponent *= 10;
		exponent += *str - '0';
	}

	if (length < 0)
		goto on_length_error;

	if (sign < 0)
		exponent = -exponent;

	*m = mantisse;
	*e = exponent - (nbr_decimals << 2);

	return EINA_TRUE;

      on_length_error:
	eina_error_set(EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH);
	return EINA_FALSE;
}

/**
 * @brief Convert a double to a string.
 *
 * @param d The double to convert.
 * @param des The destination buffer to store the converted double.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function converts the double @p d to a string. The string is
 * stored in the buffer pointed by @p des and must be sufficiently
 * large to contain the converted double. The returned string is nul
 * terminated and has the following format:
 *
 * @code
 * [-]0xh.hhhhhp[+-]e
 * @endcode
 *
 * where the h are the hexadecimal cyphers of the mantiss and e the
 * exponent (a decimal number).
 *
 * The returned value is the length of the string, including the nul
 * character.
 */
EAPI int eina_convert_dtoa(double d, char *des)
{
	int length = 0;
	int p;
	int i;

	EINA_SAFETY_ON_NULL_RETURN_VAL(des, EINA_FALSE);

	if (d < 0.0) {
		*(des++) = '-';
		d = -d;
		length++;
	}

	d = frexp(d, &p);

	if (p) {
		d *= 2;
		p -= 1;
	}

	*(des++) = '0';
	*(des++) = 'x';
	*(des++) = look_up_table[(size_t) d];
	*(des++) = '.';
	length += 4;

	for (i = 0; i < 16; i++, length++) {
		d -= floor(d);
		d *= 16;
		*(des++) = look_up_table[(size_t) d];
	}

	while (*(des - 1) == '0') {
		des--;
		length--;
	}

	if (*(des - 1) == '.') {
		des--;
		length--;
	}

	*(des++) = 'p';
	if (p < 0) {
		*(des++) = '-';
		p = -p;
	} else
		*(des++) = '+';

	length += 2;

	return length + eina_convert_itoa(p, des);
}

/**
 * @brief Convert a 32.32 fixed point number to a string.
 *
 * @param fp The fixed point number to convert.
 * @param des The destination buffer to store the converted fixed point number.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function converts the 32.32 fixed point number @p fp to a
 * string. The string is stored in the buffer pointed by @p des and
 * must be sufficiently large to contain the converted fixed point
 * number. The returned string is terminated and has the following
 * format:
 *
 * @code
 * [-]0xh.hhhhhp[+-]e
 * @endcode
 *
 * where the h are the hexadecimal cyphers of the mantiss and e the
 * exponent (a decimal number).
 *
 * The returned value is the length of the string, including the nul
 * character.
 *
 * @note The code is the same than eina_convert_dtoa() except that it
 * implements the frexp() function for fixed point numbers and does
 * some optimisations.
 */
EAPI int eina_convert_fptoa(Eina_F32p32 fp, char *des)
{
	int length = 0;
	int p = 0;
	int i;

	EINA_SAFETY_ON_NULL_RETURN_VAL(des, EINA_FALSE);

	if (fp == 0) {
		memcpy(des, "0x0p+0", 7);
		return 7;
	}

	if (fp < 0) {
		*(des++) = '-';
		fp = -fp;
		length++;
	}

	/* fp >= 1 */
	if (fp >= 0x0000000100000000LL)
		while (fp >= 0x0000000100000000LL) {
			p++;
			/* fp /= 2 */
			fp >>= 1;
		} /* fp < 0.5 */
	else if (fp < 0x80000000)
		while (fp < 0x80000000) {
			p--;
			/* fp *= 2 */
			fp <<= 1;
		}

	if (p) {
		p--;
		/* fp *= 2 */
		fp <<= 1;
	}

	*(des++) = '0';
	*(des++) = 'x';
	*(des++) = look_up_table[fp >> 32];
	*(des++) = '.';
	length += 4;

	for (i = 0; i < 16; i++, length++) {
		fp &= 0x00000000ffffffffLL;
		fp <<= 4;	/* fp *= 16 */
		*(des++) = look_up_table[fp >> 32];
	}

	while (*(des - 1) == '0') {
		des--;
		length--;
	}

	if (*(des - 1) == '.') {
		des--;
		length--;
	}

	*(des++) = 'p';
	if (p < 0) {
		*(des++) = '-';
		p = -p;
	} else
		*(des++) = '+';

	length += 2;

	return length + eina_convert_itoa(p, des);
}

/**
 * @brief Convert a string to a 32.32 fixed point number.
 *
 * @param src The string to convert.
 * @param length The length of the string.
 * @param fp The fixed point number.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function converts the string @p src of length @p length that
 * represent a double in hexadecimal base to a 32.32 fixed point
 * number stored in @p fp. The function always tries to convert the
 * string with eina_convert_atod().
 *
 * The string must have the following format:
 *
 * @code
 * [-]0xh.hhhhhp[+-]e
 * @endcode
 *
 * where the h are the hexadecimal cyphers of the mantiss and e the
 * exponent (a decimal number). If n is the number of cypers after the
 * point, the returned mantiss and exponents are:
 *
 * @code
 * mantiss  : [-]hhhhhh
 * exponent : 2^([+-]e - 4 * n)
 * @endcode
 *
 * The mantiss and exponent are stored in the buffers pointed
 * respectively by @p m and @p e.
 *
 * If the string is invalid, the error is set to:
 *
 * @li #EINA_ERROR_CONVERT_0X_NOT_FOUND if no 0x is found,
 * @li #EINA_ERROR_CONVERT_P_NOT_FOUND if no p is found,
 * @li #EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH if @p length is not
 * correct.
 *
 * In those cases, or if @p fp is @c NULL, #EINA_FALSE is returned,
 * otherwise @p fp is computed and #EINA_TRUE is returned.
 *
 * @note The code uses eina_convert_atod() and do the correct bit
 * shift to compute the fixed point number.
 */
EAPI Eina_Bool
eina_convert_atofp(const char *src, int length, Eina_F32p32 * fp)
{
	long long m;
	long e;

	if (!eina_convert_atod(src, length, &m, &e))
		return EINA_FALSE;

	if (!fp)
		return EINA_TRUE;

	e += 32;

	if (e > 0)
		*fp = m << e;
	else
		*fp = m >> -e;

	return EINA_TRUE;
}

/**
 * @}
 */
