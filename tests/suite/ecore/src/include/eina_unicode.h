#ifndef EINA_UNICODE_H
#define EINA_UNICODE_H

#include <stdlib.h>

#include "eina_config.h"
#include "eina_types.h"

/**
 * @addtogroup Eina_Data_Types_Group Data Types
 *
 * @{
 */
/**
 * @addtogroup Eina_Unicode_String Unicode String
 *
 * @brief These functions provide basic unicode string handling
 *
 * Eina_Unicode is a type that holds unicode codepoints.
 *
 * @{
 */

/**
 * @typedef Eina_Unicode
 * A type that holds Unicode codepoints.
 */
#if EINA_SIZEOF_WCHAR_T >= 4
#include <wchar.h>
typedef wchar_t Eina_Unicode;
#elif defined(EINA_HAVE_INTTYPES_H)
#include <inttypes.h>
typedef uint32_t Eina_Unicode;
#elif defined(EINA_HAVE_STDINT_H)
#include <stdint.h>
typedef uint32_t Eina_Unicode;
#else
/* Hope that int is big enough */
typedef unsigned int Eina_Unicode;
#endif

EAPI extern const Eina_Unicode *EINA_UNICODE_EMPTY_STRING;

EAPI size_t eina_unicode_strlen(const Eina_Unicode *
				ustr) EINA_ARG_NONNULL(1)
EINA_WARN_UNUSED_RESULT EINA_PURE;
EAPI size_t eina_unicode_strnlen(const Eina_Unicode * ustr,
				 int n) EINA_ARG_NONNULL(1)
EINA_WARN_UNUSED_RESULT EINA_PURE;


EAPI Eina_Unicode *eina_unicode_strdup(const Eina_Unicode * text)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1) EINA_MALLOC;

EAPI int eina_unicode_strcmp(const Eina_Unicode * a,
			     const Eina_Unicode * b)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1, 2) EINA_PURE;

EAPI Eina_Unicode *eina_unicode_strcpy(Eina_Unicode * dest,
				       const Eina_Unicode *
				       source) EINA_ARG_NONNULL(1, 2);

EAPI Eina_Unicode *eina_unicode_strstr(const Eina_Unicode * haystack,
				       const Eina_Unicode * needle)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1, 2) EINA_PURE;

EAPI Eina_Unicode *eina_unicode_strncpy(Eina_Unicode * dest,
					const Eina_Unicode * source,
					size_t n) EINA_ARG_NONNULL(1, 2);

EAPI Eina_Unicode *eina_unicode_escape(const Eina_Unicode *
				       str) EINA_ARG_NONNULL(1)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;

/**
 * @}
 */
/**
 * @}
 */

#endif
