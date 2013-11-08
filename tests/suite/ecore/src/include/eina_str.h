#ifndef _EINA_STR_H
#define _EINA_STR_H

#include <stddef.h>
#include <string.h>

#include "eina_types.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_String_Group String
 *
 * @{
 */

/* strlcpy implementation for libc's lacking it */
EAPI size_t eina_strlcpy(char *dst, const char *src,
			 size_t siz) EINA_ARG_NONNULL(1, 2);
EAPI size_t eina_strlcat(char *dst, const char *src,
			 size_t siz) EINA_ARG_NONNULL(1, 2);

EAPI Eina_Bool eina_str_has_prefix(const char *str, const char *prefix)
EINA_PURE EINA_ARG_NONNULL(1, 2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Bool eina_str_has_suffix(const char *str, const char *suffix)
EINA_PURE EINA_ARG_NONNULL(1, 2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Bool eina_str_has_extension(const char *str, const char *ext)
EINA_PURE EINA_ARG_NONNULL(1, 2) EINA_WARN_UNUSED_RESULT;

EAPI char **eina_str_split(const char *string, const char *delimiter,
			   int max_tokens) EINA_ARG_NONNULL(1, 2)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI char **eina_str_split_full(const char *string, const char *delimiter,
				int max_tokens,
				unsigned int *elements) EINA_ARG_NONNULL(1,
									 2,
									 4)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;

EAPI size_t eina_str_join_len(char *dst, size_t size, char sep,
			      const char *a, size_t a_len, const char *b,
			      size_t b_len) EINA_ARG_NONNULL(1, 4, 6);

EAPI char *eina_str_convert(const char *enc_from, const char *enc_to,
			    const char *text)
EINA_WARN_UNUSED_RESULT EINA_MALLOC EINA_ARG_NONNULL(1, 2, 3);

EAPI char *eina_str_escape(const char *str)
EINA_WARN_UNUSED_RESULT EINA_MALLOC EINA_ARG_NONNULL(1);

EAPI void eina_str_tolower(char **str);
EAPI void eina_str_toupper(char **str);

static inline size_t eina_str_join(char *dst, size_t size, char sep,
				   const char *a,
				   const char *b) EINA_ARG_NONNULL(1, 4,
								   5);

/**
 * @def eina_str_join_static(dst, sep, a, b)
 * @brief Join two static strings and store the result in a static buffer.
 *
 * @param dst The buffer to store the result.
 * @param sep The separator character to use.
 * @param a First string to use, before @p sep.
 * @param b Second string to use, after @p sep.
 * @return The number of characters printed.
 *
 * This function is similar to eina_str_join_len(), but will assume
 * string sizes are know using sizeof(X).
 *
 * @see eina_str_join()
 * @see eina_str_join_static()
 */
#define eina_str_join_static(dst, sep, a, b) eina_str_join_len(dst, sizeof(dst), sep, a, (sizeof(a) > 0) ? sizeof(a) - 1 : 0, b, (sizeof(b) > 0) ? sizeof(b) - 1 : 0)

static inline size_t eina_strlen_bounded(const char *str, size_t maxlen)
EINA_PURE EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);

#include "eina_inline_str.x"

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_STR_H */
