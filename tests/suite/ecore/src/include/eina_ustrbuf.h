#ifndef EINA_USTRBUF_H
#define EINA_USTRBUF_H

#include <stddef.h>

#include "eina_types.h"
#include "eina_unicode.h"

/**
 * @addtogroup Eina_Data_Types_Group Data Types
 *
 * @{
 */

/**
 * @defgroup Eina_Unicode_String_Buffer_Group Unicode String Buffer
 *
 * @{
 */

/**
 * @typedef Eina_UStrbuf
 * Type for a string buffer.
 */
typedef struct _Eina_Strbuf Eina_UStrbuf;

/**
 * @brief Create a new string buffer.
 *
 * @return Newly allocated string buffer instance.
 *
 * This function creates a new string buffer. On error, @c NULL is
 * returned and Eina error is set to #EINA_ERROR_OUT_OF_MEMORY. To
 * free the resources, use eina_ustrbuf_free().
 *
 * @see eina_ustrbuf_free()
 * @see eina_ustrbuf_append()
 * @see eina_ustrbuf_string_get()
 */
EAPI Eina_UStrbuf *eina_ustrbuf_new(void)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;

/**
 * @brief Free a string buffer.
 *
 * @param buf The string buffer to free.
 *
 * This function frees the memory of @p buf. @p buf must have been
 * created by eina_ustrbuf_new().
 */
EAPI void eina_ustrbuf_free(Eina_UStrbuf * buf) EINA_ARG_NONNULL(1);

/**
 * @brief Reset a string buffer.
 *
 * @param buf The string buffer to reset.
 *
 * This function reset @p buf: the buffer len is set to 0, and the
 * string is set to '\\0'. No memory is free'd.
 */
EAPI void eina_ustrbuf_reset(Eina_UStrbuf * buf) EINA_ARG_NONNULL(1);

/**
 * @brief Append a string to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends @p str to @p buf. It computes the length of
 * @p str, so is slightly slower than eina_ustrbuf_append_length(). If
 * the length is known beforehand, consider using that variant. If
 * @p buf can't append it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 *
 * @see eina_ustrbuf_append()
 * @see eina_ustrbuf_append_length()
 */
EAPI Eina_Bool eina_ustrbuf_append(Eina_UStrbuf * buf,
				   const Eina_Unicode *
				   str) EINA_ARG_NONNULL(1, 2);

/**
 * @brief Append an escaped string to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends the escaped string @p str to @p buf. If @p
 * str can not be appended, #EINA_FALSE is returned, otherwise,
 * #EINA_TRUE is returned.
 */
EAPI Eina_Bool eina_ustrbuf_append_escaped(Eina_UStrbuf * buf,
					   const Eina_Unicode *
					   str) EINA_ARG_NONNULL(1, 2);

/**
 * @brief Append a string to a buffer, reallocating as necessary,
 * limited by the given length.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @param maxlen The maximum number of characters to append.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends at most @p maxlen characters of @p str to
 * @p buf. It can't appends more than the length of @p str. It
 * computes the length of @p str, so is slightly slower than
 * eina_ustrbuf_append_length(). If the length is known beforehand,
 * consider using that variant (@p maxlen should then be checked so
 * that it is greater than the size of @p str). If @p str can not be
 * appended, #EINA_FALSE is returned, otherwise, #EINA_TRUE is
 * returned.
 *
 * @see eina_ustrbuf_append()
 * @see eina_ustrbuf_append_length()
 */
EAPI Eina_Bool eina_ustrbuf_append_n(Eina_UStrbuf * buf,
				     const Eina_Unicode * str,
				     size_t maxlen) EINA_ARG_NONNULL(1, 2);

/**
 * @brief Append a string of exact length to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @param length The exact length to use.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends @p str to @p buf. @p str must be of size at
 * most @p length. It is slightly faster than eina_ustrbuf_append() as
 * it does not compute the size of @p str. It is useful when dealing
 * with strings of known size, such as eina_strngshare. If @p buf
 * can't append it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 *
 * @see eina_stringshare_length()
 * @see eina_ustrbuf_append()
 * @see eina_ustrbuf_append_n()
 */
EAPI Eina_Bool eina_ustrbuf_append_length(Eina_UStrbuf * buf,
					  const Eina_Unicode * str,
					  size_t length)
EINA_ARG_NONNULL(1, 2);

/**
 * @brief Append a character to a string buffer, reallocating as
 * necessary.
 *
 * @param buf The string buffer to append to.
 * @param c The char to append.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts @p c to @p buf. If it can not insert it,
 * #EINA_FALSE is returned, otherwise #EINA_TRUE is returned.
 */
EAPI Eina_Bool eina_ustrbuf_append_char(Eina_UStrbuf * buf,
					Eina_Unicode c)
EINA_ARG_NONNULL(1);

/**
 * @brief Insert a string to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to insert.
 * @param str The string to insert.
 * @param pos The position to insert the string.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts @p str to @p buf at position @p pos. It
 * computes the length of @p str, so is slightly slower than
 * eina_ustrbuf_insert_length(). If  the length is known beforehand,
 * consider using that variant. If @p buf can't insert it, #EINA_FALSE
 * is returned, otherwise #EINA_TRUE is returned.
 */
EAPI Eina_Bool eina_ustrbuf_insert(Eina_UStrbuf * buf,
				   const Eina_Unicode * str,
				   size_t pos) EINA_ARG_NONNULL(1, 2);

/**
 * @brief Insert an escaped string to a buffer, reallocating as
 * necessary.
 *
 * @param buf The string buffer to insert to.
 * @param str The string to insert.
 * @param pos The position to insert the string.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts the escaped string @p str to @p buf at
 * position @p pos. If @p buf can't insert @p str, #EINA_FALSE is
 * returned, otherwise #EINA_TRUE is returned.
 */
EAPI Eina_Bool eina_ustrbuf_insert_escaped(Eina_UStrbuf * buf,
					   const Eina_Unicode * str,
					   size_t pos) EINA_ARG_NONNULL(1,
									2);

/**
 * @brief Insert a string to a buffer, reallocating as necessary. Limited by maxlen.
 *
 * @param buf The string buffer to insert to.
 * @param str The string to insert.
 * @param maxlen The maximum number of chars to insert.
 * @param pos The position to insert the string.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts @p str ot @p buf at position @p pos, with at
 * most @p maxlen bytes. The number of inserted characters can not be
 * greater than the length of @p str. It computes the length of
 * @p str, so is slightly slower than eina_ustrbuf_insert_length(). If the
 * length is known beforehand, consider using that variant (@p maxlen
 * should then be checked so that it is greater than the size of
 * @p str). If @p str can not be inserted, #EINA_FALSE is returned,
 * otherwise, #EINA_TRUE is returned.
 */
EAPI Eina_Bool eina_ustrbuf_insert_n(Eina_UStrbuf * buf,
				     const Eina_Unicode * str,
				     size_t maxlen,
				     size_t pos) EINA_ARG_NONNULL(1, 2);

/**
 * @brief Insert a string of exact length to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to insert to.
 * @param str The string to insert.
 * @param length The exact length to use.
 * @param pos The position to insert the string.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts @p str to @p buf. @p str must be of size at
 * most @p length. It is slightly faster than eina_ustrbuf_insert() as
 * it does not compute the size of @p str. It is useful when dealing
 * with strings of known size, such as eina_strngshare. If @p buf
 * can't insert it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 *
 * @see eina_stringshare_length()
 * @see eina_ustrbuf_insert()
 * @see eina_ustrbuf_insert_n()
 */
EAPI Eina_Bool eina_ustrbuf_insert_length(Eina_UStrbuf * buf,
					  const Eina_Unicode * str,
					  size_t length,
					  size_t pos) EINA_ARG_NONNULL(1,
								       2);

/**
 * @brief Insert a character to a string buffer, reallocating as
 * necessary.
 *
 * @param buf The string buffer to insert to.
 * @param c The char to insert.
 * @param pos The position to insert the char.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function inserts @p c to @p buf at position @p pos. If @p buf
 * can't append it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 */
EAPI Eina_Bool eina_ustrbuf_insert_char(Eina_UStrbuf * buf, Eina_Unicode c,
					size_t pos) EINA_ARG_NONNULL(1);

/**
 * @def eina_ustrbuf_prepend(buf, str)
 * @brief Prepend the given string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param str The string to prepend.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert() at position 0.If @p buf
 * can't prepend it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 */
#define eina_ustrbuf_prepend(buf, str) eina_ustrbuf_insert(buf, str, 0)

/**
 * @def eina_ustrbuf_prepend_escaped(buf, str)
 * @brief Prepend the given escaped string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param str The string to prepend.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_escaped() at position 0. If
 * @p buf can't prepend it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 */
#define eina_ustrbuf_prepend_escaped(buf, str) eina_ustrbuf_insert_escaped(buf, str, 0)

/**
 * @def eina_ustrbuf_prepend_n(buf, str)
 * @brief Prepend the given escaped string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param str The string to prepend.
 * @param maxlen The maximum number of Eina_Unicode *s to prepend.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_n() at position 0. If
 * @p buf can't prepend it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 */
#define eina_ustrbuf_prepend_n(buf, str, maxlen) eina_ustrbuf_insert_n(buf, str, maxlen, 0)

/**
 * @def eina_ustrbuf_prepend_length(buf, str)
 * @brief Prepend the given escaped string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param str The string to prepend.
 * @param length The exact length to use.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_length() at position 0. If
 * @p buf can't prepend it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 */
#define eina_ustrbuf_prepend_length(buf, str, length) eina_ustrbuf_insert_length(buf, str, length, 0)

/**
 * @def eina_ustrbuf_prepend_Eina_Unicode *(buf, str)
 * @brief Prepend the given Eina_Unicode *acter to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param c The Eina_Unicode *acter to prepend.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_Eina_Unicode *() at position 0. If
 * @p buf can't prepend it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 */
#define eina_ustrbuf_prepend_Eina_Unicode *(buf, c)eina_ustrbuf_insert_Eina_Unicode * (buf, c, 0)

/**
 * @def eina_ustrbuf_prepend_printf(buf, fmt, ...)
 * @brief Prepend the given string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param fmt The string to prepend.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_printf() at position 0.If @p buf
 * can't prepend it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 */
#define eina_ustrbuf_prepend_printf(buf, fmt, ...) eina_ustrbuf_insert_printf(buf, fmt, 0, ## __VA_ARGS__)

/**
 * @def eina_ustrbuf_prepend_vprintf(buf, fmt, args)
 * @brief Prepend the given string to the given buffer
 *
 * @param buf The string buffer to prepend to.
 * @param fmt The string to prepend.
 * @param args The variable arguments.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This macro is calling eina_ustrbuf_insert_vprintf() at position 0.If @p buf
 * can't prepend it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 */
#define eina_ustrbuf_prepend_vprintf(buf, fmt, args) eina_ustrbuf_insert_vprintf(buf, fmt, 0, args)

/**
 * @brief Remove a slice of the given string buffer.
 *
 * @param buf The string buffer to remove a slice.
 * @param start The initial (inclusive) slice position to start
 *        removing, in bytes.
 * @param end The final (non-inclusive) slice position to finish
 *        removing, in bytes.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function removes a slice of @p buf, starting at @p start
 * (inclusive) and ending at @p end (non-inclusive). Both values are
 * in bytes. It returns #EINA_FALSE on failure, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_ustrbuf_remove(Eina_UStrbuf * buf, size_t start,
		    size_t end) EINA_ARG_NONNULL(1);

/**
 * @brief Retrieve a pointer to the contents of a string buffer
 *
 * @param buf The string buffer.
 * @return The current string in the string buffer.
 *
 * This function returns the string contained in @p buf. The returned
 * value must not be modified and will no longer be valid if @p buf is
 * modified. In other words, any eina_ustrbuf_append() or similar will
 * make that pointer invalid.
 *
 * @see eina_ustrbuf_string_steal()
 */
EAPI const Eina_Unicode *eina_ustrbuf_string_get(const Eina_UStrbuf *
						 buf) EINA_ARG_NONNULL(1)
    EINA_WARN_UNUSED_RESULT;

/**
 * @brief Steal the contents of a string buffer.
 *
 * @param buf The string buffer to steal.
 * @return The current string in the string buffer.
 *
 * This function returns the string contained in @p buf. @p buf is
 * then initialized and does not own the returned string anymore. The
 * caller must release the memory of the returned string by calling
 * free().
 *
 * @see eina_ustrbuf_string_get()
 */
EAPI Eina_Unicode *eina_ustrbuf_string_steal(Eina_UStrbuf * buf)
EINA_MALLOC EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);

/**
 * @brief Free the contents of a string buffer but not the buffer.
 *
 * @param buf The string buffer to free the string of.
 *
 * This function frees the string contained in @p buf without freeing
 * @p buf.
 */
EAPI void eina_ustrbuf_string_free(Eina_UStrbuf * buf) EINA_ARG_NONNULL(1);

/**
 * @brief Retrieve the length of the string buffer content.
 *
 * @param buf The string buffer.
 * @return The current length of the string, in bytes.
 *
 * This function returns the length of @p buf.
 */
EAPI size_t
eina_ustrbuf_length_get(const Eina_UStrbuf *
			buf) EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_STRBUF_H */
