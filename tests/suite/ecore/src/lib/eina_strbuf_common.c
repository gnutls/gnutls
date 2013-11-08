#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <Evil.h>
#endif

#include "eina_private.h"
#include "eina_str.h"
#include "eina_magic.h"
#include "eina_error.h"
#include "eina_safety_checks.h"
#include "eina_strbuf.h"
#include "eina_strbuf_common.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#define EINA_STRBUF_INIT_SIZE 32
#define EINA_STRBUF_INIT_STEP 32
#define EINA_STRBUF_MAX_STEP 4096

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the strbuf module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the strbuf module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_strbuf_common_init(void)
{
	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the strbuf module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the strbuf module set up by
 * eina_strbuf_common_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_strbuf_common_shutdown(void)
{
	return EINA_TRUE;
}

/**
 * @internal
 *
 * init the buffer
 * @param buf the buffer to init
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 */
static Eina_Bool _eina_strbuf_common_init(size_t csize, Eina_Strbuf * buf)
{
	buf->len = 0;
	buf->size = EINA_STRBUF_INIT_SIZE;
	buf->step = EINA_STRBUF_INIT_STEP;

	eina_error_set(0);
	buf->buf = calloc(csize, buf->size);
	if (EINA_UNLIKELY(!buf->buf)) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return EINA_FALSE;
	}

	return EINA_TRUE;
}

/**
 * @internal
 *
 * resize the buffer
 * @param buf the buffer to resize
 * @param size the minimum size of the buffer
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 */
static inline Eina_Bool
_eina_strbuf_common_resize(size_t csize, Eina_Strbuf * buf, size_t size)
{
	size_t new_size, new_step, delta;
	void *buffer;

	size += 1;		// Add extra space for '\0'

	if (size == buf->size)
		/* nothing to do */
		return EINA_TRUE;
	else if (size > buf->size)
		delta = size - buf->size;
	else
		delta = buf->size - size;

	/* check if should keep the same step (just used while growing) */
	if ((delta <= buf->step) && (size > buf->size))
		new_step = buf->step;
	else {
		new_step = (((delta / EINA_STRBUF_INIT_STEP) + 1)
			    * EINA_STRBUF_INIT_STEP);

		if (new_step > EINA_STRBUF_MAX_STEP)
			new_step = EINA_STRBUF_MAX_STEP;
	}

	new_size = (((size / new_step) + 1) * new_step);

	/* reallocate the buffer to the new size */
	buffer = realloc(buf->buf, new_size * csize);
	if (EINA_UNLIKELY(!buffer)) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return EINA_FALSE;
	}

	buf->buf = buffer;
	buf->size = new_size;
	buf->step = new_step;
	eina_error_set(0);
	return EINA_TRUE;
}

/**
 * @internal
 *
 * If required, enlarge the buffer to fit the new size.
 *
 * @param buf the buffer to resize
 * @param size the minimum size of the buffer
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 */
Eina_Bool
_eina_strbuf_common_grow(size_t csize, Eina_Strbuf * buf, size_t size)
{
	if ((size + 1) < buf->size)
		return EINA_TRUE;

	return _eina_strbuf_common_resize(csize, buf, size);
}

/**
 * @internal
 *
 * insert string of known length at random within existing strbuf limits.
 *
 * @param buf the buffer to resize, must be valid.
 * @param str the string to copy, must be valid (!NULL and smaller than @a len)
 * @param len the amount of bytes in @a str to copy, must be valid.
 * @param pos the position inside buffer to insert, must be valid (smaller
 *        than eina_strbuf_common_length_get())
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 */
static inline Eina_Bool
_eina_strbuf_common_insert_length(size_t csize,
				  Eina_Strbuf * buf,
				  const void *str, size_t len, size_t pos)
{
	if (EINA_UNLIKELY
	    (!_eina_strbuf_common_grow(csize, buf, buf->len + len)))
		return EINA_FALSE;

	/* move the existing text */
	memmove(buf->buf + ((len + pos) * csize), buf->buf + (pos * csize),
		(buf->len - pos) * csize);

	/* and now insert the given string */
	memcpy(buf->buf + (pos * csize), str, len * csize);

	buf->len += len;
	memset(buf->buf + (buf->len * csize), 0, csize);
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @brief Create a new string buffer.
 *
 * @return Newly allocated string buffer instance.
 *
 * This function creates a new string buffer. On error, @c NULL is
 * returned and Eina error is set to #EINA_ERROR_OUT_OF_MEMORY. To
 * free the resources, use eina_strbuf_common_free().
 *
 * @see eina_strbuf_common_free()
 * @see eina_strbuf_common_append()
 * @see eina_strbuf_common_string_get()
 */
Eina_Strbuf *eina_strbuf_common_new(size_t csize)
{
	Eina_Strbuf *buf;

	eina_error_set(0);
	buf = malloc(sizeof(Eina_Strbuf));
	if (EINA_UNLIKELY(!buf)) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	if (EINA_UNLIKELY(!_eina_strbuf_common_init(csize, buf))) {
		eina_strbuf_common_free(buf);
		return NULL;
	}

	return buf;
}

/**
 * @brief Free a string buffer.
 *
 * @param buf The string buffer to free.
 *
 * This function frees the memory of @p buf. @p buf must have been
 * created by eina_strbuf_common_new().
 */
void eina_strbuf_common_free(Eina_Strbuf * buf)
{
	free(buf->buf);
	free(buf);
}

/**
 * @brief Reset a string buffer.
 *
 * @param buf The string buffer to reset.
 *
 * This function reset @p buf: the buffer len is set to 0, and the
 * string is set to '\\0'. No memory is free'd.
 */
void eina_strbuf_common_reset(size_t csize, Eina_Strbuf * buf)
{
	buf->len = 0;
	buf->step = EINA_STRBUF_INIT_STEP;

	memset(buf->buf, 0, csize);
}

/**
 * @brief Append a string to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends @p str to @p buf. It computes the length of
 * @p str, so is slightly slower than eina_strbuf_common_append_length(). If
 * the length is known beforehand, consider using that variant. If
 * @p buf can't append it, #EINA_FALSE is returned, otherwise
 * #EINA_TRUE is returned.
 *
 * @see eina_strbuf_common_append()
 * @see eina_strbuf_common_append_length()
 */
Eina_Bool
eina_strbuf_common_append(size_t csize,
			  Eina_Strbuf * buf, const void *str, size_t len)
{

	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (EINA_UNLIKELY
	    (!_eina_strbuf_common_grow(csize, buf, buf->len + len)))
		return EINA_FALSE;

	memcpy(buf->buf + (buf->len * csize), str, (len + 1) * csize);
	buf->len += len;
	return EINA_TRUE;
}

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
 * eina_strbuf_common_append_length(). If the length is known beforehand,
 * consider using that variant (@p maxlen should then be checked so
 * that it is greater than the size of @p str). If @p str can not be
 * appended, #EINA_FALSE is returned, otherwise, #EINA_TRUE is
 * returned.
 *
 * @see eina_strbuf_common_append()
 * @see eina_strbuf_common_append_length()
 */
Eina_Bool
eina_strbuf_common_append_n(size_t csize,
			    Eina_Strbuf * buf,
			    const void *str, size_t len, size_t maxlen)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (len > maxlen)
		len = maxlen;

	if (EINA_UNLIKELY
	    (!_eina_strbuf_common_grow(csize, buf, buf->len + len)))
		return EINA_FALSE;

	memcpy(buf->buf + (buf->len * csize), str, len * csize);
	buf->len += len;
	memset(buf->buf + (buf->len * csize), 0, csize);
	return EINA_TRUE;
}

/**
 * @brief Append a string of exact length to a buffer, reallocating as necessary.
 *
 * @param buf The string buffer to append to.
 * @param str The string to append.
 * @param length The exact length to use.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function appends @p str to @p buf. @p str must be of size at
 * most @p length. It is slightly faster than eina_strbuf_common_append() as
 * it does not compute the size of @p str. It is useful when dealing
 * with strings of known size, such as eina_strngshare. If @p buf
 * can't append it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 *
 * @see eina_stringshare_length()
 * @see eina_strbuf_common_append()
 * @see eina_strbuf_common_append_n()
 */
Eina_Bool
eina_strbuf_common_append_length(size_t csize,
				 Eina_Strbuf * buf,
				 const void *str, size_t length)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (EINA_UNLIKELY
	    (!_eina_strbuf_common_grow(csize, buf, buf->len + length)))
		return EINA_FALSE;

	memcpy(buf->buf + (buf->len * csize), str, length * csize);
	buf->len += length;
	memset(buf->buf + (buf->len * csize), 0, csize);
	return EINA_TRUE;
}

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
 * eina_strbuf_common_insert_length(). If  the length is known beforehand,
 * consider using that variant. If @p buf can't insert it, #EINA_FALSE
 * is returned, otherwise #EINA_TRUE is returned.
 */
Eina_Bool
eina_strbuf_common_insert(size_t csize,
			  Eina_Strbuf * buf,
			  const void *str, size_t len, size_t pos)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (pos >= buf->len)
		return eina_strbuf_common_append(csize, buf, str, len);

	return _eina_strbuf_common_insert_length(csize, buf, str, len,
						 pos);
}

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
 * @p str, so is slightly slower than eina_strbuf_common_insert_length(). If the
 * length is known beforehand, consider using that variant (@p maxlen
 * should then be checked so that it is greater than the size of
 * @p str). If @p str can not be inserted, #EINA_FALSE is returned,
 * otherwise, #EINA_TRUE is returned.
 */
Eina_Bool
eina_strbuf_common_insert_n(size_t csize,
			    Eina_Strbuf * buf,
			    const void *str,
			    size_t len, size_t maxlen, size_t pos)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (pos >= buf->len)
		return eina_strbuf_common_append_n(csize, buf, str, len,
						   maxlen);

	if (len > maxlen)
		len = maxlen;

	return _eina_strbuf_common_insert_length(csize, buf, str, len,
						 pos);
}

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
 * most @p length. It is slightly faster than eina_strbuf_common_insert() as
 * it does not compute the size of @p str. It is useful when dealing
 * with strings of known size, such as eina_strngshare. If @p buf
 * can't insert it, #EINA_FALSE is returned, otherwise #EINA_TRUE is
 * returned.
 *
 * @see eina_stringshare_length()
 * @see eina_strbuf_common_insert()
 * @see eina_strbuf_common_insert_n()
 */
Eina_Bool
eina_strbuf_common_insert_length(size_t csize,
				 Eina_Strbuf * buf,
				 const void *str,
				 size_t length, size_t pos)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);

	if (pos >= buf->len)
		return eina_strbuf_common_append_length(csize, buf, str,
							length);

	return _eina_strbuf_common_insert_length(csize, buf, str, length,
						 pos);
}

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
Eina_Bool
eina_strbuf_common_append_char(size_t csize, Eina_Strbuf * buf,
			       const void *c)
{

	if (EINA_UNLIKELY
	    (!_eina_strbuf_common_grow(csize, buf, buf->len + 1)))
		return EINA_FALSE;

	memcpy(buf->buf + ((buf->len)++ * csize), c, csize);
	memset(buf->buf + (buf->len * csize), 0, csize);
	return EINA_TRUE;
}

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
Eina_Bool
eina_strbuf_common_insert_char(size_t csize,
			       Eina_Strbuf * buf,
			       const void *c, size_t pos)
{

	if (pos >= buf->len)
		return eina_strbuf_common_append_char(csize, buf, c);

	return _eina_strbuf_common_insert_length(csize, buf, c, 1, pos);
}

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
Eina_Bool
eina_strbuf_common_remove(size_t csize,
			  Eina_Strbuf * buf, size_t start, size_t end)
{
	size_t remove_len, tail_len;

	if (end >= buf->len)
		end = buf->len;

	if (end <= start)
		return EINA_TRUE;

	remove_len = end - start;
	if (remove_len == buf->len) {
		free(buf->buf);
		return _eina_strbuf_common_init(csize, buf);
	}

	tail_len = buf->len - end + 1;	/* includes '\0' */
	memmove(buf->buf + (start * csize),
		buf->buf + (end * csize), tail_len * csize);
	buf->len -= remove_len;
	return _eina_strbuf_common_resize(csize, buf, buf->len);
}

/**
 * @brief Retrieve a pointer to the contents of a string buffer
 *
 * @param buf The string buffer.
 * @return The current string in the string buffer.
 *
 * This function returns the string contained in @p buf. The returned
 * value must not be modified and will no longer be valid if @p buf is
 * modified. In other words, any eina_strbuf_common_append() or similar will
 * make that pointer invalid.
 *
 * @see eina_strbuf_common_string_steal()
 */
const void *eina_strbuf_common_string_get(const Eina_Strbuf * buf)
{
	return buf->buf;
}

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
 * @see eina_strbuf_common_string_get()
 */
void *eina_strbuf_common_string_steal(size_t csize, Eina_Strbuf * buf)
{
	void *ret;

	ret = buf->buf;
	// TODO: Check return value and do something clever
	_eina_strbuf_common_init(csize, buf);
	return ret;
}

/**
 * @brief Free the contents of a string buffer but not the buffer.
 *
 * @param buf The string buffer to free the string of.
 *
 * This function frees the string contained in @p buf without freeing
 * @p buf.
 */
void eina_strbuf_common_string_free(size_t csize, Eina_Strbuf * buf)
{
	free(buf->buf);
	_eina_strbuf_common_init(csize, buf);
}

/**
 * @brief Retrieve the length of the string buffer content.
 *
 * @param buf The string buffer.
 * @return The current length of the string, in bytes.
 *
 * This function returns the length of @p buf.
 */
size_t eina_strbuf_common_length_get(const Eina_Strbuf * buf)
{
	return buf->len;
}

/**
 * @addtogroup Eina_String_Buffer_Group String Buffer
 *
 * @brief These functions provide string buffers management.
 *
 * The String Buffer data type is designed to be a mutable string,
 * allowing to append, prepend or insert a string to a buffer.
 *
 * @{
 */


/**
 * @cond LOCAL
 */

/*FIXME: Implementing them here is a hack! */

#ifdef _STRBUF_CSIZE
#undef _STRBUF_CSIZE
#endif

#ifdef _STRBUF_MAGIC
#undef _STRBUF_MAGIC
#endif

#ifdef _STRBUF_MAGIC_STR
#undef _STRBUF_MAGIC_STR
#endif

#define _STRBUF_CSIZE 1
#define _STRBUF_MAGIC             EINA_MAGIC_STRBUF
#define _STRBUF_MAGIC_STR         __STRBUF_STR_MAGIC_STR
static const char __STRBUF_STR_MAGIC_STR[] = "Eina Strbuf";


/**
 * @endcond
 */


/**
 * @brief Replace the n-th string with an other string.
 *
 * @param buf The string buffer to work with.
 * @param str The string to replace.
 * @param with The replaceing string.
 * @param n The number of the fitting string.
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function replaces the n-th occurrence of @p str in @p buf with
 * @p with. It returns #EINA_FALSE on failure, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_strbuf_replace(Eina_Strbuf * buf,
		    const char *str, const char *with, unsigned int n)
{
	size_t len1, len2;
	char *spos;
	size_t pos;

	EINA_SAFETY_ON_NULL_RETURN_VAL(str, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(with, EINA_FALSE);
	EINA_MAGIC_CHECK_STRBUF(buf, 0);

	if (n == 0)
		return EINA_FALSE;

	spos = buf->buf;
	while (n--) {
		spos = strstr(spos, str);
		if (!spos || *spos == '\0')
			return EINA_FALSE;

		if (n)
			spos++;
	}

	pos = spos - (const char *) buf->buf;
	len1 = strlen(str);
	len2 = strlen(with);
	if (len1 != len2) {
		/* resize the buffer if necessary */
		if (EINA_UNLIKELY
		    (!_eina_strbuf_common_grow
		     (_STRBUF_CSIZE, buf, buf->len - len1 + len2))) {
			return EINA_FALSE;	/* move the existing text */

		}

		memmove(buf->buf + pos + len2, buf->buf + pos + len1,
			buf->len - pos - len1);
	}

	/* and now insert the given string */
	memcpy(buf->buf + pos, with, len2);
	buf->len += len2 - len1;
	memset((char *) buf->buf + buf->len, 0, 1);

	return EINA_TRUE;
}

/**
 * @brief Replace all strings with an other string.

 * @param buf the string buffer to work with.
 * @param str The string to replace.
 * @param with The replaceing string.
 * @return How often the string was replaced.
 *
 * This function replaces all the occurrences of @p str in @ buf with
 * the string @p with. This function returns the number of times @p str
 * has been replaced. On failure, it returns 0.
 */
EAPI int
eina_strbuf_replace_all(Eina_Strbuf * buf, const char *str,
			const char *with)
{
	size_t len1, len2, len;
	char *tmp_buf = NULL;
	char *spos;
	size_t pos, start;
	size_t pos_tmp, start_tmp;
	int n = 0;

	EINA_SAFETY_ON_NULL_RETURN_VAL(str, 0);
	EINA_SAFETY_ON_NULL_RETURN_VAL(with, 0);
	EINA_MAGIC_CHECK_STRBUF(buf, 0);

	spos = strstr(buf->buf, str);
	if (!spos || *spos == '\0')
		return 0;

	len1 = strlen(str);
	len2 = strlen(with);

	/* if the size of the two string is equal, it is fairly easy to replace them
	 * we don't need to resize the buffer or doing other calculations */
	if (len1 == len2) {
		while (spos) {
			memcpy(spos, with, len2);
			spos = strstr(spos + len2, str);
			n++;
		}
		return n;
	}

	pos = pos_tmp = spos - (const char *) buf->buf;
	tmp_buf = buf->buf;
	buf->buf = malloc(buf->size);
	if (EINA_UNLIKELY(!buf->buf)) {
		buf->buf = tmp_buf;
		return 0;
	}

	start = start_tmp = 0;
	len = buf->len;

	while (spos) {
		n++;
		len = (len + len2) - len1;
		/* resize the buffer if necessary */
		if (EINA_UNLIKELY
		    (!_eina_strbuf_common_grow(_STRBUF_CSIZE, buf, len))) {
			/* we have to stop replacing here, because we haven't enough
			 * memory to go on */
			len = (len + len1) - len2;
			break;
		}

		/* copy the untouched text */
		memcpy(buf->buf + start, tmp_buf + start_tmp, pos - start);
		/* copy the new string */
		memcpy(buf->buf + pos, with, len2);

		/* calculate the next positions */
		start_tmp = pos_tmp + len1;
		start = pos + len2;
		spos = strstr(tmp_buf + start_tmp, str);
		/* this calculations don't make sense if spos == NULL, but the
		 * calculated values won't be used, because the loop will stop
		 * then */
		pos_tmp = spos - tmp_buf;
		pos = start + pos_tmp - start_tmp;
	}
	/* and now copy the rest of the text */
	memcpy(buf->buf + start, tmp_buf + start_tmp, len - start);
	buf->len = len;
	memset((char *) buf->buf + buf->len, 0, 1);

	free(tmp_buf);

	return n;
}

/**
 * @}
 */
