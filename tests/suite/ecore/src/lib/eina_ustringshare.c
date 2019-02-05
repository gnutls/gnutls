/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler,
 *                         Jorge Luis Zapata Muga,
 *                         Cedric Bail,
 *                         Gustavo Sverzut Barbieri
 *                         Tom Hacohen
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
/**
 * @page tutorial_ustringshare_page UStringshare Tutorial
 *
 * to be written...
 *
 */

#include "eina_share_common.h"
#include "eina_unicode.h"
#include "eina_private.h"
#include "eina_ustringshare.h"

/* The actual share */
static Eina_Share *ustringshare_share;
static const char EINA_MAGIC_USTRINGSHARE_NODE_STR[] =
    "Eina UStringshare Node";

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the share_common module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the share_common module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_ustringshare_init(void)
{
	return eina_share_common_init(&ustringshare_share,
				      EINA_MAGIC_USTRINGSHARE_NODE,
				      EINA_MAGIC_USTRINGSHARE_NODE_STR);
}

/**
 * @internal
 * @brief Shut down the share_common module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the share_common module set up by
 * eina_share_common_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_ustringshare_shutdown(void)
{
	Eina_Bool ret;
	ret = eina_share_common_shutdown(&ustringshare_share);
	return ret;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/
/**
 * @addtogroup Eina_UStringshare_Group Unicode Stringshare
 *
 * These functions allow you to store one copy of a string, and use it
 * throughout your program.
 *
 * This is a method to reduce the number of duplicated strings kept in
 * memory. It's pretty common for the same strings to be dynamically
 * allocated repeatedly between applications and libraries, especially in
 * circumstances where you could have multiple copies of a structure that
 * allocates the string. So rather than duplicating and freeing these
 * strings, you request a read-only pointer to an existing string and
 * only incur the overhead of a hash lookup.
 *
 * It sounds like micro-optimizing, but profiling has shown this can have
 * a significant impact as you scale the number of copies up. It improves
 * string creation/destruction speed, reduces memory use and decreases
 * memory fragmentation, so a win all-around.
 *
 * For more information, you can look at the @ref tutorial_ustringshare_page.
 *
 * @{
 */

/**
 * @brief Note that the given string has lost an instance.
 *
 * @param str string The given string.
 *
 * This function decreases the reference counter associated to @p str
 * if it exists. If that counter reaches 0, the memory associated to
 * @p str is freed. If @p str is NULL, the function returns
 * immediately.
 *
 * Note that if the given pointer is not shared or NULL, bad things
 * will happen, likely a segmentation fault.
 */
EAPI void eina_ustringshare_del(const Eina_Unicode * str)
{
	if (!str)
		return;

	eina_share_common_del(ustringshare_share, (const char *) str);
}

/**
 * @brief Retrieve an instance of a string for use in a program.
 *
 * @param   str The string to retrieve an instance of.
 * @param   slen The string size (<= strlen(str)).
 * @return  A pointer to an instance of the string on success.
 *          @c NULL on failure.
 *
 * This function retrieves an instance of @p str. If @p str is
 * @c NULL, then @c NULL is returned. If @p str is already stored, it
 * is just returned and its reference counter is increased. Otherwise
 * it is added to the strings to be searched and a duplicated string
 * of @p str is returned.
 *
 * This function does not check string size, but uses the
 * exact given size. This can be used to share_common part of a larger
 * buffer or substring.
 *
 * @see eina_ustringshare_add()
 */
EAPI const Eina_Unicode *eina_ustringshare_add_length(const Eina_Unicode *
						      str,
						      unsigned int slen)
{
	return (const Eina_Unicode *)
	    eina_share_common_add_length(ustringshare_share,
					 (const char *) str,
					 slen * sizeof(Eina_Unicode),
					 sizeof(Eina_Unicode));
}

/**
 * @brief Retrieve an instance of a string for use in a program.
 *
 * @param   str The NULL terminated string to retrieve an instance of.
 * @return  A pointer to an instance of the string on success.
 *          @c NULL on failure.
 *
 * This function retrieves an instance of @p str. If @p str is
 * @c NULL, then @c NULL is returned. If @p str is already stored, it
 * is just returned and its reference counter is increased. Otherwise
 * it is added to the strings to be searched and a duplicated string
 * of @p str is returned.
 *
 * The string @p str must be NULL terminated ('@\0') and its full
 * length will be used. To use part of the string or non-null
 * terminated, use eina_stringshare_add_length() instead.
 *
 * @see eina_ustringshare_add_length()
 */
EAPI const Eina_Unicode *eina_ustringshare_add(const Eina_Unicode * str)
{
	int slen = (str) ? (int) eina_unicode_strlen(str) : -1;
	return eina_ustringshare_add_length(str, slen);
}

/**
 * Increment references of the given shared string.
 *
 * @param str The shared string.
 * @return    A pointer to an instance of the string on success.
 *            @c NULL on failure.
 *
 * This is similar to eina_share_common_add(), but it's faster since it will
 * avoid lookups if possible, but on the down side it requires the parameter
 * to be shared before, in other words, it must be the return of a previous
 * eina_ustringshare_add().
 *
 * There is no unref since this is the work of eina_ustringshare_del().
 */
EAPI const Eina_Unicode *eina_ustringshare_ref(const Eina_Unicode * str)
{
	return (const Eina_Unicode *)
	    eina_share_common_ref(ustringshare_share, (const char *) str);
}

/**
 * @brief Note that the given string @b must be shared.
 *
 * @param str the shared string to know the length. It is safe to
 *        give NULL, in that case -1 is returned.
 *
 * This function is a cheap way to known the length of a shared
 * string. Note that if the given pointer is not shared, bad
 * things will happen, likely a segmentation fault. If in doubt, try
 * strlen().
 */
EAPI int eina_ustringshare_strlen(const Eina_Unicode * str)
{
	int len =
	    eina_share_common_length(ustringshare_share,
				     (const char *) str);
	len = (len > 0) ? len / (int) sizeof(Eina_Unicode) : -1;
	return len;
}

/**
 * @brief Dump the contents of the share_common.
 *
 * This function dumps all strings in the share_common to stdout with a
 * DDD: prefix per line and a memory usage summary.
 */
EAPI void eina_ustringshare_dump(void)
{
	eina_share_common_dump(ustringshare_share, NULL, 0);
}

/**
 * @}
 */
