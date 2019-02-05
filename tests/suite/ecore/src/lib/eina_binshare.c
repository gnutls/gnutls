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
 * @page tutorial_binshare_page Binary Share Tutorial
 *
 * Should call eina_binshare_init() before usage and eina_binshare_shutdown() after.
 * to be written...
 *
 */

#include "eina_share_common.h"
#include "eina_unicode.h"
#include "eina_private.h"
#include "eina_binshare.h"

/* The actual share */
static Eina_Share *binshare_share;
static const char EINA_MAGIC_BINSHARE_NODE_STR[] = "Eina Binshare Node";

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
EAPI Eina_Bool eina_binshare_init(void)
{
	return eina_share_common_init(&binshare_share,
				      EINA_MAGIC_BINSHARE_NODE,
				      EINA_MAGIC_BINSHARE_NODE_STR);
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
EAPI Eina_Bool eina_binshare_shutdown(void)
{
	Eina_Bool ret;
	ret = eina_share_common_shutdown(&binshare_share);
	return ret;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/
/**
 * @addtogroup Eina_Binshare_Group Binary Share
 *
 * These functions allow you to store one copy of an object, and use it
 * throughout your program.
 *
 * This is a method to reduce the number of duplicated objects kept in
 * memory.
 *
 * For more information, you can look at the @ref tutorial_binshare_page.
 *
 * @{
 */

/**
 * @brief Note that the given object has lost an instance.
 *
 * @param obj object The given object.
 *
 * This function decreases the reference counter associated to @p obj
 * if it exists. If that counter reaches 0, the memory associated to
 * @p obj is freed. If @p obj is NULL, the function returns
 * immediately.
 *
 * Note that if the given pointer is not shared or NULL, bad things
 * will happen, likely a segmentation fault.
 */
EAPI void eina_binshare_del(const void *obj)
{
	if (!obj)
		return;

	eina_share_common_del(binshare_share, obj);
}

/**
 * @brief Retrieve an instance of an object for use in a program.
 *
 * @param   obj The binary object to retrieve an instance of.
 * @param   olen The byte size
 * @return  A pointer to an instance of the object on success.
 *          @c NULL on failure.
 *
 * This function retrieves an instance of @p obj. If @p obj is
 * @c NULL, then @c NULL is returned. If @p obj is already stored, it
 * is just returned and its reference counter is increased. Otherwise
 * it is added to the objects to be searched and a duplicated object
 * of @p obj is returned.
 *
 * This function does not check object size, but uses the
 * exact given size. This can be used to share part of a larger
 * object or subobject.
 *
 * @see eina_binshare_add()
 */
EAPI const void *eina_binshare_add_length(const void *obj,
					  unsigned int olen)
{
	return eina_share_common_add_length(binshare_share,
					    obj, (olen) * sizeof(char), 0);
}

/**
 * Increment references of the given shared object.
 *
 * @param obj The shared object.
 * @return    A pointer to an instance of the object on success.
 *            @c NULL on failure.
 *
 * This is similar to eina_share_common_add(), but it's faster since it will
 * avoid lookups if possible, but on the down side it requires the parameter
 * to be shared before, in other words, it must be the return of a previous
 * eina_binshare_add().
 *
 * There is no unref since this is the work of eina_binshare_del().
 */
EAPI const void *eina_binshare_ref(const void *obj)
{
	return eina_share_common_ref(binshare_share, obj);
}

/**
 * @brief Note that the given object @b must be shared.
 *
 * @param obj the shared object to know the length. It is safe to
 *        give NULL, in that case -1 is returned.
 *
 * This function is a cheap way to known the length of a shared
 * object. Note that if the given pointer is not shared, bad
 * things will happen, likely a segmentation fault. If in doubt, try
 * strlen().
 */
EAPI int eina_binshare_length(const void *obj)
{
	return eina_share_common_length(binshare_share, obj);
}

/**
 * @brief Dump the contents of the share_common.
 *
 * This function dumps all objects in the share_common to stdout with a
 * DDD: prefix per line and a memory usage summary.
 */
EAPI void eina_binshare_dump(void)
{
	eina_share_common_dump(binshare_share, NULL, 0);
}

/**
 * @}
 */
