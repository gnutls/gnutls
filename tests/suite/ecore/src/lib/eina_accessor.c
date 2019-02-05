/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Cedric Bail
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

#include <stdlib.h>

#include "eina_config.h"
#include "eina_private.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_accessor.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

static const char EINA_MAGIC_ACCESSOR_STR[] = "Eina Accessor";

#define EINA_MAGIC_CHECK_ACCESSOR(d)                            \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_ACCESSOR)) {              \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_ACCESSOR); }                  \
     } while(0)

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the accessor module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the accessor module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_accessor_init(void)
{
	return eina_magic_string_set(EINA_MAGIC_ACCESSOR,
				     EINA_MAGIC_ACCESSOR_STR);
}

/**
 * @internal
 * @brief Shut down the accessor module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the accessor module set up by
 * eina_accessor_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_accessor_shutdown(void)
{
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Accessor_Group Accessor Functions
 *
 * @brief These functions manage accessor on containers.
 *
 * These functions allow to access elements of a container in a
 * generic way, without knowing which container is used (a bit like
 * iterators in the C++ STL). Accessors allows random access (that is, any
 * element in the container). For sequential access, see
 * @ref Eina_Iterator_Group.
 *
 * An accessor is created from container data types, so no creation
 * function is available here. An accessor is deleted with
 * eina_accessor_free(). To get the data of an element at a given
 * position, use eina_accessor_data_get(). To call a function on
 * chosen elements of a container, use eina_accessor_over().
 *
 * @{
 */

/**
 * @brief Free an accessor.
 *
 * @param accessor The accessor to free.
 *
 * This function frees @p accessor if it is not @c NULL;
 */
EAPI void eina_accessor_free(Eina_Accessor * accessor)
{
	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN(accessor);
	EINA_SAFETY_ON_NULL_RETURN(accessor->free);
	accessor->free(accessor);
}

/**
 * @brief Return the container of an accessor.
 *
 * @param accessor The accessor.
 * @return The container which created the accessor.
 *
 * This function returns the container which created @p accessor. If
 * @p accessor is @c NULL, this function returns @c NULL.
 */
EAPI void *eina_accessor_container_get(Eina_Accessor * accessor)
{
	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor->get_container, NULL);
	return accessor->get_container(accessor);
}

/**
 * @brief Retrieve the data of an accessor at a given position.
 *
 * @param accessor The accessor.
 * @param position The position of the element.
 * @param data The pointer that stores the data to retrieve.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function retrieves the data of the element pointed by
 * @p accessor at the porition @p position, and stores it in
 * @p data. If @p accessor is @c NULL or if an error occurred,
 * #EINA_FALSE is returned, otherwise EINA_TRUE is returned.
 */
EAPI Eina_Bool
eina_accessor_data_get(Eina_Accessor * accessor,
		       unsigned int position, void **data)
{
	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor->get_at, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, EINA_FALSE);
	return accessor->get_at(accessor, position, data);
}

/**
 * @brief Iterate over the container and execute a callback on chosen elements.
 *
 * @param accessor The accessor.
 * @param cb The callback called on the chosen elements.
 * @param start The position of the first element.
 * @param end The position of the last element.
 * @param fdata The data passed to the callback.
 *
 * This function iterates over the elements pointed by @p accessor,
 * starting from the element at position @p start and ending to the
 * element at position @p end. For Each element, the callback
 * @p cb is called with the data @p fdata. If @p accessor is @c NULL
 * or if @p start is greter or equal than @p end, the function returns
 * immediately.
 */
EAPI void
eina_accessor_over(Eina_Accessor * accessor,
		   Eina_Each_Cb cb,
		   unsigned int start, unsigned int end, const void *fdata)
{
	const void *container;
	void *data;
	unsigned int i;

	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN(accessor);
	EINA_SAFETY_ON_NULL_RETURN(accessor->get_container);
	EINA_SAFETY_ON_NULL_RETURN(accessor->get_at);
	EINA_SAFETY_ON_NULL_RETURN(cb);
	EINA_SAFETY_ON_FALSE_RETURN(start < end);

	if (!eina_accessor_lock(accessor))
		return;

	container = accessor->get_container(accessor);
	for (i = start;
	     i < end && accessor->get_at(accessor, i, &data) == EINA_TRUE;
	     ++i)
		if (cb(container, data, (void *) fdata) != EINA_TRUE)
			goto on_exit;

      on_exit:
	(void) eina_accessor_unlock(accessor);
}

/**
 * @brief Lock the container of the accessor.
 *
 * @param accessor The accessor.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * If the container of the @p accessor permit it, it will be locked.
 * If @p accessor is @c NULL or if a problem occurred, #EINA_FALSE is
 * returned, otherwise #EINA_TRUE is returned. If the container
 * is not lockable, it will return EINA_TRUE.
 */
EAPI Eina_Bool eina_accessor_lock(Eina_Accessor * accessor)
{
	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor, EINA_FALSE);

	if (accessor->lock)
		return accessor->lock(accessor);
	return EINA_TRUE;
}

/**
 * @brief Unlock the container of the accessor.
 *
 * @param accessor The accessor.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * If the container of the @p accessor permit it and was previously
 * locked, it will be unlocked. If @p accessor is @c NULL or if a
 * problem occurred, #EINA_FALSE is returned, otherwise #EINA_TRUE
 * is returned. If the container is not lockable, it will return
 * EINA_TRUE.
 */
EAPI Eina_Bool eina_accessor_unlock(Eina_Accessor * accessor)
{
	EINA_MAGIC_CHECK_ACCESSOR(accessor);
	EINA_SAFETY_ON_NULL_RETURN_VAL(accessor, EINA_FALSE);

	if (accessor->unlock)
		return accessor->unlock(accessor);
	return EINA_TRUE;
}

/**
 * @}
 */
