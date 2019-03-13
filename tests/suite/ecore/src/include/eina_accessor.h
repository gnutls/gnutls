/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric Bail
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

#ifndef EINA_ACCESSOR_H__
#define EINA_ACCESSOR_H__

#include "eina_config.h"

#include "eina_types.h"
#include "eina_magic.h"

/**
 * @addtogroup Eina_Content_Access_Group Content Access
 *
 * @{
 */

/**
 * @defgroup Eina_Accessor_Group Accessor Functions
 *
 * @{
 */

/**
 * @typedef Eina_Accessor
 * Type for accessors.
 */
typedef struct _Eina_Accessor Eina_Accessor;

typedef Eina_Bool(*Eina_Accessor_Get_At_Callback) (Eina_Accessor * it,
						   unsigned int index,
						   void **data);
typedef void *(*Eina_Accessor_Get_Container_Callback) (Eina_Accessor * it);
typedef void (*Eina_Accessor_Free_Callback) (Eina_Accessor * it);
typedef Eina_Bool(*Eina_Accessor_Lock_Callback) (Eina_Accessor * it);

struct _Eina_Accessor {
#define EINA_ACCESSOR_VERSION 1
	int version;

	Eina_Accessor_Get_At_Callback get_at EINA_ARG_NONNULL(1,
							      3)
	    EINA_WARN_UNUSED_RESULT;
	Eina_Accessor_Get_Container_Callback get_container
	    EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
	Eina_Accessor_Free_Callback free EINA_ARG_NONNULL(1);

	Eina_Accessor_Lock_Callback lock EINA_WARN_UNUSED_RESULT;
	Eina_Accessor_Lock_Callback unlock EINA_WARN_UNUSED_RESULT;

#define EINA_MAGIC_ACCESSOR 0x98761232
 EINA_MAGIC};

#define FUNC_ACCESSOR_GET_AT(Function) ((Eina_Accessor_Get_At_Callback)Function)
#define FUNC_ACCESSOR_GET_CONTAINER(Function) ((Eina_Accessor_Get_Container_Callback)Function)
#define FUNC_ACCESSOR_FREE(Function) ((Eina_Accessor_Free_Callback)Function)
#define FUNC_ACCESSOR_LOCK(Function) ((Eina_Accessor_Lock_Callback)Function)

EAPI void eina_accessor_free(Eina_Accessor * accessor) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_accessor_data_get(Eina_Accessor * accessor,
				      unsigned int position,
				      void **data) EINA_ARG_NONNULL(1);
EAPI void *eina_accessor_container_get(Eina_Accessor *
				       accessor) EINA_ARG_NONNULL(1)
    EINA_PURE;
EAPI void eina_accessor_over(Eina_Accessor * accessor, Eina_Each_Cb cb,
			     unsigned int start, unsigned int end,
			     const void *fdata) EINA_ARG_NONNULL(1, 2);
EAPI Eina_Bool eina_accessor_lock(Eina_Accessor *
				  accessor) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_accessor_unlock(Eina_Accessor *
				    accessor) EINA_ARG_NONNULL(1);

/**
 * @def EINA_ACCESSOR_FOREACH
 * @brief Macro to iterate over all elements easily.
 *
 * @param accessor The accessor to use.
 * @param counter A counter used by eina_accessor_data_get() when
 * iterating over the container.
 * @param data Where to store * data, must be a pointer support getting
 * its address since * eina_accessor_data_get() requires a pointer to
 * pointer!
 *
 * This macro allows a convenient way to loop over all elements in an
 * accessor, very similar to EINA_LIST_FOREACH().
 *
 * This macro can be used for freeing the data of a list, like in the
 * following example. It has the same goal as the one documented in
 * EINA_LIST_FOREACH(), but using accessors:
 *
 * @code
 * Eina_List     *list;
 * Eina_Accessor *accessor;
 * unsigned int   i;
 * char          *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings
 *
 * accessor = eina_list_accessor_new(list);
 * EINA_ACCESSOR_FOREACH(accessor, i, data)
 *   free(data);
 * eina_accessor_free(accessor);
 * eina_list_free(list);
 * @endcode
 *
 * @note if the datatype provides both iterators and accessors prefer
 *    to use iterators to iterate over, as they're likely to be more
 *    optimized for such task.
 *
 * @note this example is not optimal algorithm to release a list since
 *    it will walk the list twice, but it serves as an example. For
 *    optimized version use EINA_LIST_FREE()
 *
 * @warning unless explicitly stated in functions returning accessors,
 *    do not modify the accessed object while you walk it, in this
 *    example using lists, do not remove list nodes or you might
 *    crash!  This is not a limitiation of accessors themselves,
 *    rather in the accessors implementations to keep them as simple
 *    and fast as possible.
 */
#define EINA_ACCESSOR_FOREACH(accessor, counter, data)			\
  for ((counter) = 0;							\
       eina_accessor_data_get((accessor), (counter), (void **)&(data)); \
       (counter)++)

/**
 * @}
 */

/**
 * @}
 */

#endif
