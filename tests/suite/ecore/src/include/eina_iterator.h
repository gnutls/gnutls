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

#ifndef EINA_ITERATOR_H__
#define EINA_ITERATOR_H__

#include "eina_config.h"

#include "eina_types.h"
#include "eina_magic.h"

/**
 * @addtogroup Eina_Content_Access_Group Content Access
 *
 * @{
 */

/**
 * @defgroup Eina_Iterator_Group Iterator Functions
 *
 * @{
 */

/**
 * @typedef Eina_Iterator
 * Type for iterators.
 */
typedef struct _Eina_Iterator Eina_Iterator;

typedef Eina_Bool(*Eina_Iterator_Next_Callback) (Eina_Iterator * it,
						 void **data);
typedef void *(*Eina_Iterator_Get_Container_Callback) (Eina_Iterator * it);
typedef void (*Eina_Iterator_Free_Callback) (Eina_Iterator * it);
typedef Eina_Bool(*Eina_Iterator_Lock_Callback) (Eina_Iterator * it);

struct _Eina_Iterator {
#define EINA_ITERATOR_VERSION 1
	int version;

	Eina_Iterator_Next_Callback next EINA_ARG_NONNULL(1,
							  2)
	    EINA_WARN_UNUSED_RESULT;
	Eina_Iterator_Get_Container_Callback get_container
	    EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
	Eina_Iterator_Free_Callback free EINA_ARG_NONNULL(1);

	Eina_Iterator_Lock_Callback lock EINA_WARN_UNUSED_RESULT;
	Eina_Iterator_Lock_Callback unlock EINA_WARN_UNUSED_RESULT;

#define EINA_MAGIC_ITERATOR 0x98761233
 EINA_MAGIC};


#define FUNC_ITERATOR_NEXT(Function) ((Eina_Iterator_Next_Callback)Function)
#define FUNC_ITERATOR_GET_CONTAINER(Function) (( \
                                                  Eina_Iterator_Get_Container_Callback) \
                                               Function)
#define FUNC_ITERATOR_FREE(Function) ((Eina_Iterator_Free_Callback)Function)
#define FUNC_ITERATOR_LOCK(Function) ((Eina_Iterator_Lock_Callback)Function)

EAPI void eina_iterator_free(Eina_Iterator * iterator) EINA_ARG_NONNULL(1);

EAPI void *eina_iterator_container_get(Eina_Iterator *
				       iterator) EINA_ARG_NONNULL(1)
    EINA_PURE;
EAPI Eina_Bool eina_iterator_next(Eina_Iterator * iterator,
				  void **data) EINA_ARG_NONNULL(1,
								2)
    EINA_WARN_UNUSED_RESULT;

EAPI void eina_iterator_foreach(Eina_Iterator * iterator,
				Eina_Each_Cb callback,
				const void *fdata) EINA_ARG_NONNULL(1, 2);

EAPI Eina_Bool eina_iterator_lock(Eina_Iterator *
				  iterator) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_iterator_unlock(Eina_Iterator *
				    iterator) EINA_ARG_NONNULL(1);

/**
 * @def EINA_ITERATOR_FOREACH
 * @brief Macro to iterate over all elements easily.
 *
 * @param itr The iterator to use.
 * @param data Where to store * data, must be a pointer support getting
 *        its address since * eina_iterator_next() requires a pointer
 *        to pointer!
 *
 * This macro is a convenient way to use iterators, very similar to
 * EINA_LIST_FOREACH().
 *
 * This macro can be used for freeing the data of a list, like in the
 * following example. It has the same goal as the one documented in
 * EINA_LIST_FOREACH(), but using iterators:
 *
 * @code
 * Eina_List     *list;
 * Eina_Iterator *itr;
 * char          *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings
 *
 * itr = eina_list_iterator_new(list);
 * EINA_ITERATOR_FOREACH(itr, data)
 *   free(data);
 * eina_iterator_free(itr);
 * eina_list_free(list);
 * @endcode
 *
 * @note this example is not optimal algorithm to release a list since
 *    it will walk the list twice, but it serves as an example. For
 *    optimized version use EINA_LIST_FREE()
 *
 * @warning unless explicitly stated in functions returning iterators,
 *    do not modify the iterated object while you walk it, in this
 *    example using lists, do not remove list nodes or you might
 *    crash!  This is not a limitiation of iterators themselves,
 *    rather in the iterators implementations to keep them as simple
 *    and fast as possible.
 */
#define EINA_ITERATOR_FOREACH(itr, \
                              data) while (eina_iterator_next((itr), \
                                                              (void **)&(data)))

/**
 * @}
 */

/**
 * @}
 */

#endif
