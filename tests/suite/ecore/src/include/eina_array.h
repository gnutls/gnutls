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

#ifndef EINA_ARRAY_H_
#define EINA_ARRAY_H_

#include <stdlib.h>

#include "eina_config.h"

#include "eina_types.h"
#include "eina_error.h"
#include "eina_iterator.h"
#include "eina_accessor.h"
#include "eina_magic.h"

/**
 * @addtogroup Eina_Data_Types_Group Data Types
 *
 * @{
 */

/**
 * @addtogroup Eina_Containers_Group Containers
 *
 * @{
 */

/**
 * @defgroup Eina_Array_Group Array
 *
 * @{
 */

/**
 * @typedef Eina_Array
 * Type for a generic vector.
 */
typedef struct _Eina_Array Eina_Array;

/**
 * @typedef Eina_Array_Iterator
 * Type for an iterator on arrays, used with #EINA_ARRAY_ITER_NEXT.
 */
typedef void **Eina_Array_Iterator;

/**
 * @struct _Eina_Array
 * Type for an array of data.
 */
struct _Eina_Array {
#define EINA_ARRAY_VERSION 1
	int version;
		/**< Should match EINA_ARRAY_VERSION used when compiled your apps, provided for ABI compatibility */

	void **data;
		/**< Pointer to a vector of pointer to payload */
	unsigned int total;
		       /**< Total number of slots in the vector */
	unsigned int count;
		       /**< Number of active slots in the vector */
	unsigned int step;
		      /**< How much must we grow the vector when it is full */
 EINA_MAGIC};

EAPI Eina_Array *eina_array_new(unsigned int step)
EINA_WARN_UNUSED_RESULT EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI void eina_array_free(Eina_Array * array) EINA_ARG_NONNULL(1);
EAPI void eina_array_step_set(Eina_Array * array,
			      unsigned int sizeof_eina_array,
			      unsigned int step) EINA_ARG_NONNULL(1);
EAPI void eina_array_clean(Eina_Array * array) EINA_ARG_NONNULL(1);
EAPI void eina_array_flush(Eina_Array * array) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_array_remove(Eina_Array * array,
				 Eina_Bool(*keep) (void *data,
						   void *gdata),
				 void *gdata) EINA_ARG_NONNULL(1, 2);
static inline Eina_Bool eina_array_push(Eina_Array * array,
					const void *data)
EINA_ARG_NONNULL(1, 2);
static inline void *eina_array_pop(Eina_Array * array) EINA_ARG_NONNULL(1);
static inline void *eina_array_data_get(const Eina_Array * array,
					unsigned int idx)
EINA_ARG_NONNULL(1);
static inline void eina_array_data_set(const Eina_Array * array,
				       unsigned int idx,
				       const void *data)
EINA_ARG_NONNULL(1, 3);
static inline unsigned int eina_array_count_get(const Eina_Array *
						array) EINA_ARG_NONNULL(1);
EAPI Eina_Iterator *eina_array_iterator_new(const Eina_Array * array)
EINA_MALLOC EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Accessor *eina_array_accessor_new(const Eina_Array * array)
EINA_MALLOC EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_array_foreach(Eina_Array * array,
					   Eina_Each_Cb cb, void *data);
/**
 * @def EINA_ARRAY_ITER_NEXT
 * @brief Macro to iterate over an array easily.
 *
 * @param array The array to iterate over.
 * @param index The integer number that is increased while itareting.
 * @param item The data
 * @param iterator The iterator
 *
 * This macro allows the iteration over @p array in an easy way. It
 * iterates from the first element to the last one. @p index is an
 * integer that increases from 0 to the number of elements. @p item is
 * the data of each element of @p array, so it is a pointer to a type
 * chosen by the user. @p iterator is of type #Eina_Array_Iterator.
 *
 * This macro can be used for freeing the data of an array, like in
 * the following example:
 *
 * @code
 * Eina_Array         *array;
 * char               *item;
 * Eina_Array_Iterator iterator;
 * unsigned int        i;
 *
 * // array is already filled,
 * // its elements are just duplicated strings,
 * // EINA_ARRAY_ITER_NEXT will be used to free those strings
 *
 * EINA_ARRAY_ITER_NEXT(array, i, item, iterator)
 *   free(item);
 * @endcode
 */
#define EINA_ARRAY_ITER_NEXT(array, index, item, iterator)		\
  for (index = 0, iterator = (array)->data;				\
       (index < eina_array_count_get(array)) && ((item = *((iterator)++))); \
       ++(index))

#include "eina_inline_array.x"

/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */

#endif
