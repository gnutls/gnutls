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

#ifndef EINA_INLINE_ARRAY_X_
#define EINA_INLINE_ARRAY_X_

#include <stdio.h>

/**
 * @cond LOCAL
 */

EAPI Eina_Bool eina_array_grow(Eina_Array *array);

/**
 * @endcond
 */

/**
 * @addtogroup Eina_Array_Group Array
 *
 * @brief These functions provide array management.
 *
 * @{
 */

/**
 * @brief Append a data to an array.
 *
 * @param array The array.
 * @param data The data to add.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function appends @p data to @p array. For performance
 * reasons, there is no check of @p array. If it is @c NULL or
 * invalid, the program may crash. If @p data is @c NULL, or if an
 * allocation is necessary and fails, #EINA_FALSE is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, #EINA_TRUE is
 * returned.
 */

static inline Eina_Bool
eina_array_push(Eina_Array *array, const void *data)
{
   if (!data) return EINA_FALSE;

   if (EINA_UNLIKELY((array->count + 1) > array->total))
     if (!eina_array_grow(array))
       return EINA_FALSE;

   array->data[array->count++] = (void*) data;

   return EINA_TRUE;
}

/**
 * @brief Remove the last data of an array.
 *
 * @param array The array.
 * @return The retrieved data.
 *
 * This function removes the last data of @p array, decreases the count
 * of @p array and returns the data. For performance reasons, there
 * is no check of @p array. If it is @c NULL or invalid, the program
 * may crash. If the count member is less or equal than 0, @c NULL is
 * returned.
 */
static inline void *
eina_array_pop(Eina_Array *array)
{
   void *ret = NULL;

   if (array->count <= 0)
     goto on_empty;

   ret = array->data[--array->count];

 on_empty:
   return ret;
}

/**
 * @brief Return the data at a given position in an array.
 *
 * @param array The array.
 * @param idx The potition of the data to retrieve.
 * @return The retrieved data.
 *
 * This function returns the data at the position @p idx in @p
 * array. For performance reasons, there is no check of @p array or @p
 * idx. If it is @c NULL or invalid, the program may crash.
 */
static inline void *
eina_array_data_get(const Eina_Array *array, unsigned int idx)
{
   return array->data[idx];
}

/**
 * @brief Set the data at a given position in an array.
 *
 * @param array The array.
 * @param idx The potition of the data to set.
 * @param data The data to set.
 *
 * This function sets the data at the position @p idx in @p
 * array. For performance reasons, there is no check of @p array or @p
 * idx. If it is @c NULL or invalid, the program may crash.
 */
static inline void
eina_array_data_set(const Eina_Array *array, unsigned int idx, const void *data)
{
   array->data[idx] = (void*) data;
}

/**
 * @brief Return the number of elements in an array.
 *
 * @param array The array.
 * @return The number of elements.
 *
 * This function returns the number of elements in @p array. For
 * performance reasons, there is no check of @p array. If it is
 * @c NULL or invalid, the program may crash.
 */
static inline unsigned int
eina_array_count_get(const Eina_Array *array)
{
   return array->count;
}

/**
 * @brief Provide a safe way to iterate over an array
 *
 * @param array The array to iterate over.
 * @param cb The callback to call for each item.
 * @param fdata The user data to pass to the callback.
 * @return EINA_TRUE if it successfully iterate all items of the array.
 *
 * This function provide a safe way to iterate over an array. @p cb should
 * return EINA_TRUE as long as you want the function to continue iterating,
 * by returning EINA_FALSE it will stop and return EINA_FALSE as a result.
 */
static inline Eina_Bool
eina_array_foreach(Eina_Array *array, Eina_Each_Cb cb, void *fdata)
{
   void *data;
   Eina_Array_Iterator iterator;
   unsigned int i;
   Eina_Bool ret = EINA_TRUE;

   EINA_ARRAY_ITER_NEXT(array, i, data, iterator)
     if (cb(array, data, fdata) != EINA_TRUE)
       {
	  ret = EINA_FALSE;
	  break;
       }

   return ret;
}

/**
 * @}
 */

#endif
