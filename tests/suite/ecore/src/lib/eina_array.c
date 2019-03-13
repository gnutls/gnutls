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


/**
 * @page tutorial_array_page Array Tutorial
 *
 * The Array data type is allow the storage of data like a C array.
 * It is designed such that the access to its element is very fast.
 * But the addition or removal can be done only at the end of the
 * array. To add or remove an element at any location, the Eina
 * @ref Eina_List_Group is the correct container is the correct one.
 *
 * @section tutorial_error_basic_usage Basic Usage
 *
 * An array must created with eina_array_new(). That function
 * takes an integer as parameter, which is the count of pointers to
 * add when increasing the array size. Once the array is not used
 * anymore, it must be destroyed with eina_array_free().
 *
 * To append data at the end of the array, the function
 * eina_array_push() must be used. To remove the data at the end of
 * the array, eina_array_pop() must be used. Once the array is filled,
 * one can check its elements by iterating over it. A while loop and
 * eina_array_data_get() can be used, or else one can use the
 * predefined macro EINA_ARRAY_ITER_NEXT(). To free all the elements,
 * a while loop can be used with eina_array_count_get(). Here is an
 * example of use:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 * #include <string.h>
 *
 * #include <eina_array.h>
 *
 * int main(void)
 * {
 *     const char *strings[] = {
 *         "first string",
 *         "second string",
 *         "third string",
 *         "fourth string"
 *     };
 *     Eina_Array         *array;
 *     char               *item;
 *     Eina_Array_Iterator iterator;
 *     unsigned int        i;
 *
 *     if (!eina_init())
 *     {
 *         printf ("Error during the initialization of eina\n");
 *         return EXIT_FAILURE;
 *     }
 *
 *     array = eina_array_new(16);
 *     if (!array)
 *         goto shutdown;
 *
 *     for (i = 0; i < 4; i++)
 *     {
 *         eina_array_push(array, strdup(strings[i]));
 *     }
 *
 *     printf("array count: %d\n", eina_array_count_get(array));
 *     EINA_ARRAY_ITER_NEXT(array, i, item, iterator)
 *     {
 *         printf("item #%d: %s\n", i, item);
 *     }
 *
 *     while (eina_array_count_get(array))
 *     {
 *         void *data;
 *
 *         data = eina_array_pop(array);
 *         free(data);
 *     }
 *
 *     eina_array_free(array);
 *     eina_shutdown();
 *
 *     return EXIT_SUCCESS;
 *
 *   shutdown:
 *     eina_shutdown();
 *
 *     return EXIT_FAILURE;
 * }
 * @endcode
 *
 * To be continued
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "eina_config.h"
#include "eina_private.h"
#include "eina_error.h"
#include "eina_log.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_array.h"

/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

/**
 * @cond LOCAL
 */

static const char EINA_MAGIC_ARRAY_STR[] = "Eina Array";
static const char EINA_MAGIC_ARRAY_ITERATOR_STR[] = "Eina Array Iterator";
static const char EINA_MAGIC_ARRAY_ACCESSOR_STR[] = "Eina Array Accessor";

#define EINA_MAGIC_CHECK_ARRAY(d)                       \
   do {                                                  \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_ARRAY)) {        \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_ARRAY); }            \
     } while (0)

#define EINA_MAGIC_CHECK_ARRAY_ITERATOR(d, ...)                 \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_ARRAY_ITERATOR))       \
          {                                                        \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_ARRAY_ITERATOR);        \
             return __VA_ARGS__;                                   \
          }                                                        \
     } while (0)

#define EINA_MAGIC_CHECK_ARRAY_ACCESSOR(d, ...)                 \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_ARRAY_ACCESSOR))       \
          {                                                        \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_ACCESSOR);              \
             return __VA_ARGS__;                                   \
          }                                                        \
     } while (0)


typedef struct _Eina_Iterator_Array Eina_Iterator_Array;
struct _Eina_Iterator_Array {
	Eina_Iterator iterator;

	const Eina_Array *array;
	unsigned int index;

 EINA_MAGIC};

typedef struct _Eina_Accessor_Array Eina_Accessor_Array;
struct _Eina_Accessor_Array {
	Eina_Accessor accessor;
	const Eina_Array *array;
 EINA_MAGIC};

static int _eina_array_log_dom = -1;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_array_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_array_log_dom, __VA_ARGS__)

static void eina_array_iterator_free(Eina_Iterator_Array *
				     it) EINA_ARG_NONNULL(1);
static Eina_Array *eina_array_iterator_get_container(Eina_Iterator_Array *
						     it)
EINA_ARG_NONNULL(1);
static Eina_Bool eina_array_iterator_next(Eina_Iterator_Array * it,
					  void **data) EINA_ARG_NONNULL(1);

static Eina_Bool eina_array_accessor_get_at(Eina_Accessor_Array * it,
					    unsigned int idx,
					    void **data)
EINA_ARG_NONNULL(1);
static Eina_Array *eina_array_accessor_get_container(Eina_Accessor_Array *
						     it)
EINA_ARG_NONNULL(1);
static void eina_array_accessor_free(Eina_Accessor_Array *
				     it) EINA_ARG_NONNULL(1);

static Eina_Bool
eina_array_iterator_next(Eina_Iterator_Array * it, void **data)
{
	EINA_MAGIC_CHECK_ARRAY_ITERATOR(it, EINA_FALSE);

	if (!(it->index < eina_array_count_get(it->array)))
		return EINA_FALSE;

	if (data)
		*data = eina_array_data_get(it->array, it->index);

	it->index++;
	return EINA_TRUE;
}

static Eina_Array *eina_array_iterator_get_container(Eina_Iterator_Array *
						     it)
{
	EINA_MAGIC_CHECK_ARRAY_ITERATOR(it, NULL);
	return (Eina_Array *) it->array;
}

static void eina_array_iterator_free(Eina_Iterator_Array * it)
{
	EINA_MAGIC_CHECK_ARRAY_ITERATOR(it);
	MAGIC_FREE(it);
}

static Eina_Bool
eina_array_accessor_get_at(Eina_Accessor_Array * it,
			   unsigned int idx, void **data)
{
	EINA_MAGIC_CHECK_ARRAY_ACCESSOR(it, EINA_FALSE);

	if (!(idx < eina_array_count_get(it->array)))
		return EINA_FALSE;

	if (data)
		*data = eina_array_data_get(it->array, idx);

	return EINA_TRUE;
}

static Eina_Array *eina_array_accessor_get_container(Eina_Accessor_Array *
						     it)
{
	EINA_MAGIC_CHECK_ARRAY_ACCESSOR(it, NULL);
	return (Eina_Array *) it->array;
}

static void eina_array_accessor_free(Eina_Accessor_Array * it)
{
	EINA_MAGIC_CHECK_ARRAY_ACCESSOR(it);
	MAGIC_FREE(it);
}

EAPI Eina_Bool eina_array_grow(Eina_Array * array)
{
	void **tmp;
	unsigned int total;

	EINA_SAFETY_ON_NULL_RETURN_VAL(array, EINA_FALSE);

	EINA_MAGIC_CHECK_ARRAY(array);

	total = array->total + array->step;
	eina_error_set(0);
	tmp = realloc(array->data, sizeof(void *) * total);
	if (EINA_UNLIKELY(!tmp)) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return 0;
	}

	array->total = total;
	array->data = tmp;

	return 1;
}

/**
 * @endcond
 */


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/

/**
 * @internal
 * @brief Initialize the array module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the error and magic modules or Eina. It is
 * called by eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_array_init(void)
{
	_eina_array_log_dom = eina_log_domain_register("eina_array",
						       EINA_LOG_COLOR_DEFAULT);
	if (_eina_array_log_dom < 0) {
		EINA_LOG_ERR("Could not register log domain: eina_array");
		return EINA_FALSE;
	}
#define EMS(n) eina_magic_string_static_set(n, n ## _STR)
	EMS(EINA_MAGIC_ARRAY);
	EMS(EINA_MAGIC_ARRAY_ITERATOR);
	EMS(EINA_MAGIC_ARRAY_ACCESSOR);
#undef EMS
	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the array module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the array module set up by
 * eina_array_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_array_shutdown(void)
{
	eina_log_domain_unregister(_eina_array_log_dom);
	_eina_array_log_dom = -1;
	return EINA_TRUE;
}

/*============================================================================*
 *                                   API                                      *
 *============================================================================*/

/**
 * @addtogroup Eina_Array_Group Array
 *
 * @brief These functions provide array management.
 *
 * The Array data type in Eina is designed to have a very fast access to
 * its data (compared to the Eina @ref Eina_List_Group). On the other hand,
 * data can be added or removed only at the end of the array. To insert
 * data at any place, the Eina @ref Eina_List_Group is the correct container
 * to use.
 *
 * To use the array data type, eina_init() must be called before any
 * other array functions. When eina is no more array function is used,
 * eina_shutdown() must be called to free all the resources.
 *
 * An array must be created with eina_array_new(). It allocated all
 * the necessary data for an array. When not needed anymore, an array
 * is freed with eina_array_free(). This function does not free any
 * allocated memory used to store the data of each element. For that,
 * just iterate over the array to free them. A convenient way to do
 * that is by using #EINA_ARRAY_ITER_NEXT. An example of code is given
 * in the description of this macro.
 *
 * @warning All the other functions do not check if the used array is
 * valid or not. It's up to the user to be sure of that. It is
 * designed like that for performance reasons.
 *
 * The usual features of an array are classic ones: to append an
 * element, use eina_array_push() and to remove the last element, use
 * eina_array_pop(). To retrieve the element at a given positin, use
 * eina_array_data_get(). The number of elements can be retrieved with
 * eina_array_count_get().
 *
 * For more information, you can look at the @ref tutorial_array_page.
 *
 * @{
 */

/**
 * @brief Create a new array.
 *
 * @param step The count of pointers to add when increasing the array size.
 * @return @c NULL on failure, non @c NULL otherwise.
 *
 * This function creates a new array. When adding an element, the array
 * allocates @p step elements. When that buffer is full, then adding
 * another element will increase the buffer of @p step elements again.
 *
 * This function return a valid array on success, or @c NULL if memory
 * allocation fails. In that case, the error is set to
 * #EINA_ERROR_OUT_OF_MEMORY.
 */
EAPI Eina_Array *eina_array_new(unsigned int step)
{
	Eina_Array *array;

	eina_error_set(0);
	array = malloc(sizeof(Eina_Array));
	if (!array) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(array, EINA_MAGIC_ARRAY);

	array->version = EINA_ARRAY_VERSION;
	array->data = NULL;
	array->total = 0;
	array->count = 0;
	array->step = step;

	return array;
}

/**
 * @brief Free an array.
 *
 * @param array The array to free.
 *
 * This function frees @p array. It calls first eina_array_flush() then
 * free the memory of the pointer. It does not free the memory
 * allocated for the elements of @p array. To free them, use
 * #EINA_ARRAY_ITER_NEXT. For performance reasons, there is no check
 * of @p array.
 */
EAPI void eina_array_free(Eina_Array * array)
{
	eina_array_flush(array);

	EINA_SAFETY_ON_NULL_RETURN(array);
	EINA_MAGIC_CHECK_ARRAY(array);
	MAGIC_FREE(array);
}

/**
 * @brief Set the step of an array.
 *
 * @param array The array.
 * @param sizeof_eina_array Should be the value returned by sizeof(Eina_Array).
 * @param step The count of pointers to add when increasing the array size.
 *
 * This function sets the step of @p array to @p step. For performance
 * reasons, there is no check of @p array. If it is @c NULL or
 * invalid, the program may crash. This function should be called when
 * the array is not initialized.
 */
EAPI void
eina_array_step_set(Eina_Array * array,
		    unsigned int sizeof_eina_array, unsigned int step)
{
	EINA_SAFETY_ON_NULL_RETURN(array);

	if (sizeof(Eina_Array) != sizeof_eina_array) {
		ERR("Unknow Eina_Array size ! Got %i, expected %i !\n",
		    sizeof_eina_array, (int) sizeof(Eina_Array));
		/* Force memory to zero to provide a small layer of security */
		memset(array, 0, sizeof_eina_array);
		return;
	}

	array->version = EINA_ARRAY_VERSION;
	array->data = NULL;
	array->total = 0;
	array->count = 0;
	array->step = step;
	EINA_MAGIC_SET(array, EINA_MAGIC_ARRAY);
}

/**
 * @brief Clean an array.
 *
 * @param array The array to clean.
 *
 * This function sets the count member of @p array to 0. For
 * performance reasons, there is no check of @p array. If it is
 * @c NULL or invalid, the program may crash.
 */
EAPI void eina_array_clean(Eina_Array * array)
{
	EINA_SAFETY_ON_NULL_RETURN(array);
	EINA_MAGIC_CHECK_ARRAY(array);

	array->count = 0;
}

/**
 * @brief Flush an array.
 *
 * @param array The array to flush.
 *
 * This function sets the count and total members of @p array to 0,
 * frees and set to NULL its data member. For performance reasons,
 * there is no check of @p array. If it is @c NULL or invalid, the
 * program may crash.
 */
EAPI void eina_array_flush(Eina_Array * array)
{
	EINA_SAFETY_ON_NULL_RETURN(array);
	EINA_MAGIC_CHECK_ARRAY(array);

	array->count = 0;
	array->total = 0;

	if (!array->data)
		return;

	free(array->data);
	array->data = NULL;
}

/**
 * @brief Rebuild an array by specifying the data to keep.
 *
 * @param array The array.
 * @param keep The functions which selects the data to keep.
 * @param gdata The data to pass to the function keep.
 * @return #EINA_TRUE on success, #EINA_FALSE oterwise.
 *
 * This function rebuilds @p array be specifying the elements to keep
 * with the function @p keep. @p gdata is an additional data to pass
 * to @p keep. For performance reasons, there is no check of @p
 * array. If it is @c NULL or invalid, the program may crash.
 *
 * This function always return a valid array. If it wasn't able to
 * remove items due to an allocation failure, it will return #EINA_FALSE
 * and the error is set to #EINA_ERROR_OUT_OF_MEMORY.
 */
EAPI Eina_Bool
eina_array_remove(Eina_Array * array, Eina_Bool(*keep) (void *data,
							void *gdata),
		  void *gdata)
{
	void **tmp;
	/* WARNING:
	   The algorithm does exit before using unitialized data. So compiler is
	   giving you a false positiv here too.
	 */
	void *data = NULL;
	unsigned int total = 0;
	unsigned int limit;
	unsigned int i;

	EINA_SAFETY_ON_NULL_RETURN_VAL(array, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(keep, EINA_FALSE);
	EINA_MAGIC_CHECK_ARRAY(array);

	if (array->total == 0)
		return EINA_TRUE;

	for (i = 0; i < array->count; ++i) {
		data = eina_array_data_get(array, i);

		if (keep(data, gdata) == EINA_FALSE)
			break;
	}
	limit = i;
	if (i < array->count)
		++i;

	for (; i < array->count; ++i) {
		data = eina_array_data_get(array, i);

		if (keep(data, gdata) == EINA_TRUE)
			break;
	}
	/* Special case all objects that need to stay are at the beginning of the array. */
	if (i == array->count) {
		array->count = limit;
		if (array->count == 0) {
			free(array->data);
			array->total = 0;
			array->data = NULL;
		}

		return EINA_TRUE;
	}

	eina_error_set(0);
	tmp = malloc(sizeof(void *) * array->total);
	if (!tmp) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return EINA_FALSE;
	}

	memcpy(tmp, array->data, limit * sizeof(void *));
	total = limit;

	if (i < array->count) {
		tmp[total] = data;
		total++;
		++i;
	}

	for (; i < array->count; ++i) {
		data = eina_array_data_get(array, i);

		if (keep(data, gdata)) {
			tmp[total] = data;
			total++;
		}
	}

	free(array->data);

	/* If we do not keep any object in the array, we should have exited
	   earlier in test (i == array->count). */
	assert(total != 0);

	array->data = tmp;
	array->count = total;
	return EINA_TRUE;
}

/**
 * @brief Returned a new iterator associated to an array.
 *
 * @param array The array.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to
 * @p array. If @p array is @c NULL or the count member of @p array is
 * less or equal than 0, this function returns NULL. If the memory can
 * not be allocated, NULL is returned and #EINA_ERROR_OUT_OF_MEMORY is
 * set. Otherwise, a valid iterator is returned.
 */
EAPI Eina_Iterator *eina_array_iterator_new(const Eina_Array * array)
{
	Eina_Iterator_Array *it;

	EINA_SAFETY_ON_NULL_RETURN_VAL(array, NULL);
	EINA_MAGIC_CHECK_ARRAY(array);

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_Array));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(it, EINA_MAGIC_ARRAY_ITERATOR);
	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

	it->array = array;

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(eina_array_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(eina_array_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(eina_array_iterator_free);

	return &it->iterator;
}

/**
 * @brief Returned a new accessor associated to an array.
 *
 * @param array The array.
 * @return A new accessor.
 *
 * This function returns a newly allocated accessor associated to
 * @p array. If @p array is @c NULL or the count member of @p array is
 * less or equal than 0, this function returns NULL. If the memory can
 * not be allocated, NULL is returned and #EINA_ERROR_OUT_OF_MEMORY is
 * set. Otherwise, a valid accessor is returned.
 */
EAPI Eina_Accessor *eina_array_accessor_new(const Eina_Array * array)
{
	Eina_Accessor_Array *ac;

	EINA_SAFETY_ON_NULL_RETURN_VAL(array, NULL);
	EINA_MAGIC_CHECK_ARRAY(array);

	eina_error_set(0);
	ac = calloc(1, sizeof(Eina_Accessor_Array));
	if (!ac) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(ac, EINA_MAGIC_ARRAY_ACCESSOR);
	EINA_MAGIC_SET(&ac->accessor, EINA_MAGIC_ACCESSOR);

	ac->array = array;

	ac->accessor.version = EINA_ACCESSOR_VERSION;
	ac->accessor.get_at =
	    FUNC_ACCESSOR_GET_AT(eina_array_accessor_get_at);
	ac->accessor.get_container =
	    FUNC_ACCESSOR_GET_CONTAINER(eina_array_accessor_get_container);
	ac->accessor.free = FUNC_ACCESSOR_FREE(eina_array_accessor_free);

	return &ac->accessor;
}

/**
 * @}
 */
