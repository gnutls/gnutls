/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Vincent Torri, Jorge Luis Zapata Muga
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

#ifndef EINA_LIST_H_
#define EINA_LIST_H_

#include <stdlib.h>

#include "eina_config.h"

#include "eina_types.h"
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
 * @defgroup Eina_List_Group List
 *
 * @{
 */

/**
 * @typedef Eina_List
 * Type for a generic double linked list.
 */
typedef struct _Eina_List Eina_List;

typedef struct _Eina_List_Accounting Eina_List_Accounting;

/**
 * @struct _Eina_List
 * Type for a generic double linked list.
 */
struct _Eina_List {
	void *data;
	       /**< Pointer to list element payload */
	Eina_List *next;
		    /**< Next member in the list */
	Eina_List *prev;
		    /**< Previous member in the list */
	Eina_List_Accounting *accounting;
				     /**< Private list accounting info - don't touch */

 EINA_MAGIC};

struct _Eina_List_Accounting {
	Eina_List *last;
	unsigned int count;
 EINA_MAGIC};

EAPI Eina_List *eina_list_append(Eina_List * list,
				 const void *data) EINA_ARG_NONNULL(2)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_prepend(Eina_List * list,
				  const void *data) EINA_ARG_NONNULL(2)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_append_relative(Eina_List * list,
					  const void *data,
					  const void *relative)
EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_append_relative_list(Eina_List * list,
					       const void *data,
					       Eina_List *
					       relative)
EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_prepend_relative(Eina_List * list,
					   const void *data,
					   const void *relative)
EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_prepend_relative_list(Eina_List * list,
						const void *data,
						Eina_List *
						relative)
EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_sorted_insert(Eina_List * list,
					Eina_Compare_Cb func,
					const void *data)
EINA_ARG_NONNULL(2, 3) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_remove(Eina_List * list,
				 const void *data) EINA_ARG_NONNULL(2)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_remove_list(Eina_List * list,
				      Eina_List *
				      remove_list) EINA_ARG_NONNULL(2)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_promote_list(Eina_List * list,
				       Eina_List *
				       move_list) EINA_ARG_NONNULL(2)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_demote_list(Eina_List * list,
				      Eina_List * move_list);
EAPI void *eina_list_data_find(const Eina_List * list, const void *data)
EINA_PURE EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_data_find_list(const Eina_List * list,
					 const void *data)
EINA_PURE EINA_ARG_NONNULL(2) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_free(Eina_List * list);
EAPI void *eina_list_nth(const Eina_List * list, unsigned int n)
EINA_PURE EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_nth_list(const Eina_List * list, unsigned int n)
EINA_PURE EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_reverse(Eina_List *
				  list) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_reverse_clone(const Eina_List *
					list) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_clone(const Eina_List *
				list) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_sort(Eina_List * list, unsigned int size,
			       Eina_Compare_Cb func) EINA_ARG_NONNULL(3)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_merge(Eina_List * left,
				Eina_List * right) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_sorted_merge(Eina_List * left, Eina_List * right,
				       Eina_Compare_Cb func)
EINA_ARG_NONNULL(3) EINA_WARN_UNUSED_RESULT;
EAPI Eina_List *eina_list_split_list(Eina_List * list,
				     Eina_List * relative,
				     Eina_List **
				     right) EINA_WARN_UNUSED_RESULT;


EAPI Eina_List *eina_list_search_sorted_near_list(const Eina_List * list,
						  Eina_Compare_Cb func,
						  const void *data,
						  int *result_cmp);
EAPI Eina_List *eina_list_search_sorted_list(const Eina_List * list,
					     Eina_Compare_Cb func,
					     const void *data);
EAPI void *eina_list_search_sorted(const Eina_List * list,
				   Eina_Compare_Cb func, const void *data);
EAPI Eina_List *eina_list_search_unsorted_list(const Eina_List * list,
					       Eina_Compare_Cb func,
					       const void *data);
EAPI void *eina_list_search_unsorted(const Eina_List * list,
				     Eina_Compare_Cb func,
				     const void *data);

static inline Eina_List *eina_list_last(const Eina_List * list)
EINA_PURE EINA_WARN_UNUSED_RESULT;
static inline Eina_List *eina_list_next(const Eina_List * list)
EINA_PURE EINA_WARN_UNUSED_RESULT;
static inline Eina_List *eina_list_prev(const Eina_List * list)
EINA_PURE EINA_WARN_UNUSED_RESULT;
static inline void *eina_list_data_get(const Eina_List * list)
EINA_PURE EINA_WARN_UNUSED_RESULT;
static inline unsigned int eina_list_count(const Eina_List *
					   list) EINA_PURE;

EAPI Eina_Iterator *eina_list_iterator_new(const Eina_List * list)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI Eina_Iterator *eina_list_iterator_reversed_new(const Eina_List * list)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI Eina_Accessor *eina_list_accessor_new(const Eina_List * list)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;

/**
 * @def EINA_LIST_FOREACH
 * @brief Macro to iterate over a list.
 *
 * @param list The list to iterate over.
 * @param l A list that is used as an iterator and points to the current node.
 * @param data Current item's data.
 *
 * This macro iterates over @p list from the first element to
 * the last. @p data is the data related to the current element.
 * @p l is an #Eina_List used as the list iterator.
 *
 * It can be used to free list data, as in the following example:
 *
 * @code
 * Eina_List *list;
 * Eina_List *l;
 * char      *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings,
 * // EINA_LIST_FOREACH will be used to free those strings
 *
 * EINA_LIST_FOREACH(list, l, data)
 *   free(data);
 * eina_list_free(list);
 * @endcode
 *
 * @note This is not the optimal way to release memory allocated to
 *       a list, since it iterates over the list twice.
 *       For an optimized algorithm, use EINA_LIST_FREE().
 *
 * @warning Be careful when deleting list nodes.
 *          If you remove the current node and continue iterating,
 *          the code will fail because the macro will not be able
 *          to get the next node. Notice that it's OK to remove any
 *          node if you stop the loop after that.
 *          For destructive operations such as this, consider
 *          using EINA_LIST_FOREACH_SAFE().
 */
#define EINA_LIST_FOREACH(list, l, data)	\
  for (l = list,				\
	 data = eina_list_data_get(l);		\
       l;					\
       l = eina_list_next(l),			\
	 data = eina_list_data_get(l))

/**
 * @def EINA_LIST_REVERSE_FOREACH
 * @brief Macro to iterate over a list in the reverse order.
 *
 * @param list The list to iterate over.
 * @param l A list that is used as an iterator and points to the current node.
 * @param data Current item's data.
 *
 * This macro works like EINA_LIST_FOREACH, but iterates from the
 * last element of a list to the first.
 * @p data is the data related to the current element, while @p l
 * is an #Eina_List that is used as the list iterator.
 *
 * It can be used to free list data, as in the following example:
 *
 * @code
 * Eina_List *list;
 * Eina_List *l;
 * char      *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings,
 * // EINA_LIST_REVERSE_FOREACH will be used to free those strings
 *
 * EINA_LIST_REVERSE_FOREACH(list, l, data)
 *   free(data);
 * eina_list_free(list);
 * @endcode
 *
 * @note This is not the optimal way to release memory allocated to
 *       a list, since it iterates over the list twice.
 *       For an optimized algorithm, use EINA_LIST_FREE().
 *
 * @warning Be careful when deleting list nodes.
 *          If you remove the current node and continue iterating,
 *          the code will fail because the macro will not be able
 *          to get the next node. Notice that it's OK to remove any
 *          node if you stop the loop after that.
 *          For destructive operations such as this, consider
 *          using EINA_LIST_REVERSE_FOREACH_SAFE().
 */
#define EINA_LIST_REVERSE_FOREACH(list, l, data)	\
  for (l = eina_list_last(list),			\
	 data = eina_list_data_get(l);			\
       l;						\
       l = eina_list_prev(l),				\
	 data = eina_list_data_get(l))

/**
 * @def EINA_LIST_FOREACH_SAFE
 * @brief Macro to iterate over a list with support for node deletion.
 *
 * @param list The list to iterate over.
 * @param l A list that is used as an iterator and points to the current node.
 * @param l_next A list that is used as an iterator and points to the next node.
 * @param data Current item's data.
 *
 * This macro iterates over @p list from the first element to
 * the last. @p data is the data related to the current element.
 * @p l is an #Eina_List used as the list iterator.
 *
 * Since this macro stores a pointer to the next list node in @p l_next,
 * deleting the current node and continuing looping is safe.
 *
 * This macro can be used to free list nodes, as in the following example:
 *
 * @code
 * Eina_List *list;
 * Eina_List *l;
 * Eina_List *l_next;
 * char      *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings,
 * // EINA_LIST_FOREACH_SAFE will be used to free elements that match "key".
 *
 * EINA_LIST_FOREACH_SAFE(list, l, l_next, data)
 *   if (strcmp(data, "key") == 0) {
 *      free(data);
 *      list = eina_list_remove_list(list, l);
 *   }
 * @endcode
 */
#define EINA_LIST_FOREACH_SAFE(list, l, l_next, data)	\
  for (l = list,					\
	 l_next = eina_list_next(l),			\
	 data = eina_list_data_get(l);			\
       l;						\
       l = l_next,					\
	 l_next = eina_list_next(l),			\
	 data = eina_list_data_get(l))

/**
 * @def EINA_LIST_REVERSE_FOREACH_SAFE
 * @brief Macro to iterate over a list in the reverse order with support
 *        for deletion.
 *
 * @param list The list to iterate over.
 * @param l A list that is used as an iterator and points to the current node.
 * @param l_prev A list that is used as an iterator and points to the previous node.
 * @param data Current item's data.
 *
 * This macro works like EINA_LIST_FOREACH_SAFE, but iterates from the
 * last element of a list to the first.
 * @p data is the data related to the current element, while @p l
 * is an #Eina_List that is used as the list iterator.
 *
 * Since this macro stores a pointer to the previous list node in @p l_prev,
 * deleting the current node and continuing looping is safe.
 *
 * This macro can be used to free list nodes, as in the following example:
 *
 * @code
 * Eina_List *list;
 * Eina_List *l;
 * Eina_List *l_prev;
 * char       *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings,
 * // EINA_LIST_REVERSE_FOREACH_SAFE will be used to free elements that match "key".
 *
 * EINA_LIST_REVERSE_FOREACH_SAFE(list, l, l_prev, data)
 *   if (strcmp(data, "key") == 0) {
 *      free(data);
 *      list = eina_list_remove_list(list, l);
 *   }
 * @endcode
 */
#define EINA_LIST_REVERSE_FOREACH_SAFE(list, l, l_prev, data)	\
  for (l = eina_list_last(list),				\
	 l_prev = eina_list_prev(l),				\
	 data = eina_list_data_get(l);				\
       l;							\
       l = l_prev,						\
	 l_prev = eina_list_prev(l),				\
	 data = eina_list_data_get(l))

/**
 * @def EINA_LIST_FREE
 * @brief Macro to remove each list node while having access to each node's data.
 *
 * @param list The list that will be cleared.
 * @param data Current node's data.
 *
 * This macro will call #eina_list_remove_list for each list node, and store
 * the data contained in the current node in @p data.
 *
 * If you do not need to release node data, it is easier to call #eina_list_free().
 *
 * @code
 * Eina_List *list;
 * char      *data;
 *
 * // list is already filled,
 * // its elements are just duplicated strings,
 *
 * EINA_LIST_FREE(list, data)
 *   free(data);
 * @endcode
 *
 * @see eina_list_free()
 */
#define EINA_LIST_FREE(list, data)			\
  for (data = eina_list_data_get(list);			\
       list;						\
       list = eina_list_remove_list(list, list),	\
	 data = eina_list_data_get(list))

#include "eina_inline_list.x"

/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_LIST_H_ */
