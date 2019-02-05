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

#ifndef EINA_LIST_INLINE_H_
#define EINA_LIST_INLINE_H_

/**
 * @addtogroup Eina_List_Group List
 *
 * @brief These functions provide list management.
 *
 * @{
 */

/**
 * @brief Get the last list node in the list.
 *
 * @param list The list to get the last list node from.
 * @return The last list node in the list.
 *
 * This function returns the last list node in the list @p list. If
 * @p list is @c NULL or empty, @c NULL is returned.
 *
 * This is a order-1 operation (it takes the same short time
 * regardless of the length of the list).
 */
static inline Eina_List *
eina_list_last(const Eina_List *list)
{
   if (!list) return NULL;
   return list->accounting->last;
}

/**
 * @brief Get the next list node after the specified list node.
 *
 * @param list The list node to get the next list node from
 * @return The next list node on success, @c NULL otherwise.
 *
 * This function returns the next list node after the current one in
 * @p list. It is equivalent to list->next. If @p list is @c NULL or
 * if no next list node exists, it returns @c NULL.
 */
static inline Eina_List *
eina_list_next(const Eina_List *list)
{
   if (!list) return NULL;
   return list->next;
}

/**
 * @brief Get the previous list node before the specified list node.
 *
 * @param list The list node to get the previous list node from.
 * @return The previous list node o success, @c NULL otherwise.
 * if no previous list node exists
 *
 * This function returns the previous list node before the current one
 * in @p list. It is equivalent to list->prev. If @p list is @c NULL or
 * if no previous list node exists, it returns @c NULL.
 */
static inline Eina_List *
eina_list_prev(const Eina_List *list)
{
   if (!list) return NULL;
   return list->prev;
}

/**
 * @brief Get the list node data member.
 *
 * @param list The list node to get the data member of.
 * @return The data member from the list node.
 *
 * This function returns the data member of the specified list node @p
 * list. It is equivalent to list->data. If @p list is @c NULL, this
 * function returns @c NULL.
 */
static inline void *
eina_list_data_get(const Eina_List *list)
{
   if (!list) return NULL;
   return list->data;
}

/**
 * @brief Set the list node data member.
 *
 * @param list The list node to get the data member of.
 * @param data The data member to the list node.
 * @return The previous data value.
 *
 * This function set the data member @p data of the specified list node
 * @p list. It returns the previous data of the node. If @p list is
 * @c NULL, this function returns @c NULL.
 */
static inline void *
eina_list_data_set(Eina_List *list, const void *data)
{
   void *tmp;
   if (!list) return NULL;
   tmp = list->data;
   list->data = (void*) data;
   return tmp;
}

/**
 * @brief Get the count of the number of items in a list.
 *
 * @param list The list whose count to return.
 * @return The number of members in the list.
 *
 * This function returns how many members @p list contains. If the
 * list is @c NULL, 0 is returned.
 *
 * NB: This is an order-1 operation and takes the same time regardless
 * of the length of the list.
 */
static inline unsigned int
eina_list_count(const Eina_List *list)
{
   if (!list) return 0;
   return list->accounting->count;
}

/**
 * @}
 */

#endif /* EINA_LIST_INLINE_H_ */
