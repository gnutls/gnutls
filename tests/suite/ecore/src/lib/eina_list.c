/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Gustavo Sverzut Barbieri, Tilman Sauerbeck,
 *                         Vincent Torri, Cedric Bail, Jorge Luis Zapata Muga,
 *                         Corey Donohoe, Arnaud de Turckheim, Alexandre Becoulet
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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Copyright (C) 2004 ncn
 * Copyright (C) 2006 Sebastian Dransfeld
 * Copyright (C) 2007 Christopher Michael
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:

 *  The above copyright notice and this permission notice shall be included in
 *  all copies of the Software and its Copyright notices. In addition publicly
 *  documented acknowledgment must be given that this software has been used if no
 *  source code of this software is made available publicly. This includes
 *  acknowledgments in either Copyright notices, Manuals, Publicity and Marketing
 *  documents or any documentation provided with any product containing this
 *  software. This License does not apply to any software that links to the
 *  libraries provided by this software (statically or dynamically), but only to
 *  the software provided.

 *  Please see the OLD-COPYING.PLAIN for a plain-english explanation of this notice
 *  and it's intent.

 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


/**
 * @page tutorial_list_page List Tutorial
 *
 * to be written...
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_error.h"
#include "eina_log.h"
#include "eina_mempool.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_list.h"


/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

static const char EINA_MAGIC_LIST_STR[] = "Eina List";
static const char EINA_MAGIC_LIST_ITERATOR_STR[] = "Eina List Iterator";
static const char EINA_MAGIC_LIST_ACCESSOR_STR[] = "Eina List Accessor";
static const char EINA_MAGIC_LIST_ACCOUNTING_STR[] =
    "Eina List Accounting";


#define EINA_MAGIC_CHECK_LIST(d, ...)                           \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_LIST))                  \
          {                                                           \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_LIST);                    \
             return __VA_ARGS__;                                     \
          }                                                           \
     } while(0)

#define EINA_MAGIC_CHECK_LIST_ITERATOR(d, ...)                  \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_LIST_ITERATOR))         \
          {                                                           \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_LIST_ITERATOR);           \
             return __VA_ARGS__;                                     \
          }                                                           \
     } while(0)

#define EINA_MAGIC_CHECK_LIST_ACCESSOR(d, ...)                  \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_LIST_ACCESSOR))         \
          {                                                           \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_LIST_ACCESSOR);           \
             return __VA_ARGS__;                                     \
          }                                                           \
     } while(0)

#define EINA_MAGIC_CHECK_LIST_ACCOUNTING(d)                     \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_LIST_ACCOUNTING))       \
          {                                                           \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_LIST_ACCOUNTING);         \
             return;                                                 \
          }                                                           \
     } while(0)

#define EINA_LIST_SORT_STACK_SIZE 32

typedef struct _Eina_Iterator_List Eina_Iterator_List;
typedef struct _Eina_Accessor_List Eina_Accessor_List;

struct _Eina_Iterator_List {
	Eina_Iterator iterator;

	const Eina_List *head;
	const Eina_List *current;

 EINA_MAGIC};

struct _Eina_Accessor_List {
	Eina_Accessor accessor;

	const Eina_List *head;
	const Eina_List *current;

	unsigned int index;

 EINA_MAGIC};

static Eina_Mempool *_eina_list_mp = NULL;
static Eina_Mempool *_eina_list_accounting_mp = NULL;
static int _eina_list_log_dom = -1;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_list_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_list_log_dom, __VA_ARGS__)

static inline Eina_List_Accounting
    *_eina_list_mempool_accounting_new(__UNUSED__ Eina_List * list)
{
	Eina_List_Accounting *tmp;

	tmp =
	    eina_mempool_malloc(_eina_list_accounting_mp,
				sizeof(Eina_List_Accounting));
	if (!tmp)
		return NULL;

	EINA_MAGIC_SET(tmp, EINA_MAGIC_LIST_ACCOUNTING);

	return tmp;
}

static inline void
_eina_list_mempool_accounting_free(Eina_List_Accounting * accounting)
{
	EINA_MAGIC_CHECK_LIST_ACCOUNTING(accounting);

	EINA_MAGIC_SET(accounting, EINA_MAGIC_NONE);
	eina_mempool_free(_eina_list_accounting_mp, accounting);
}

static inline Eina_List *_eina_list_mempool_list_new(__UNUSED__ Eina_List *
						     list)
{
	Eina_List *tmp;

	tmp = eina_mempool_malloc(_eina_list_mp, sizeof(Eina_List));
	if (!tmp)
		return NULL;

	EINA_MAGIC_SET(tmp, EINA_MAGIC_LIST);

	return tmp;
}

static inline void _eina_list_mempool_list_free(Eina_List * list)
{
	EINA_MAGIC_CHECK_LIST(list);

	list->accounting->count--;
	if (list->accounting->count == 0)
		_eina_list_mempool_accounting_free(list->accounting);

	EINA_MAGIC_SET(list, EINA_MAGIC_NONE);
	eina_mempool_free(_eina_list_mp, list);
}

static Eina_List *_eina_list_setup_accounting(Eina_List * list)
{
	EINA_MAGIC_CHECK_LIST(list, NULL);

	list->accounting = _eina_list_mempool_accounting_new(list);
	if (!list->accounting)
		goto on_error;

	list->accounting->last = list;
	list->accounting->count = 1;

	return list;

      on_error:
	_eina_list_mempool_list_free(list);
	return NULL;
}

static inline void
_eina_list_update_accounting(Eina_List * list, Eina_List * new_list)
{
	EINA_MAGIC_CHECK_LIST(list);
	EINA_MAGIC_CHECK_LIST(new_list);

	list->accounting->count++;
	new_list->accounting = list->accounting;
}

#if 0
static Eina_Mempool2 _eina_list_mempool = {
	sizeof(Eina_List),
	320,
	0, NULL, NULL
};

static Eina_Mempool2 _eina_list_accounting_mempool = {
	sizeof(Eina_List_Accounting),
	80,
	0, NULL, NULL
};
#endif

static Eina_Bool
eina_list_iterator_next(Eina_Iterator_List * it, void **data)
{
	EINA_MAGIC_CHECK_LIST_ITERATOR(it, EINA_FALSE);

	if (!it->current)
		return EINA_FALSE;

	*data = eina_list_data_get(it->current);

	it->current = eina_list_next(it->current);

	return EINA_TRUE;
}

static Eina_Bool
eina_list_iterator_prev(Eina_Iterator_List * it, void **data)
{
	EINA_MAGIC_CHECK_LIST_ITERATOR(it, EINA_FALSE);

	if (!it->current)
		return EINA_FALSE;

	*data = eina_list_data_get(it->current);

	it->current = eina_list_prev(it->current);

	return EINA_TRUE;
}

static Eina_List *eina_list_iterator_get_container(Eina_Iterator_List * it)
{
	EINA_MAGIC_CHECK_LIST_ITERATOR(it, NULL);

	return (Eina_List *) it->head;
}

static void eina_list_iterator_free(Eina_Iterator_List * it)
{
	EINA_MAGIC_CHECK_LIST_ITERATOR(it);

	MAGIC_FREE(it);
}

static Eina_Bool
eina_list_accessor_get_at(Eina_Accessor_List * it, unsigned int idx,
			  void **data)
{
	const Eina_List *over;
	unsigned int middle;
	unsigned int i;

	EINA_MAGIC_CHECK_LIST_ACCESSOR(it, EINA_FALSE);

	if (idx >= eina_list_count(it->head))
		return EINA_FALSE;

	if (it->index == idx)
		over = it->current;
	else if (idx > it->index) {
		/* After current position. */
		middle =
		    ((eina_list_count(it->head) - it->index) >> 1) +
		    it->index;

		if (idx > middle)
			/* Go backward from the end. */
			for (i = eina_list_count(it->head) - 1,
			     over = eina_list_last(it->head);
			     i > idx && over;
			     --i, over = eina_list_prev(over));
		else
			/* Go forward from current. */
			for (i = it->index, over = it->current;
			     i < idx && over;
			     ++i, over = eina_list_next(over));
	} else {
		/* Before current position. */
		middle = it->index >> 1;

		if (idx > middle)
			/* Go backward from current. */
			for (i = it->index, over = it->current;
			     i > idx && over;
			     --i, over = eina_list_prev(over));
		else
			/* Go forward from start. */
			for (i = 0, over = it->head;
			     i < idx && over;
			     ++i, over = eina_list_next(over));
	}

	if (!over)
		return EINA_FALSE;

	it->current = over;
	it->index = idx;

	*data = eina_list_data_get(it->current);
	return EINA_TRUE;
}

static Eina_List *eina_list_accessor_get_container(Eina_Accessor_List * it)
{
	EINA_MAGIC_CHECK_LIST_ACCESSOR(it, NULL);

	return (Eina_List *) it->head;
}

static void eina_list_accessor_free(Eina_Accessor_List * it)
{
	EINA_MAGIC_CHECK_LIST_ACCESSOR(it);

	MAGIC_FREE(it);
}

static Eina_List *eina_list_sort_rebuild_prev(Eina_List * list)
{
	Eina_List *prev = NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	for (; list; list = list->next) {
		list->prev = prev;
		prev = list;
	}

	return prev;
}

static Eina_List *eina_list_sort_merge(Eina_List * a, Eina_List * b,
				       Eina_Compare_Cb func)
{
	Eina_List *first, *last;

	if (func(a->data, b->data) < 0)
		a = (last = first = a)->next;
	else
		b = (last = first = b)->next;

	while (a && b)
		if (func(a->data, b->data) < 0)
			a = (last = last->next = a)->next;
		else
			b = (last = last->next = b)->next;

	last->next = a ? a : b;

	return first;
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the list module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the list module of Eina. It is called by
 * eina_init().
 *
 * This function creates mempool to speed up list node and accounting
 * management, using EINA_MEMPOOL environment variable if it is set to
 * choose the memory pool type to use.
 *
 * @see eina_init()
 */
Eina_Bool eina_list_init(void)
{
	const char *choice, *tmp;

	_eina_list_log_dom = eina_log_domain_register("eina_list",
						      EINA_LOG_COLOR_DEFAULT);
	if (_eina_list_log_dom < 0) {
		EINA_LOG_ERR("Could not register log domain: eina_list");
		return EINA_FALSE;
	}
#ifdef EINA_DEFAULT_MEMPOOL
	choice = "pass_through";
#else
	choice = "chained_mempool";
#endif
	tmp = getenv("EINA_MEMPOOL");
	if (tmp && tmp[0])
		choice = tmp;

	_eina_list_mp = eina_mempool_add
	    (choice, "list", NULL, sizeof(Eina_List), 320);
	if (!_eina_list_mp) {
		ERR("ERROR: Mempool for list cannot be allocated in list init.");
		goto on_init_fail;
	}

	_eina_list_accounting_mp = eina_mempool_add
	    (choice, "list_accounting", NULL, sizeof(Eina_List_Accounting),
	     80);
	if (!_eina_list_accounting_mp) {
		ERR("ERROR: Mempool for list accounting cannot be allocated in list init.");
		eina_mempool_del(_eina_list_mp);
		goto on_init_fail;
	}
#define EMS(n) eina_magic_string_static_set(n, n ## _STR)
	EMS(EINA_MAGIC_LIST);
	EMS(EINA_MAGIC_LIST_ITERATOR);
	EMS(EINA_MAGIC_LIST_ACCESSOR);
	EMS(EINA_MAGIC_LIST_ACCOUNTING);
#undef EMS

	return EINA_TRUE;

      on_init_fail:
	eina_log_domain_unregister(_eina_list_log_dom);
	_eina_list_log_dom = -1;
	return EINA_FALSE;
}

/**
 * @internal
 * @brief Shut down the list module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the list module set up by
 * eina_list_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_list_shutdown(void)
{
	eina_mempool_del(_eina_list_accounting_mp);
	eina_mempool_del(_eina_list_mp);

	eina_log_domain_unregister(_eina_list_log_dom);
	_eina_list_log_dom = -1;
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_List_Group List
 *
 * @brief These functions provide double linked list management.
 *
 * For more information, you can look at the @ref tutorial_list_page.
 *
 * @{
 */

/**
 * @brief Append the given data to the given linked list.
 *
 * @param list The given list.
 * @param data The data to append.
 * @return A list pointer.
 *
 * This function appends @p data to @p list. If @p list is @c NULL, a
 * new list is returned. On success, a new list pointer that should be
 * used in place of the one given to this function is
 * returned. Otherwise, the old pointer is returned.
 *
 * The following example code demonstrates how to ensure that the
 * given data has been successfully appended.
 *
 * @code
 * Eina_List *list = NULL;
 * extern void *my_data;
 *
 * list = eina_list_append(list, my_data);
 * if (eina_error_get())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_append(Eina_List * list, const void *data)
{
	Eina_List *l, *new_l;

	eina_error_set(0);
	new_l = _eina_list_mempool_list_new(list);
	if (!new_l)
		return list;

	new_l->next = NULL;
	new_l->data = (void *) data;
	if (!list) {
		new_l->prev = NULL;
		return _eina_list_setup_accounting(new_l);
	}

	EINA_MAGIC_CHECK_LIST(list, NULL);

	l = list->accounting->last;
	list->accounting->last = new_l;

	l->next = new_l;
	new_l->prev = l;

	_eina_list_update_accounting(list, new_l);
	return list;
}

/**
 * @brief Prepends the given data to the given linked list.
 *
 * @param list The given list.
 * @param data The data to prepend.
 * @return A list pointer.
 *
 * This function prepends @p data to @p list. If @p list is @c NULL, a
 * new list is returned. On success, a new list pointer that should be
 * used in place of the one given to this function is
 * returned. Otherwise, the old pointer is returned.
 *
 * The following example code demonstrates how to ensure that the
 * given data has been successfully prepended.
 *
 * Example:
 * @code
 * Eina_List *list = NULL;
 * extern void *my_data;
 *
 * list = eina_list_prepend(list, my_data);
 * if (eina_error_get())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_prepend(Eina_List * list, const void *data)
{
	Eina_List *new_l;

	eina_error_set(0);
	new_l = _eina_list_mempool_list_new(list);
	if (!new_l)
		return list;

	new_l->prev = NULL;
	new_l->next = list;
	new_l->data = (void *) data;

	if (!list)
		return _eina_list_setup_accounting(new_l);

	EINA_MAGIC_CHECK_LIST(list, NULL);

	list->prev = new_l;

	_eina_list_update_accounting(list, new_l);

	return new_l;
}

/**
 * @brief Insert the given data into the given linked list after the specified data.
 *
 * @param list The given linked list.
 * @param data The data to insert.
 * @param relative The data to insert after.
 * @return A list pointer.
 *
 * This function inserts @p data to @p list after @p relative. If
 * @p relative is not in the list, @p data is appended to the end of
 * the list.  If @p list is @c NULL, a  new list is returned. If there
 * are multiple instances of @p relative in the list, @p data is
 * inserted after the first instance.On success, a new list pointer
 * that should be used in place of the one given to this function is
 * returned. Otherwise, the old pointer is returned.
 *
 * The following example code demonstrates how to ensure that the
 * given data has been successfully inserted.
 *
 * @code
 * Eina_List *list = NULL;
 * extern void *my_data;
 * extern void *relative_member;
 *
 * list = eina_list_append(list, relative_member);
 * if (eina_error_get())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * list = eina_list_append_relative(list, my_data, relative_member);
 * if (eina_error_get())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_append_relative(Eina_List * list,
					  const void *data,
					  const void *relative)
{
	Eina_List *l;
	void *list_data;

	if (list)
		EINA_MAGIC_CHECK_LIST(list, NULL);

	EINA_LIST_FOREACH(list, l, list_data) {
		if (list_data == relative)
			return eina_list_append_relative_list(list, data,
							      l);
	}

	return eina_list_append(list, data);
}

/**
 * @brief Append a list node to a linked list after the specified member
 *
 * @param list The given linked list.
 * @param data The data to insert.
 * @param relative The list node to insert after.
 * @return A list pointer.
 *
 * This function inserts @p data to @p list after the list node
 * @p relative. If @p list or @p relative are @c NULL, @p data is just
 * appended to @p list using eina_list_append(). If @p list is
 * @c NULL, a  new list is returned. If there are multiple instances
 * of @p relative in the list, @p data is inserted after the first
 * instance. On success, a new list pointer that should be used in
 * place of the one given to this function is returned. Otherwise, the
 * old pointer is returned.
 */
EAPI Eina_List *eina_list_append_relative_list(Eina_List * list,
					       const void *data,
					       Eina_List * relative)
{
	Eina_List *new_l;

	if ((!list) || (!relative))
		return eina_list_append(list, data);

	eina_error_set(0);
	new_l = _eina_list_mempool_list_new(list);
	if (!new_l)
		return list;

	EINA_MAGIC_CHECK_LIST(relative, NULL);
	new_l->next = relative->next;
	new_l->data = (void *) data;

	if (relative->next)
		relative->next->prev = new_l;

	relative->next = new_l;
	new_l->prev = relative;

	_eina_list_update_accounting(list, new_l);

	if (!new_l->next)
		new_l->accounting->last = new_l;

	return list;
}

/**
 * @brief Prepend a data pointer to a linked list before the specified member
 *
 * @param list The given linked list.
 * @param data The data to insert.
 * @param relative The data to insert before.
 * @return A list pointer.
 *
 * This function inserts @p data to @p list before @p relative. If
 * @p relative is not in the list, @p data is prepended to the list
 * with eina_list_prepend(). If @p list is @c NULL, a  new list is
 * returned. If there are multiple instances of @p relative in the
 * list, @p data is inserted before the first instance. On success, a
 * new list pointer that should be used in place of the one given to
 * this function is returned. Otherwise, the old pointer is returned.
 *
 * The following code example demonstrates how to ensure that the
 * given data has been successfully inserted.
 *
 * @code
 * Eina_List *list = NULL;
 * extern void *my_data;
 * extern void *relative_member;
 *
 * list = eina_list_append(list, relative_member);
 * if (eina_error_get_error())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * list = eina_list_prepend_relative(list, my_data, relative_member);
 * if (eina_error_get())
 *   {
 *     fprintf(stderr, "ERROR: Memory is low. List allocation failed.\n");
 *     exit(-1);
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_prepend_relative(Eina_List * list,
					   const void *data,
					   const void *relative)
{
	Eina_List *l;
	void *list_data;

	if (list)
		EINA_MAGIC_CHECK_LIST(list, NULL);

	EINA_LIST_FOREACH(list, l, list_data) {
		if (list_data == relative)
			return eina_list_prepend_relative_list(list, data,
							       l);
	}
	return eina_list_prepend(list, data);
}

/**
 * @brief Prepend a list node to a linked list before the specified member
 *
 * @param list The given linked list.
 * @param data The data to insert.
 * @param relative The list node to insert before.
 * @return A list pointer.
 *
 * This function inserts @p data to @p list before the list node
 * @p relative. If @p list or @p relative are @c NULL, @p data is just
 * prepended to @p list using eina_list_prepend(). If @p list is
 * @c NULL, a  new list is returned. If there are multiple instances
 * of @p relative in the list, @p data is inserted before the first
 * instance. On success, a new list pointer that should be used in
 * place of the one given to this function is returned. Otherwise, the
 * old pointer is returned.
 */
EAPI Eina_List *eina_list_prepend_relative_list(Eina_List * list,
						const void *data,
						Eina_List * relative)
{
	Eina_List *new_l;

	if ((!list) || (!relative))
		return eina_list_prepend(list, data);

	eina_error_set(0);
	new_l = _eina_list_mempool_list_new(list);
	if (!new_l)
		return list;

	EINA_MAGIC_CHECK_LIST(relative, NULL);

	new_l->prev = relative->prev;
	new_l->next = relative;
	new_l->data = (void *) data;

	if (relative->prev)
		relative->prev->next = new_l;

	relative->prev = new_l;

	_eina_list_update_accounting(list, new_l);

	if (new_l->prev)
		return list;

	return new_l;
}

/**
 * @brief Insert a new node into a sorted list.
 *
 * @param list The given linked list, @b must be sorted.
 * @param func The function called for the sort.
 * @param data The data to insert sorted.
 * @return A list pointer.
 *
 * This function inserts values into a linked list assuming it was
 * sorted and the result will be sorted. If @p list is @c NULLL, a new
 * list is returned. On success, a new list pointer that should be
 * used in place of the one given to this function is
 * returned. Otherwise, the old pointer is returned. See eina_error_get().
 *
 * @note O(log2(n)) comparisons (calls to @p func) average/worst case
 * performance as it uses eina_list_search_sorted_near_list() and thus
 * is bounded to that. As said in eina_list_search_sorted_near_list(),
 * lists do not have O(1) access time, so walking to the correct node
 * can be costly, consider worst case to be almost O(n) pointer
 * dereference (list walk).
 */
EAPI Eina_List *eina_list_sorted_insert(Eina_List * list,
					Eina_Compare_Cb func,
					const void *data)
{
	Eina_List *lnear;
	int cmp;

	if (!list)
		return eina_list_append(NULL, data);

	lnear = eina_list_search_sorted_near_list(list, func, data, &cmp);
	if (cmp < 0)
		return eina_list_append_relative_list(list, data, lnear);
	else
		return eina_list_prepend_relative_list(list, data, lnear);
}

/**
 * @brief Remove the first instance of the specified data from the given list.
 *
 * @param list The given list.
 * @param data The specified data.
 * @return A list pointer.
 *
 * This function removes the first instance of @p data from
 * @p list. If the specified data is not in the given list (tihis
 * include the case where @p data is @c NULL), nothing is done. If
 * @p list is @c NULL, @c NULL is returned, otherwise a new list
 * pointer that should be used in place of the one passed to this
 * function.
 */
EAPI Eina_List *eina_list_remove(Eina_List * list, const void *data)
{
	Eina_List *l;

	if (list)
		EINA_MAGIC_CHECK_LIST(list, NULL);

	l = eina_list_data_find_list(list, data);
	return eina_list_remove_list(list, l);
}

/**
 * @brief Remove the specified data.
 *
 * @param list The given linked list.
 * @param remove_list The list node which is to be removed.
 * @return A list pointer.
 *
 * This function removes the list node @p remove_list from @p list and
 * frees the list node structure @p remove_list. If @p list is
 * @c NULL, this function returns @c NULL. If @p remove_list is
 * @c NULL, it returns @p list, otherwise, a new list pointer that
 * should be used in place of the one passed to this function.
 *
 * The following code gives an example (notice we use EINA_LIST_FOREACH
 * instead of EINA_LIST_FOREACH_SAFE because we stop the loop after
 * removing the current node).
 *
 * @code
 * extern Eina_List *list;
 * Eina_List *l;
 * extern void *my_data;
 * void *data
 *
 * EINA_LIST_FOREACH(list, l, data)
 *   {
 *     if (data == my_data)
 *       {
 *         list = eina_list_remove_list(list, l);
 *         break;
 *       }
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_remove_list(Eina_List * list,
				      Eina_List * remove_list)
{
	Eina_List *return_l;

	if (!list)
		return NULL;

	if (!remove_list)
		return list;

	EINA_MAGIC_CHECK_LIST(remove_list, NULL);

	if (remove_list->next)
		remove_list->next->prev = remove_list->prev;

	if (remove_list->prev) {
		remove_list->prev->next = remove_list->next;
		return_l = list;
	} else
		return_l = remove_list->next;

	if (remove_list == remove_list->accounting->last) {
		EINA_MAGIC_CHECK_LIST(list, NULL);
		list->accounting->last = remove_list->prev;
	}

	_eina_list_mempool_list_free(remove_list);
	return return_l;
}

/**
 * @brief Free an entire list and all the nodes, ignoring the data contained.

 * @param list The list to free
 * @return A NULL pointer
 *
 * This function frees all the nodes of @p list. It does not free the
 * data of the nodes. To free them, use #EINA_LIST_FREE.
 */
EAPI Eina_List *eina_list_free(Eina_List * list)
{
	Eina_List *l, *free_l;

	if (!list)
		return NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	for (l = list; l;) {
		free_l = l;
		l = l->next;

		_eina_list_mempool_list_free(free_l);
	}

	return NULL;
}

/**
 * @brief Move the specified data to the head of the list.
 *
 * @param list The list handle to move the data.
 * @param move_list The list node to move.
 * @return A new list handle to replace the old one
 *
 * This function move @p move_list to the front of @p list. If list is
 * @c NULL, @c NULL is returned. If @p move_list is @c NULL,
 * @p list is returned. Otherwise, a new list pointer that should be
 * used in place of the one passed to this function.
 *
 * Example:
 * @code
 * extern Eina_List *list;
 * Eina_List *l;
 * extern void *my_data;
 * void *data;
 *
 * EINA_LIST_FOREACH(list, l, data)
 *   {
 *     if (data == my_data)
 *       {
 *         list = eina_list_promote_list(list, l);
 *         break;
 *       }
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_promote_list(Eina_List * list,
				       Eina_List * move_list)
{
	if (!list)
		return NULL;

	if (!move_list) {
		return list;	/* Promoting head to be head. */

	}

	if (move_list == list)
		return list;

	if (move_list->next == list)
		return move_list;

	EINA_MAGIC_CHECK_LIST(list, NULL);
	EINA_MAGIC_CHECK_LIST(move_list, NULL);

	/* Remove the promoted item from the list. */
	if (!move_list->prev)
		move_list->next->prev = NULL;
	else {
		move_list->prev->next = move_list->next;
		if (move_list == list->accounting->last)
			list->accounting->last = move_list->prev;
		else
			move_list->next->prev = move_list->prev;
	}

	/* Add the promoted item in the list. */
	move_list->next = list;
	move_list->prev = list->prev;
	list->prev = move_list;
	if (move_list->prev)
		move_list->prev->next = move_list;

	return move_list;
}

/**
 * @brief Move the specified data to the tail of the list.
 *
 * @param list The list handle to move the data.
 * @param move_list The list node to move.
 * @return A new list handle to replace the old one
 *
 * This function move @p move_list to the back of @p list. If list is
 * @c NULL, @c NULL is returned. If @p move_list is @c NULL,
 * @p list is returned. Otherwise, a new list pointer that should be
 * used in place of the one passed to this function.
 *
 * Example:
 * @code
 * extern Eina_List *list;
 * Eina_List *l;
 * extern void *my_data;
 * void *data;
 *
 * EINA_LIST_FOREACH(list, l, data)
 *   {
 *     if (data == my_data)
 *       {
 *         list = eina_list_demote_list(list, l);
 *         break;
 *       }
 *   }
 * @endcode
 */
EAPI Eina_List *eina_list_demote_list(Eina_List * list,
				      Eina_List * move_list)
{
	if (!list)
		return NULL;

	if (!move_list) {
		return list;	/* Demoting tail to be tail. */

	}

	if (move_list == list->accounting->last)
		return list;

	EINA_MAGIC_CHECK_LIST(list, NULL);
	EINA_MAGIC_CHECK_LIST(move_list, NULL);

	/* Update pointer list if necessary. */
	if (list == move_list) {
		list = move_list->next;	/* Remove the demoted item from the list. */

	}

	if (move_list->prev)
		move_list->prev->next = move_list->next;

	move_list->next->prev = move_list->prev;
	/* Add the demoted item in the list. */
	move_list->prev = list->accounting->last;
	move_list->prev->next = move_list;
	move_list->next = NULL;
	list->accounting->last = move_list;

	return list;
}

/**
 * @brief Find a member of a list and return the member.
 *
 * @param list The list to search for a data.
 * @param data The data pointer to find in the list.
 * @return The found member data pointer if foun, @c NULL otherwise.
 *
 * This function searches in @p list from beginning to end for the
 * first member whose data pointer is @p data. If it is found, @p data
 * will be returned, otherwise NULL will be returned.
 *
 * Example:
 * @code
 * extern Eina_List *list;
 * extern void *my_data;
 *
 * if (eina_list_data_find(list, my_data) == my_data)
 *   {
 *     printf("Found member %p\n", my_data);
 *   }
 * @endcode
 */
EAPI void *eina_list_data_find(const Eina_List * list, const void *data)
{
	if (eina_list_data_find_list(list, data))
		return (void *) data;

	return NULL;
}

/**
 * @brief Find a member of a list and return the list node containing that member.
 *
 * @param list The list to search for data.
 * @param data The data pointer to find in the list.
 * @return The found members list node on success, @c NULL otherwise.
 *
 * This function searches in @p list from beginning to end for the
 * first member whose data pointer is @p data. If it is found, the
 * list node containing the specified member is returned, otherwise
 * @c NULL is returned.
 */
EAPI Eina_List *eina_list_data_find_list(const Eina_List * list,
					 const void *data)
{
	const Eina_List *l;
	void *list_data;

	if (list)
		EINA_MAGIC_CHECK_LIST(list, NULL);

	EINA_LIST_FOREACH(list, l, list_data) {
		if (list_data == data)
			return (Eina_List *) l;
	}

	return NULL;
}

/**
 * @brief Get the nth member's data pointer in a list.
 *
 * @param list The list to get the specified member number from.
 * @param n The number of the element (0 being the first).
 * @return The data pointer stored in the specified element.
 *
 * This function returns the data pointer of element number @p n, in
 * the @p list. The first element in the array is element number 0. If
 * the element number @p n does not exist, @c NULL is
 * returned. Otherwise, the data of the found element is returned.
 */
EAPI void *eina_list_nth(const Eina_List * list, unsigned int n)
{
	Eina_List *l;

	l = eina_list_nth_list(list, n);
	return l ? l->data : NULL;
}

/**
 * @brief Get the nth member's list node in a list.
 *
 * @param list The list to get the specfied member number from.
 * @param n The number of the element (0 being the first).
 * @return The list node stored in the numbered element.
 *
 * This function returns the list node of element number @p n, in
 * @ list. The first element in the array is element number 0. If the
 * element number @p n does not exist or @p list is @c NULL or @p n is
 * greater than the count of elements in @p list minus 1, @c NULL is
 * returned. Otherwise the list node stored in the numbered element is
 * returned.
 */
EAPI Eina_List *eina_list_nth_list(const Eina_List * list, unsigned int n)
{
	const Eina_List *l;
	unsigned int i;

	if (list)
		EINA_MAGIC_CHECK_LIST(list, NULL);

	/* check for non-existing nodes */
	if ((!list) || (n > (list->accounting->count - 1)))
		return NULL;

	/* if the node is in the 2nd half of the list, search from the end
	 * else, search from the beginning.
	 */
	if (n > (list->accounting->count / 2))
		for (i = list->accounting->count - 1,
		     l = list->accounting->last; l; l = l->prev, i--) {
			if (i == n)
				return (Eina_List *) l;
	} else
		for (i = 0, l = list; l; l = l->next, i++) {
			if (i == n)
				return (Eina_List *) l;
		}

	abort();
}

/**
 * @brief Reverse all the elements in the list.
 *
 * @param list The list to reverse.
 * @return The list head after it has been reversed.
 *
 * This function reverses the order of all elements in @p list, so the
 * last member is now first, and so on. If @p list is @c NULL, this
 * functon returns @c NULL.
 *
 * @note @b in-place: this will change the given list, so you should
 * now point to the new list head that is returned by this function.
 *
 * @see eina_list_reverse_clone()
 * @see eina_list_iterator_reversed_new()
 */
EAPI Eina_List *eina_list_reverse(Eina_List * list)
{
	Eina_List *l1, *l2;

	if (!list)
		return NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	l1 = list;
	l2 = list->accounting->last;
	while (l1 != l2) {
		void *data;

		data = l1->data;
		l1->data = l2->data;
		l2->data = data;
		l1 = l1->next;
		if (l1 == l2)
			break;

		l2 = l2->prev;
	}

	return list;
}

/**
 * @brief Clone (copy) all the elements in the list in reverse order.
 *
 * @param list The list to reverse.
 * @return The new list that has been reversed.
 *
 * This function reverses the order of all elements in @p list, so the
 * last member is now first, and so on. If @p list is @c NULL, this
 * functon returns @c NULL. This returns a copy of the given list.
 *
 * @note @b copy: this will copy the list and you should then
 * eina_list_free() when it is not required anymore.
 *
 * @see eina_list_reverse()
 * @see eina_list_clone()
 */
EAPI Eina_List *eina_list_reverse_clone(const Eina_List * list)
{
	const Eina_List *l;
	Eina_List *lclone;
	void *data;

	if (!list)
		return NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	lclone = NULL;
	EINA_LIST_FOREACH(list, l, data)
	    lclone = eina_list_prepend(lclone, data);

	return lclone;
}

/**
 * @brief Clone (copy) all the elements in the list in exact order.
 *
 * @param list The list to clone.
 * @return The new list that has been cloned.
 *
 * This function clone in order of all elements in @p list. If @p list
 * is @c NULL, this functon returns @c NULL. This returns a copy of
 * the given list.
 *
 * @note @b copy: this will copy the list and you should then
 * eina_list_free() when it is not required anymore.
 *
 * @see eina_list_reverse_clone()
 */
EAPI Eina_List *eina_list_clone(const Eina_List * list)
{
	const Eina_List *l;
	Eina_List *lclone;
	void *data;

	if (!list)
		return NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	lclone = NULL;
	EINA_LIST_FOREACH(list, l, data)
	    lclone = eina_list_append(lclone, data);

	return lclone;
}

/**
 * @brief Sort a list according to the ordering func will return.
 *
 * @param list The list handle to sort.
 * @param size The length of the list to sort.
 * @param func A function pointer that can handle comparing the list data
 * nodes.
 * @return the new head of list.
 *
 * This function sorts @p list. @p size if the number of the first
 * element to sort. If @p size is 0 or greater than the number of
 * elements in @p list, all the elements are sorted. @p func is used to
 * compare two elements of @p list. If @p list or @p func are @c NULL,
 * this function returns @c NULL.
 *
 * @note @b in-place: this will change the given list, so you should
 * now point to the new list head that is returned by this function.
 *
 * @note worst case is O(n * log2(n)) comparisons (calls to func()),
 * O(n) comparisons average case. That means that for 1,000,000 list
 * elements, sort will usually do 1,000,000 comparisons, but may do up
 * to 20,000,000.
 *
 * Example:
 * @code
 * int
 * sort_cb(const void *d1, const void *d2)
 * {
 *    const char *txt = NULL;
 *    const char *txt2 = NULL;
 *
 *    if(!d1) return(1);
 *    if(!d2) return(-1);
 *
 *    return(strcmp((const char*)d1, (const char*)d2));
 * }
 * extern Eina_List *list;
 *
 * list = eina_list_sort(list, eina_list_count(list), sort_cb);
 * @endcode
 */
EAPI Eina_List *eina_list_sort(Eina_List * list, unsigned int size,
			       Eina_Compare_Cb func)
{
	unsigned int i = 0;
	unsigned int n = 0;
	Eina_List *tail = list;
	Eina_List *unsort = NULL;
	Eina_List *stack[EINA_LIST_SORT_STACK_SIZE];

	EINA_SAFETY_ON_NULL_RETURN_VAL(func, list);
	if (!list)
		return NULL;

	EINA_MAGIC_CHECK_LIST(list, NULL);

	/* if the caller specified an invalid size, sort the whole list */
	if ((size == 0) || (size > list->accounting->count))
		size = list->accounting->count;

	if (size != list->accounting->count) {
		unsort = eina_list_nth_list(list, size);
		if (unsort)
			unsort->prev->next = NULL;
	}

	while (tail) {
		unsigned int idx, tmp;

		Eina_List *a = tail;
		Eina_List *b = tail->next;

		if (!b) {
			stack[i++] = a;
			break;
		}

		tail = b->next;

		if (func(a->data, b->data) < 0)
			((stack[i++] = a)->next = b)->next = 0;
		else
			((stack[i++] = b)->next = a)->next = 0;

		tmp = n++;
		for (idx = n ^ tmp; idx &= idx - 1; i--)
			stack[i - 2] =
			    eina_list_sort_merge(stack[i - 2],
						 stack[i - 1], func);
	}

	while (i-- > 1)
		stack[i - 1] =
		    eina_list_sort_merge(stack[i - 1], stack[i], func);

	list = stack[0];
	tail = eina_list_sort_rebuild_prev(list);

	if (unsort) {
		tail->next = unsort;
		unsort->prev = tail;
	} else
		list->accounting->last = tail;

	return list;
}

/**
 * @brief Merge two list.
 *
 * @param left Head list to merge.
 * @param right Tail list to merge.
 * @return A new merged list.
 *
 * This function put right at the end of left and return the head.
 *
 * Both left and right does not exist anymore after the merge.
 *
 * @note merge cost is O(n), being @b n the size of the smallest
 * list. This is due the need to fix accounting of that segment,
 * making count and last access O(1).
 */
EAPI Eina_List *eina_list_merge(Eina_List * left, Eina_List * right)
{
	unsigned int n_left, n_right;

	if (!left)
		return right;

	if (!right)
		return left;

	left->accounting->last->next = right;
	right->prev = left->accounting->last;

	n_left = left->accounting->count;
	n_right = right->accounting->count;

	if (n_left >= n_right) {
		Eina_List *itr = right;
		left->accounting->last = right->accounting->last;
		left->accounting->count += n_right;

		_eina_list_mempool_accounting_free(right->accounting);

		do {
			itr->accounting = left->accounting;
			itr = itr->next;
		}
		while (itr);
	} else {
		Eina_List *itr = left->accounting->last;
		right->accounting->count += n_left;

		_eina_list_mempool_accounting_free(left->accounting);

		do {
			itr->accounting = right->accounting;
			itr = itr->prev;
		}
		while (itr);
	}

	return left;
}


/**
 * @brief Split a list into 2 lists.
 *
 * @param list List to split.
 * @param relative The list will be split after @p relative.
 * @param right The head of the new right list.
 * @return The new left list
 *
 * This function split @p list into two lists ( left and right ) after the node @p relative. @p Relative
 * will become the last node of the left list. If @p list or @p right are NULL list is returns.
 * If @p relative is NULL right is set to @p list and NULL is returns.
 * If @p relative is the last node of @p list list is returns and @p right is set to NULL.
 *
 * list does not exist anymore after the split.
 *
 */
EAPI Eina_List *eina_list_split_list(Eina_List * list,
				     Eina_List * relative,
				     Eina_List ** right)
{
	Eina_List *next;
	Eina_List *itr;

	if (!right)
		return list;

	*right = NULL;

	if (!list)
		return NULL;

	if (!relative) {
		*right = list;
		return NULL;
	}

	if (relative == eina_list_last(list))
		return list;

	next = eina_list_next(relative);
	next->prev = NULL;
	next->accounting = _eina_list_mempool_accounting_new(next);
	next->accounting->last = list->accounting->last;
	*right = next;

	itr = next;
	do {
		itr->accounting = next->accounting;
		next->accounting->count++;
		itr = itr->next;
	}
	while (itr);

	relative->next = NULL;
	list->accounting->last = relative;
	list->accounting->count =
	    list->accounting->count - next->accounting->count;

	return list;
}

/**
 * @brief Merge two sorted list according to the ordering func will return.
 *
 * @param left First list to merge.
 * @param right Second list to merge.
 * @param func A function pointer that can handle comparing the list data
 * nodes.
 * @return A new sorted list.
 *
 * This function compare the head of @p left and @p right, and choose the
 * smallest one to be head of the returned list. It will continue this process
 * for all entry of both list.
 *
 * Both left and right does not exist anymore after the merge.
 * If @p func is NULL, it will return NULL.
 *
 * Example:
 * @code
 * int
 * sort_cb(void *d1, void *d2)
 * {
 *   const char *txt = NULL;
 *    const char *txt2 = NULL;
 *
 *    if(!d1) return(1);
 *    if(!d2) return(-1);
 *
 *    return(strcmp((const char*)d1, (const char*)d2));
 * }
 * extern Eina_List *sorted1;
 * extern Eina_List *sorted2;
 *
 * list = eina_list_sorted_merge(sorted1, sorted2, sort_cb);
 * @endcode
 */
EAPI Eina_List *eina_list_sorted_merge(Eina_List * left, Eina_List * right,
				       Eina_Compare_Cb func)
{
	Eina_List *ret;
	Eina_List *current;

	EINA_SAFETY_ON_NULL_RETURN_VAL(func, NULL);

	if (!left)
		return right;

	if (!right)
		return left;

	if (func(left->data, right->data) < 0) {
		ret = left;
		current = left;
		left = left->next;
		ret->accounting->count += right->accounting->count;

		_eina_list_mempool_accounting_free(right->accounting);
	} else {
		ret = right;
		current = right;
		right = right->next;
		ret->accounting->count += left->accounting->count;

		_eina_list_mempool_accounting_free(left->accounting);
	}

	while (left && right) {
		if (func(left->data, right->data) < 0) {
			current->next = left;
			left->prev = current;
			left = left->next;
		} else {
			current->next = right;
			right->prev = current;
			right = right->next;
		}

		current = current->next;
		current->accounting = ret->accounting;
	}

	if (left) {
		current->next = left;
		left->prev = current;
		current->accounting = ret->accounting;
	}

	if (right) {
		current->next = right;
		right->prev = current;
		current->accounting = ret->accounting;
	}

	while (current->next) {
		current = current->next;
		current->accounting = ret->accounting;
	}

	ret->accounting->last = current;

	return ret;
}

/**
 * @brief Returns node nearest to data is in the sorted list.
 *
 * @param list The list to search for data, @b must be sorted.
 * @param func A function pointer that can handle comparing the list data nodes.
 * @param data reference value to search.
 * @param result_cmp if provided returns the result of
 * func(node->data, data) node being the last (returned) node. If node
 * was found (exact match), then it is 0. If returned node is smaller
 * than requested data, it is less than 0 and if it's bigger it's
 * greater than 0. It is the last value returned by func().
 * @return the nearest node, NULL if not found.
 *
 * This can be used to check if some value is inside the list and get
 * the nearest container node in this case. It should be used when list is
 * known to be sorted as it will do binary search for results.
 *
 * Example: imagine user gives a string, you check if it's in the list
 * before duplicating its contents, otherwise you want to insert it
 * sorted. In this case you get the result of this function and either
 * append or prepend the value.
 *
 * @note O(log2(n)) average/worst case performance, for 1,000,000
 * elements it will do a maximum of 20 comparisons. This is much
 * faster than the 1,000,000 comparisons made naively walking the list
 * from head to tail, so depending on the number of searches and
 * insertions, it may be worth to eina_list_sort() the list and do the
 * searches later. As lists do not have O(1) access time, walking to
 * the correct node can be costly, consider worst case to be almost
 * O(n) pointer dereference (list walk).
 *
 * @see eina_list_search_sorted_list()
 * @see eina_list_sort()
 * @see eina_list_sorted_merge()
 */
EAPI Eina_List *eina_list_search_sorted_near_list(const Eina_List * list,
						  Eina_Compare_Cb func,
						  const void *data,
						  int *result_cmp)
{
	const Eina_List *ct;
	unsigned int inf, sup, cur;
	int cmp;

	if (!list) {
		if (result_cmp)
			*result_cmp = 0;

		return NULL;
	}

	if (list->accounting->count == 1) {
		if (result_cmp)
			*result_cmp = func(list->data, data);

		return (Eina_List *) list;
	}

	/* list walk is expensive, do quick check: tail */
	ct = list->accounting->last;
	cmp = func(ct->data, data);
	if (cmp <= 0)
		goto end;

	/* list walk is expensive, do quick check: head */
	ct = list;
	cmp = func(ct->data, data);
	if (cmp >= 0)
		goto end;

	/* inclusive bounds */
	inf = 1;
	sup = list->accounting->count - 2;
	cur = 1;
	ct = list->next;

	/* no loop, just compare if comparison value is important to caller */
	if (inf > sup) {
		if (result_cmp)
			cmp = func(ct->data, data);

		goto end;
	}

	while (inf <= sup) {
		unsigned int tmp = cur;
		cur = inf + ((sup - inf) >> 1);
		if (tmp < cur)
			for (; tmp != cur; tmp++, ct = ct->next);
		else if (tmp > cur)
			for (; tmp != cur; tmp--, ct = ct->prev);

		cmp = func(ct->data, data);
		if (cmp == 0)
			break;
		else if (cmp < 0)
			inf = cur + 1;
		else if (cmp > 0) {
			if (cur > 0)
				sup = cur - 1;
			else
				break;
		} else
			break;
	}

      end:
	if (result_cmp)
		*result_cmp = cmp;

	return (Eina_List *) ct;
}

/**
 * @brief Returns node if data is in the sorted list.
 *
 * @param list The list to search for data, @b must be sorted.
 * @param func A function pointer that can handle comparing the list data nodes.
 * @param data reference value to search.
 * @return the node if func(node->data, data) == 0, NULL if not found.
 *
 * This can be used to check if some value is inside the list and get
 * the container node in this case. It should be used when list is
 * known to be sorted as it will do binary search for results.
 *
 * Example: imagine user gives a string, you check if it's in the list
 * before duplicating its contents.
 *
 * @note O(log2(n)) average/worst case performance, for 1,000,000
 * elements it will do a maximum of 20 comparisons. This is much
 * faster than the 1,000,000 comparisons made by
 * eina_list_search_unsorted_list(), so depending on the number of
 * searches and insertions, it may be worth to eina_list_sort() the
 * list and do the searches later. As said in
 * eina_list_search_sorted_near_list(), lists do not have O(1) access
 * time, so walking to the correct node can be costly, consider worst
 * case to be almost O(n) pointer dereference (list walk).
 *
 * @see eina_list_search_sorted()
 * @see eina_list_sort()
 * @see eina_list_sorted_merge()
 * @see eina_list_search_unsorted_list()
 * @see eina_list_search_sorted_near_list()
 */
EAPI Eina_List *eina_list_search_sorted_list(const Eina_List * list,
					     Eina_Compare_Cb func,
					     const void *data)
{
	Eina_List *lnear;
	int cmp;

	lnear = eina_list_search_sorted_near_list(list, func, data, &cmp);
	if (!lnear)
		return NULL;

	if (cmp == 0)
		return lnear;

	return NULL;
}


/**
 * @brief Returns node data if it is in the sorted list.
 *
 * @param list The list to search for data, @b must be sorted.
 * @param func A function pointer that can handle comparing the list data nodes.
 * @param data reference value to search.
 * @return the node value (@c node->data) if func(node->data, data) == 0,
 * NULL if not found.
 *
 * This can be used to check if some value is inside the list and get
 * the existing instance in this case. It should be used when list is
 * known to be sorted as it will do binary search for results.
 *
 * Example: imagine user gives a string, you check if it's in the list
 * before duplicating its contents.
 *
 * @note O(log2(n)) average/worst case performance, for 1,000,000
 * elements it will do a maximum of 20 comparisons. This is much
 * faster than the 1,000,000 comparisons made by
 * eina_list_search_unsorted(), so depending on the number of
 * searches and insertions, it may be worth to eina_list_sort() the
 * list and do the searches later. As said in
 * eina_list_search_sorted_near_list(), lists do not have O(1) access
 * time, so walking to the correct node can be costly, consider worst
 * case to be almost O(n) pointer dereference (list walk).
 *
 * @see eina_list_search_sorted_list()
 * @see eina_list_sort()
 * @see eina_list_sorted_merge()
 * @see eina_list_search_unsorted_list()
 */
EAPI void *eina_list_search_sorted(const Eina_List * list,
				   Eina_Compare_Cb func, const void *data)
{
	return
	    eina_list_data_get(eina_list_search_sorted_list
			       (list, func, data));
}

/**
 * @brief Returns node if data is in the unsorted list.
 *
 * @param list The list to search for data, may be unsorted.
 * @param func A function pointer that can handle comparing the list data nodes.
 * @param data reference value to search.
 * @return the node if func(node->data, data) == 0, NULL if not found.
 *
 * This can be used to check if some value is inside the list and get
 * the container node in this case.
 *
 * Example: imagine user gives a string, you check if it's in the list
 * before duplicating its contents.
 *
 * @note this is expensive and may walk the whole list, it's order-N,
 * that is for 1,000,000 elements list it may walk and compare
 * 1,000,000 nodes.
 *
 * @see eina_list_search_sorted_list()
 * @see eina_list_search_unsorted()
 */
EAPI Eina_List *eina_list_search_unsorted_list(const Eina_List * list,
					       Eina_Compare_Cb func,
					       const void *data)
{
	const Eina_List *l;
	void *d;

	EINA_LIST_FOREACH(list, l, d) {
		if (!func(d, data))
			return (Eina_List *) l;
	}
	return NULL;
}

/**
 * @brief Returns node data if it is in the unsorted list.
 *
 * @param list The list to search for data, may be unsorted.
 * @param func A function pointer that can handle comparing the list data nodes.
 * @param data reference value to search.
 * @return the node value (@c node->data) if func(node->data, data) == 0,
 * NULL if not found.
 *
 * This can be used to check if some value is inside the list and get
 * the existing instance in this case.
 *
 * Example: imagine user gives a string, you check if it's in the list
 * before duplicating its contents.
 *
 * @note this is expensive and may walk the whole list, it's order-N,
 * that is for 1,000,000 elements list it may walk and compare
 * 1,000,000 nodes.
 *
 * @see eina_list_search_sorted()
 * @see eina_list_search_unsorted_list()
 */
EAPI void *eina_list_search_unsorted(const Eina_List * list,
				     Eina_Compare_Cb func,
				     const void *data)
{
	return
	    eina_list_data_get(eina_list_search_unsorted_list
			       (list, func, data));
}


/**
 * @brief Returned a new iterator associated to a list.
 *
 * @param list The list.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to @p
 * list. If @p list is @c NULL or the count member of @p list is less
 * or equal than 0, this function still returns a valid iterator that
 * will always return false on eina_iterator_next(), thus keeping API
 * sane.
 *
 * If the memory can not be allocated, NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, a valid iterator is
 * returned.
 *
 * @warning if the list structure changes then the iterator becomes
 *    invalid! That is, if you add or remove nodes this iterator
 *    behavior is undefined and your program may crash!
 */
EAPI Eina_Iterator *eina_list_iterator_new(const Eina_List * list)
{
	Eina_Iterator_List *it;

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_List));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(it, EINA_MAGIC_LIST_ITERATOR);
	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

	it->head = list;
	it->current = list;

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(eina_list_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(eina_list_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(eina_list_iterator_free);

	return &it->iterator;
}

/**
 * @brief Returned a new reversed iterator associated to a list.
 *
 * @param list The list.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to @p
 * list. If @p list is @c NULL or the count member of @p list is less
 * or equal than 0, this function still returns a valid iterator that
 * will always return false on eina_iterator_next(), thus keeping API
 * sane.
 *
 * Unlike eina_list_iterator_new(), this will walk the list backwards.
 *
 * If the memory can not be allocated, NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, a valid iterator is
 * returned.
 *
 * @warning if the list structure changes then the iterator becomes
 *    invalid! That is, if you add or remove nodes this iterator
 *    behavior is undefined and your program may crash!
 */
EAPI Eina_Iterator *eina_list_iterator_reversed_new(const Eina_List * list)
{
	Eina_Iterator_List *it;

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_List));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(it, EINA_MAGIC_LIST_ITERATOR);
	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

	it->head = eina_list_last(list);
	it->current = it->head;

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(eina_list_iterator_prev);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(eina_list_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(eina_list_iterator_free);

	return &it->iterator;
}

/**
 * @brief Returned a new accessor associated to a list.
 *
 * @param list The list.
 * @return A new accessor.
 *
 * This function returns a newly allocated accessor associated to
 * @p list. If @p list is @c NULL or the count member of @p list is
 * less or equal than 0, this function returns NULL. If the memory can
 * not be allocated, NULL is returned and #EINA_ERROR_OUT_OF_MEMORY is
 * set. Otherwise, a valid accessor is returned.
 */
EAPI Eina_Accessor *eina_list_accessor_new(const Eina_List * list)
{
	Eina_Accessor_List *ac;

	eina_error_set(0);
	ac = calloc(1, sizeof(Eina_Accessor_List));
	if (!ac) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	EINA_MAGIC_SET(ac, EINA_MAGIC_LIST_ACCESSOR);
	EINA_MAGIC_SET(&ac->accessor, EINA_MAGIC_ACCESSOR);

	ac->head = list;
	ac->current = list;
	ac->index = 0;

	ac->accessor.version = EINA_ACCESSOR_VERSION;
	ac->accessor.get_at =
	    FUNC_ACCESSOR_GET_AT(eina_list_accessor_get_at);
	ac->accessor.get_container =
	    FUNC_ACCESSOR_GET_CONTAINER(eina_list_accessor_get_container);
	ac->accessor.free = FUNC_ACCESSOR_FREE(eina_list_accessor_free);

	return &ac->accessor;
}

/**
 * @}
 */
