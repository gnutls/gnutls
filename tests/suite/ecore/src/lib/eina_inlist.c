/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Vincent Torri
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
#include <assert.h>

#include "eina_config.h"
#include "eina_private.h"
#include "eina_error.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_inlist.h"

/* FIXME: TODO please, refactor this :) */

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

typedef struct _Eina_Iterator_Inlist Eina_Iterator_Inlist;
typedef struct _Eina_Accessor_Inlist Eina_Accessor_Inlist;

struct _Eina_Iterator_Inlist {
	Eina_Iterator iterator;
	const Eina_Inlist *head;
	const Eina_Inlist *current;
};

struct _Eina_Accessor_Inlist {
	Eina_Accessor accessor;

	const Eina_Inlist *head;
	const Eina_Inlist *current;

	unsigned int index;
};

static Eina_Bool
eina_inlist_iterator_next(Eina_Iterator_Inlist * it, void **data)
{
	if (!it->current)
		return EINA_FALSE;

	if (data)
		*data = (void *) it->current;

	it->current = it->current->next;

	return EINA_TRUE;
}

static Eina_Inlist *eina_inlist_iterator_get_container(Eina_Iterator_Inlist
						       * it)
{
	return (Eina_Inlist *) it->head;
}

static void eina_inlist_iterator_free(Eina_Iterator_Inlist * it)
{
	free(it);
}

static Eina_Bool
eina_inlist_accessor_get_at(Eina_Accessor_Inlist * it,
			    unsigned int idx, void **data)
{
	const Eina_Inlist *over;
	unsigned int middle;
	unsigned int i;

	if (it->index == idx)
		over = it->current;
	else if (idx > it->index)
		/* Looking after current. */
		for (i = it->index, over = it->current;
		     i < idx && over; ++i, over = over->next);
	else {
		middle = it->index >> 1;

		if (idx > middle)
			/* Looking backward from current. */
			for (i = it->index, over = it->current;
			     i > idx && over; --i, over = over->prev);
		else
			/* Looking from the start. */
			for (i = 0, over = it->head;
			     i < idx && over; ++i, over = over->next);
	}

	if (!over)
		return EINA_FALSE;

	it->current = over;
	it->index = idx;

	if (data)
		*data = (void *) over;

	return EINA_TRUE;
}

static Eina_Inlist *eina_inlist_accessor_get_container(Eina_Accessor_Inlist
						       * it)
{
	return (Eina_Inlist *) it->head;
}

static void eina_inlist_accessor_free(Eina_Accessor_Inlist * it)
{
	free(it);
}

/**
 * @endcond
 */


/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Inline_List_Group Inline List
 *
 * @brief These functions provide inline list management.
 *
 * Inline lists mean its nodes pointers are part of same memory as
 * data. This has the benefit of framenting memory less and avoiding
 * @c node->data indirection, but has the drawback of elements only
 * being able to be part of one single inlist at same time. But it is
 * possible to have inlist nodes to be part of regular lists created
 * with eina_list_append() or eina_list_prepend().
 *
 * Inline lists have its purposes, but if you don't know them go with
 * regular lists instead.
 *
 * @code
 * #include <Eina.h>
 * #include <stdio.h>
 *
 * int
 * main(void)
 * {
 *    struct my_struct {
 *       EINA_INLIST;
 *       int a, b;
 *    } *d, *cur;
 *    Eina_Inlist *list, *itr;
 *
 *    eina_init();
 *
 *    d = malloc(sizeof(*d));
 *    d->a = 1;
 *    d->b = 10;
 *    list = eina_inlist_append(NULL, EINA_INLIST_GET(d));
 *
 *    d = malloc(sizeof(*d));
 *    d->a = 2;
 *    d->b = 20;
 *    list = eina_inlist_append(list, EINA_INLIST_GET(d));
 *
 *    d = malloc(sizeof(*d));
 *    d->a = 3;
 *    d->b = 30;
 *    list = eina_inlist_prepend(list, EINA_INLIST_GET(d));
 *
 *    printf("list=%p\n", list);
 *    EINA_INLIST_FOREACH(list, cur)
 *      printf("\ta=%d, b=%d\n", cur->a, cur->b);
 *
 *    list = eina_inlist_remove(list, EINA_INLIST_GET(d));
 *    free(d);
 *    printf("list=%p\n", list);
 *    for (itr = list; itr != NULL; itr = itr->next)
 *      {
 *  cur = EINA_INLIST_CONTAINER_GET(itr, struct my_struct);
 *  printf("\ta=%d, b=%d\n", cur->a, cur->b);
 *      }
 *
 *    while (list)
 *      {
 *  Eina_Inlist *aux = list;
 *  list = eina_inlist_remove(list, list);
 *  free(aux);
 *      }
 *
 *    eina_shutdown();
 *
 *    return 0;
 * }
 * @endcode
 *
 * @{
 */

/**
 * Add a new node to end of list.
 *
 * @note this code is meant to be fast, appends are O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a new_l is considered to be in no list. If it was in another
 *       list before, please eina_inlist_remove() it before adding. No
 *       check of @a new_l prev and next pointers is done, so it' safe
 *       to have them uninitialized.
 *
 * @param list existing list head or NULL to create a new list.
 * @param new_l new list node, must not be NULL.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_append(Eina_Inlist * list,
				     Eina_Inlist * new_l)
{
	Eina_Inlist *l;

	EINA_SAFETY_ON_NULL_RETURN_VAL(new_l, list);

	new_l->next = NULL;
	if (!list) {
		new_l->prev = NULL;
		new_l->last = new_l;
		return new_l;
	}

	if (list->last)
		l = list->last;
	else
		for (l = list; (l) && (l->next); l = l->next);

	l->next = new_l;
	new_l->prev = l;
	list->last = new_l;
	return list;
}

/**
 * Add a new node to beginning of list.
 *
 * @note this code is meant to be fast, prepends are O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a new_l is considered to be in no list. If it was in another
 *       list before, please eina_inlist_remove() it before adding. No
 *       check of @a new_l prev and next pointers is done, so it' safe
 *       to have them uninitialized.
 *
 * @param list existing list head or NULL to create a new list.
 * @param new_l new list node, must not be NULL.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_prepend(Eina_Inlist * list,
				      Eina_Inlist * new_l)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(new_l, list);

	new_l->prev = NULL;
	if (!list) {
		new_l->next = NULL;
		new_l->last = new_l;
		return new_l;
	}

	new_l->next = list;
	list->prev = new_l;
	new_l->last = list->last;
	list->last = NULL;
	return new_l;
}

/**
 * Add a new node after the given relative item in list.
 *
 * @note this code is meant to be fast, appends are O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a new_l is considered to be in no list. If it was in another
 *       list before, please eina_inlist_remove() it before adding. No
 *       check of @a new_l prev and next pointers is done, so it' safe
 *       to have them uninitialized.
 *
 * @note @a relative is considered to be inside @a list, no checks are
 *       done to confirm that and giving nodes from different lists
 *       will lead to problems. Giving NULL @a relative is the same as
 *       eina_list_append().
 *
 * @param list existing list head or NULL to create a new list.
 * @param new_l new list node, must not be NULL.
 * @param relative reference node, @a new_l will be added after it.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_append_relative(Eina_Inlist * list,
					      Eina_Inlist * new_l,
					      Eina_Inlist * relative)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(new_l, list);

	if (relative) {
		if (relative->next) {
			new_l->next = relative->next;
			relative->next->prev = new_l;
		} else
			new_l->next = NULL;

		relative->next = new_l;
		new_l->prev = relative;
		if (!new_l->next)
			list->last = new_l;

		return list;
	}

	return eina_inlist_append(list, new_l);
}

/**
 * Add a new node before the given relative item in list.
 *
 * @note this code is meant to be fast, prepends are O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a new_l is considered to be in no list. If it was in another
 *       list before, please eina_inlist_remove() it before adding. No
 *       check of @a new_l prev and next pointers is done, so it' safe
 *       to have them uninitialized.
 *
 * @note @a relative is considered to be inside @a list, no checks are
 *       done to confirm that and giving nodes from different lists
 *       will lead to problems. Giving NULL @a relative is the same as
 *       eina_list_prepend().
 *
 * @param list existing list head or NULL to create a new list.
 * @param new_l new list node, must not be NULL.
 * @param relative reference node, @a new_l will be added before it.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_prepend_relative(Eina_Inlist * list,
					       Eina_Inlist * new_l,
					       Eina_Inlist * relative)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(new_l, list);

	if (relative) {
		new_l->prev = relative->prev;
		new_l->next = relative;
		relative->prev = new_l;
		if (new_l->prev) {
			new_l->prev->next = new_l;
			/* new_l->next could not be NULL, as it was set to 'relative' */
			assert(new_l->next);
			return list;
		} else {
			/* new_l->next could not be NULL, as it was set to 'relative' */
			assert(new_l->next);

			new_l->last = list->last;
			list->last = NULL;
			return new_l;
		}
	}

	return eina_inlist_prepend(list, new_l);
}

/**
 * Remove node from list.
 *
 * @note this code is meant to be fast, removals are O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a item is considered to be inside @a list, no checks are
 *       done to confirm that and giving nodes from different lists
 *       will lead to problems, specially if @a item is the head since
 *       it will be different from @a list and the wrong new head will
 *       be returned.
 *
 * @param list existing list head, must not be NULL.
 * @param item existing list node, must not be NULL.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_remove(Eina_Inlist * list,
				     Eina_Inlist * item)
{
	Eina_Inlist *return_l;

	/* checkme */
	EINA_SAFETY_ON_NULL_RETURN_VAL(list, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(item, list);
	EINA_SAFETY_ON_TRUE_RETURN_VAL
	    ((item != list) && (!item->prev) && (!item->next), list);

	if (item->next)
		item->next->prev = item->prev;

	if (item->prev) {
		item->prev->next = item->next;
		return_l = list;
	} else {
		return_l = item->next;
		if (return_l)
			return_l->last = list->last;
	}

	if (item == list->last)
		list->last = item->prev;

	item->next = NULL;
	item->prev = NULL;
	return return_l;
}

/**
 * Move existing node to beginning of list.
 *
 * @note this code is meant to be fast, promotion is O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a item is considered to be inside @a list, no checks are
 *       done to confirm that and giving nodes from different lists
 *       will lead to problems.
 *
 * @param list existing list head or NULL to create a new list.
 * @param item list node to move to beginning (head), must not be NULL.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_promote(Eina_Inlist * list,
				      Eina_Inlist * item)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(list, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(item, list);

	if (item == list)
		return list;

	if (item->next)
		item->next->prev = item->prev;

	item->prev->next = item->next;

	if (list->last == item)
		list->last = item->prev;

	item->next = list;
	item->prev = NULL;
	item->last = list->last;

	list->prev = item;
	list->last = NULL;

	return item;
}

/**
 * Move existing node to end of list.
 *
 * @note this code is meant to be fast, demoting is O(1) and do not
 *       walk @a list anyhow.
 *
 * @note @a item is considered to be inside @a list, no checks are
 *       done to confirm that and giving nodes from different lists
 *       will lead to problems.
 *
 * @param list existing list head or NULL to create a new list.
 * @param item list node to move to end (tail), must not be NULL.
 *
 * @return the new list head. Use it and not given @a list anymore.
 */
EAPI Eina_Inlist *eina_inlist_demote(Eina_Inlist * list,
				     Eina_Inlist * item)
{
	Eina_Inlist *l;

	EINA_SAFETY_ON_NULL_RETURN_VAL(list, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(item, list);

	if (list->last == item)
		return list;

	if (!list->last) {
		for (l = list; l->next; l = l->next);
		list->last = l;
	}

	l = list;
	if (item->prev)
		item->prev->next = item->next;
	else
		l = item->next;

	item->next->prev = item->prev;

	list->last->next = item;
	item->prev = list->last;
	item->next = NULL;

	l->last = item;
	return l;
}

/**
 * Find given node in list, returns itself if found, NULL if not.
 *
 * @warning this is an expensive call and have O(n) cost, possibly
 *    walking the whole list.
 *
 * @param list existing list to search @a item in, must not be NULL.
 * @param item what to search for, must not be NULL.
 *
 * @return @a item if found, NULL if not.
 */
EAPI Eina_Inlist *eina_inlist_find(Eina_Inlist * list, Eina_Inlist * item)
{
	Eina_Inlist *l;

	for (l = list; l; l = l->next) {
		if (l == item)
			return item;
	}
	return NULL;
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
 * @warning This is an order-N operation and so the time will depend
 *    on the number of elements on the list, that is, it might become
 *    slow for big lists!
 */
EAPI unsigned int eina_inlist_count(const Eina_Inlist * list)
{
	const Eina_Inlist *l;
	unsigned int i = 0;

	for (l = list; l; l = l->next)
		i++;

	return i;
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
EAPI Eina_Iterator *eina_inlist_iterator_new(const Eina_Inlist * list)
{
	Eina_Iterator_Inlist *it;

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_Inlist));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	it->head = list;
	it->current = list;

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(eina_inlist_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER
	    (eina_inlist_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(eina_inlist_iterator_free);

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

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
EAPI Eina_Accessor *eina_inlist_accessor_new(const Eina_Inlist * list)
{
	Eina_Accessor_Inlist *ac;

	eina_error_set(0);
	ac = calloc(1, sizeof(Eina_Accessor_Inlist));
	if (!ac) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	ac->head = list;
	ac->current = list;
	ac->index = 0;

	ac->accessor.version = EINA_ACCESSOR_VERSION;
	ac->accessor.get_at =
	    FUNC_ACCESSOR_GET_AT(eina_inlist_accessor_get_at);
	ac->accessor.get_container =
	    FUNC_ACCESSOR_GET_CONTAINER
	    (eina_inlist_accessor_get_container);
	ac->accessor.free = FUNC_ACCESSOR_FREE(eina_inlist_accessor_free);

	EINA_MAGIC_SET(&ac->accessor, EINA_MAGIC_ACCESSOR);

	return &ac->accessor;
}

/**
 * @}
 */
