/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Cedric BAIL, Carsten Haitzler
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

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_magic.h"
#include "eina_inlist.h"
#include "eina_mempool.h"
#include "eina_list.h"
#include "eina_trash.h"
#include "eina_log.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_rectangle.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#define EINA_RECTANGLE_POOL_MAGIC 0x1578FCB0
#define EINA_RECTANGLE_ALLOC_MAGIC 0x1578FCB1

#define BUCKET_THRESHOLD 110

typedef struct _Eina_Rectangle_Alloc Eina_Rectangle_Alloc;

struct _Eina_Rectangle_Pool {
	Eina_Inlist *head;
	Eina_List *empty;
	void *data;

	Eina_Trash *bucket;
	unsigned int bucket_count;

	unsigned int references;
	int w;
	int h;

	Eina_Bool sorted;
 EINA_MAGIC};

struct _Eina_Rectangle_Alloc {
	EINA_INLIST;
	Eina_Rectangle_Pool *pool;
 EINA_MAGIC};

#define EINA_MAGIC_CHECK_RECTANGLE_POOL(d)                     \
   do {                                                         \
        if (!EINA_MAGIC_CHECK((d), EINA_RECTANGLE_POOL_MAGIC)) {    \
             EINA_MAGIC_FAIL((d), EINA_RECTANGLE_POOL_MAGIC); }        \
     } while (0)

#define EINA_MAGIC_CHECK_RECTANGLE_ALLOC(d)                    \
   do {                                                         \
        if (!EINA_MAGIC_CHECK((d), EINA_RECTANGLE_ALLOC_MAGIC)) {   \
             EINA_MAGIC_FAIL((d), EINA_RECTANGLE_ALLOC_MAGIC); }       \
     } while (0)

static Eina_Mempool *_eina_rectangle_alloc_mp = NULL;
static Eina_Mempool *_eina_rectangle_mp = NULL;

static Eina_Trash *_eina_rectangles = NULL;
static unsigned int _eina_rectangles_count = 0;
static int _eina_rectangle_log_dom = -1;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_rectangle_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_rectangle_log_dom, __VA_ARGS__)

static int
_eina_rectangle_cmp(const Eina_Rectangle * r1, const Eina_Rectangle * r2)
{
	return (r2->w * r2->h) - (r1->w * r1->h);
}

static Eina_List *_eina_rectangle_merge_list(Eina_List * empty,
					     Eina_Rectangle * r)
{
	Eina_Rectangle *match;
	Eina_List *l;
	int xw;
	int yh;

	if (r->w == 0 || r->h == 0) {
		eina_rectangle_free(r);
		return empty;
	}

      start_again:
	xw = r->x + r->w;
	yh = r->y + r->h;

	EINA_LIST_FOREACH(empty, l, match) {
		if (match->x == r->x && match->w == r->w
		    && (match->y == yh || r->y == match->y + match->h)) {
			if (match->y > r->y)
				match->y = r->y;

			match->h += r->h;

			eina_rectangle_free(r);

			empty = eina_list_remove_list(empty, l);

			r = match;

			goto start_again;
		} else if (match->y == r->y && match->h == r->h
			   && (match->x == xw
			       || r->x == match->x + match->w)) {
			if (match->x > r->x)
				match->x = r->x;

			match->w += r->w;

			eina_rectangle_free(r);

			empty = eina_list_remove_list(empty, l);

			r = match;

			goto start_again;
		}
	}

	return eina_list_append(empty, r);
}

static Eina_List *_eina_rectangle_empty_space_find(Eina_List * empty,
						   int w, int h, int *x,
						   int *y)
{
	Eina_Rectangle *r;
	Eina_List *l;

	EINA_LIST_FOREACH(empty, l, r) {
		if (r->w >= w && r->h >= h) {
			/* Remove l from empty */
			empty = eina_list_remove_list(empty, l);
			/* Remember x and y */
			*x = r->x;
			*y = r->y;
			/* Split r in 2 rectangle if needed (only the empty one) and insert them */
			if (r->w == w) {
				r->y += h;
				r->h -= h;
			} else if (r->h == h) {
				r->x += w;
				r->w -= w;
			} else {
				int rx1, ry1, rw1, rh1;
				int x2, y2, w2, h2;

				rx1 = r->x + w;
				ry1 = r->y;
				rw1 = r->w - w;
				/* h1 could be h or r->h */
				x2 = r->x;
				y2 = r->y + h;
				/* w2 could be w or r->w */
				h2 = r->h - h;

				if (rw1 * r->h > h2 * r->w) {
					rh1 = r->h;
					w2 = w;
				} else {
					rh1 = h;
					w2 = r->w;
				}

				EINA_RECTANGLE_SET(r, rx1, ry1, rw1, rh1);
				empty =
				    _eina_rectangle_merge_list(empty, r);

				r = eina_rectangle_new(x2, y2, w2, h2);
			}

			if (r) {
				empty = _eina_rectangle_merge_list(empty, r);	/* Return empty */

			}

			return empty;
		}
	}

	*x = -1;
	*y = -1;
	return empty;
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

Eina_Bool eina_rectangle_init(void)
{
	const char *choice, *tmp;

	_eina_rectangle_log_dom =
	    eina_log_domain_register("eina_rectangle",
				     EINA_LOG_COLOR_DEFAULT);
	if (_eina_rectangle_log_dom < 0) {
		EINA_LOG_ERR
		    ("Could not register log domain: eina_rectangle");
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

	_eina_rectangle_alloc_mp = eina_mempool_add
	    (choice, "rectangle-alloc", NULL,
	     sizeof(Eina_Rectangle_Alloc) + sizeof(Eina_Rectangle), 1024);
	if (!_eina_rectangle_alloc_mp) {
		ERR("Mempool for rectangle cannot be allocated in rectangle init.");
		goto init_error;
	}

	_eina_rectangle_mp = eina_mempool_add
	    (choice, "rectangle", NULL, sizeof(Eina_Rectangle), 256);
	if (!_eina_rectangle_mp) {
		ERR("Mempool for rectangle cannot be allocated in rectangle init.");
		goto init_error;
	}

	return EINA_TRUE;

      init_error:
	eina_log_domain_unregister(_eina_rectangle_log_dom);
	_eina_rectangle_log_dom = -1;

	return EINA_FALSE;
}

Eina_Bool eina_rectangle_shutdown(void)
{
	Eina_Rectangle *del;

	while ((del = eina_trash_pop(&_eina_rectangles)))
		eina_mempool_free(_eina_rectangle_mp, del);
	_eina_rectangles_count = 0;

	eina_mempool_del(_eina_rectangle_alloc_mp);
	eina_mempool_del(_eina_rectangle_mp);

	eina_log_domain_unregister(_eina_rectangle_log_dom);
	_eina_rectangle_log_dom = -1;

	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Rectangle_Group Rectangle
 *
 * @brief These functions provide rectangle management.
 *
 * @{
 */

/**
 * @brief Create a new rectangle.
 *
 * @param x The X coordinate of the top left corner of the rectangle.
 * @param y The Y coordinate of the top left corner of the rectangle.
 * @param w The width of the rectangle.
 * @param h The height of the rectangle.
 * @return The new rectangle on success, @ NULL otherwise.
 *
 * This function creates a rectangle which top left corner has the
 * coordinates (@p x, @p y), with height @p w and height @p h and adds
 * it to the rectangles pool. No check is done on @p w and @p h. This
 * function returns a new rectangle on success, @c NULL otherwhise.
 */
EAPI Eina_Rectangle *eina_rectangle_new(int x, int y, int w, int h)
{
	Eina_Rectangle *rect;

	if (_eina_rectangles) {
		rect = eina_trash_pop(&_eina_rectangles);
		_eina_rectangles_count--;
	} else
		rect =
		    eina_mempool_malloc(_eina_rectangle_mp,
					sizeof(Eina_Rectangle));

	if (!rect)
		return NULL;

	EINA_RECTANGLE_SET(rect, x, y, w, h);

	return rect;
}

/**
 * @brief Free the given rectangle.
 *
 * @param rect The rectangle to free.
 *
 * This function removes @p rect from the rectangles pool.
 */
EAPI void eina_rectangle_free(Eina_Rectangle * rect)
{
	EINA_SAFETY_ON_NULL_RETURN(rect);

	if (_eina_rectangles_count > BUCKET_THRESHOLD)
		eina_mempool_free(_eina_rectangle_mp, rect);
	else {
		eina_trash_push(&_eina_rectangles, rect);
		_eina_rectangles_count++;
	}
}

/**
 * @brief Add a rectangle in a new pool.
 *
 * @param w The width of the rectangle.
 * @param h The height of the rectangle.
 * @return A newly allocated pool on success, @c NULL otherwise.
 *
 * This function adds the rectangle of size (@p width, @p height) to a
 * new pool. If the pool can not be created, @c NULL is
 * returned. Otherwise the newly allocated pool is returned.
 */
EAPI Eina_Rectangle_Pool *eina_rectangle_pool_new(int w, int h)
{
	Eina_Rectangle_Pool *new;

	new = malloc(sizeof(Eina_Rectangle_Pool));
	if (!new)
		return NULL;

	new->head = NULL;
	new->empty =
	    eina_list_append(NULL, eina_rectangle_new(0, 0, w, h));
	new->references = 0;
	new->sorted = EINA_FALSE;
	new->w = w;
	new->h = h;
	new->bucket = NULL;
	new->bucket_count = 0;

	EINA_MAGIC_SET(new, EINA_RECTANGLE_POOL_MAGIC);
	DBG("pool=%p, size=(%d, %d)", new, w, h);

	return new;
}

/**
 * @brief Free the given pool.
 *
 * @param pool The pool to free.
 *
 * This function frees the allocated data of @p pool. If @p pool is
 * @c NULL, ths function returned immediately.
 */
EAPI void eina_rectangle_pool_free(Eina_Rectangle_Pool * pool)
{
	Eina_Rectangle_Alloc *del;

	EINA_SAFETY_ON_NULL_RETURN(pool);
	DBG("pool=%p, size=(%d, %d), references=%u",
	    pool, pool->w, pool->h, pool->references);
	while (pool->head) {
		del = (Eina_Rectangle_Alloc *) pool->head;

		pool->head = (EINA_INLIST_GET(del))->next;

		EINA_MAGIC_SET(del, EINA_MAGIC_NONE);
		eina_mempool_free(_eina_rectangle_alloc_mp, del);
	}

	while (pool->bucket) {
		del = eina_trash_pop(&pool->bucket);
		eina_mempool_free(_eina_rectangle_alloc_mp, del);
	}

	MAGIC_FREE(pool);
}

/**
 * @brief Return the number of rectangles in the given pool.
 *
 * @param pool The pool.
 * @return The number of rectangles in the pool.
 *
 * This function returns the number of rectangles in @p pool.
 */
EAPI int eina_rectangle_pool_count(Eina_Rectangle_Pool * pool)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(pool, 0);
	return pool->references;
}

/**
 * @brief Request a rectangle of given size in the given pool.
 *
 * @param pool The pool.
 * @param w The width of the rectangle to request.
 * @param h The height of the rectangle to request.
 * @return The requested rectangle on success, @c NULL otherwise.
 *
 * This function retrieve from @p pool the rectangle of width @p w and
 * height @p h. If @p pool is @c NULL, or @p w or @p h are non-positive,
 * the function returns @c NULL. If @p w or @p h are greater than the
 * pool size, the function returns @c NULL. On success, the function
 * returns the rectangle which matches the size (@p w, @p h).
 * Otherwise it returns @c NULL.
 */
EAPI Eina_Rectangle *eina_rectangle_pool_request(Eina_Rectangle_Pool *
						 pool, int w, int h)
{
	Eina_Rectangle_Alloc *new;
	Eina_Rectangle *rect;
	int x;
	int y;

	EINA_SAFETY_ON_NULL_RETURN_VAL(pool, NULL);

	DBG("pool=%p, size=(%d, %d), references=%u",
	    pool, pool->w, pool->h, pool->references);

	if (w <= 0 || h <= 0)
		return NULL;

	if (w > pool->w || h > pool->h)
		return NULL;

	/* Sort empty if dirty */
	if (pool->sorted) {
		pool->empty =
		    eina_list_sort(pool->empty, 0,
				   EINA_COMPARE_CB(_eina_rectangle_cmp));
		pool->sorted = EINA_TRUE;
	}

	pool->empty =
	    _eina_rectangle_empty_space_find(pool->empty, w, h, &x, &y);
	if (x == -1)
		return NULL;

	pool->sorted = EINA_FALSE;

	if (pool->bucket_count > 0) {
		new = eina_trash_pop(&pool->bucket);
		pool->bucket_count--;
	} else
		new = eina_mempool_malloc(_eina_rectangle_alloc_mp,
					  sizeof(Eina_Rectangle_Alloc) +
					  sizeof(Eina_Rectangle));

	if (!new)
		return NULL;

	rect = (Eina_Rectangle *) (new + 1);
	eina_rectangle_coords_from(rect, x, y, w, h);

	pool->head = eina_inlist_prepend(pool->head, EINA_INLIST_GET(new));
	pool->references++;

	new->pool = pool;

	EINA_MAGIC_SET(new, EINA_RECTANGLE_ALLOC_MAGIC);
	DBG("rect=%p pool=%p, size=(%d, %d), references=%u",
	    rect, pool, pool->w, pool->h, pool->references);

	return rect;
}

/**
 * @brief Remove the given rectangle from the pool.
 *
 * @param rect The rectangle to remove from the pool.
 *
 * This function removes @p rect from the pool. If @p rect is
 * @c NULL, the function returns immediately. Otherwise it remoes @p
 * rect from the pool.
 */
EAPI void eina_rectangle_pool_release(Eina_Rectangle * rect)
{
	Eina_Rectangle_Alloc *era = ((Eina_Rectangle_Alloc *) rect) - 1;
	Eina_Rectangle *r;

	EINA_SAFETY_ON_NULL_RETURN(rect);

	EINA_MAGIC_CHECK_RECTANGLE_ALLOC(era);
	EINA_MAGIC_CHECK_RECTANGLE_POOL(era->pool);

	DBG("rect=%p pool=%p, size=(%d, %d), references=%u",
	    rect, era->pool, era->pool->w, era->pool->h,
	    era->pool->references);

	era->pool->references--;
	era->pool->head =
	    eina_inlist_remove(era->pool->head, EINA_INLIST_GET(era));

	r = eina_rectangle_new(rect->x, rect->y, rect->w, rect->h);
	if (r) {
		era->pool->empty =
		    _eina_rectangle_merge_list(era->pool->empty, r);
		era->pool->sorted = EINA_FALSE;
	}

	if (era->pool->bucket_count < BUCKET_THRESHOLD) {
		Eina_Rectangle_Pool *pool;

		pool = era->pool;

		pool->bucket_count++;
		eina_trash_push(&pool->bucket, era);
	} else {
		EINA_MAGIC_SET(era, EINA_MAGIC_NONE);
		eina_mempool_free(_eina_rectangle_alloc_mp, era);
	}
}

/**
 * @brief Return the pool of the given rectangle.
 *
 * @param rect The rectangle.
 * @return The pool of the given rectangle.
 *
 * This function returns the pool in which @p rect is. If  @p rect is
 * @c NULL, @c NULL is returned.
 */
EAPI Eina_Rectangle_Pool *eina_rectangle_pool_get(Eina_Rectangle * rect)
{
	Eina_Rectangle_Alloc *era = ((Eina_Rectangle_Alloc *) rect) - 1;

	EINA_SAFETY_ON_NULL_RETURN_VAL(rect, NULL);

	EINA_MAGIC_CHECK_RECTANGLE_ALLOC(era);
	EINA_MAGIC_CHECK_RECTANGLE_POOL(era->pool);

	return era->pool;
}

/**
 * @brief Set the data to the given pool.
 *
 * @param pool The pool.
 * @param data The data to set.
 *
 * This function sets @p data to @p pool. If @p pool is @c NULL, this
 * function does nothing.
 */
EAPI void
eina_rectangle_pool_data_set(Eina_Rectangle_Pool * pool, const void *data)
{
	EINA_MAGIC_CHECK_RECTANGLE_POOL(pool);
	EINA_SAFETY_ON_NULL_RETURN(pool);

	DBG("data=%p pool=%p, size=(%d, %d), references=%u",
	    data, pool, pool->w, pool->h, pool->references);

	pool->data = (void *) data;
}

/**
 * @brief Get the data from the given pool.
 *
 * @param pool The pool.
 * @return The returned data.
 *
 * This function gets the data from @p pool set by
 * eina_rectangle_pool_data_set(). If @p pool is @c NULL, this
 * function returns @c NULL.
 */
EAPI void *eina_rectangle_pool_data_get(Eina_Rectangle_Pool * pool)
{
	EINA_MAGIC_CHECK_RECTANGLE_POOL(pool);
	EINA_SAFETY_ON_NULL_RETURN_VAL(pool, NULL);

	return pool->data;
}

/**
 * @brief Return the width and height of the given pool.
 *
 * @param pool The pool.
 * @param w The returned width.
 * @param h The returned height.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function returns the width and height of @p pool and store
 * them in respectively @p w and @p h if they are not @c NULL. If
 * @p pool is @c NULL, #EINA_FALSE is returned. Otherwise #EINA_TRUE is
 * returned.
 */
EAPI Eina_Bool
eina_rectangle_pool_geometry_get(Eina_Rectangle_Pool * pool, int *w,
				 int *h)
{
	if (!pool)
		return EINA_FALSE;

	EINA_MAGIC_CHECK_RECTANGLE_POOL(pool);
	EINA_SAFETY_ON_NULL_RETURN_VAL(pool, EINA_FALSE);

	if (w)
		*w = pool->w;

	if (h)
		*h = pool->h;

	return EINA_TRUE;
}

/**
 * @}
 */
