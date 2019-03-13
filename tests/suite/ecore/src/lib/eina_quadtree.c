/* EINA - EFL data type library
 * Copyright (C) 2010 Cedric Bail
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
 * @page tutorial_quadtree_page QuadTree Tutorial
 *
 * to be written...
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>

#include "eina_quadtree.h"
#include "eina_magic.h"
#include "eina_mempool.h"
#include "eina_list.h"
#include "eina_inlist.h"
#include "eina_trash.h"
#include "eina_log.h"
#include "eina_rectangle.h"

#include "eina_private.h"

typedef struct _Eina_QuadTree_Root Eina_QuadTree_Root;

static const char EINA_MAGIC_QUADTREE_STR[] = "Eina QuadTree";
static const char EINA_MAGIC_QUADTREE_ROOT_STR[] = "Eina QuadTree Root";
static const char EINA_MAGIC_QUADTREE_ITEM_STR[] = "Eina QuadTree Item";

#define EINA_MAGIC_CHECK_QUADTREE(d, ...)               \
   do {                                                  \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_QUADTREE))     \
          {                                                \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_QUADTREE);      \
             return __VA_ARGS__;                           \
          }                                                \
     } while(0);

#define EINA_MAGIC_CHECK_QUADTREE_ROOT(d, ...)                  \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_QUADTREE_ROOT))        \
          {                                                        \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_QUADTREE_ROOT);         \
             return __VA_ARGS__;                                   \
          }                                                        \
     } while(0);

#define EINA_MAGIC_CHECK_QUADTREE_ITEM(d, ...)                  \
   do {                                                          \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_QUADTREE_ITEM))        \
          {                                                        \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_QUADTREE_ITEM);         \
             return __VA_ARGS__;                                   \
          }                                                        \
     } while(0);

struct _Eina_QuadTree {
	EINA_MAGIC;

	Eina_QuadTree_Root *root;

	Eina_List *hidden;

	size_t root_count;
	size_t items_count;

	Eina_Trash *items_trash;
	Eina_Trash *root_trash;

	Eina_Inlist *change;
	Eina_Inlist *cached;
	Eina_Rectangle target;

	size_t index;

	struct {
		Eina_Quad_Callback v;
		Eina_Quad_Callback h;
	} func;

	struct {
		size_t w;
		size_t h;
	} geom;

	Eina_Bool resize:1;
	Eina_Bool lost:1;
};

struct _Eina_QuadTree_Root {
	EINA_MAGIC;

	Eina_QuadTree_Root *parent;
	Eina_QuadTree_Root *left;
	Eina_QuadTree_Root *right;

	Eina_List *both;

	Eina_Bool sorted:1;
};

struct _Eina_QuadTree_Item {
	EINA_MAGIC;
	EINA_INLIST;

	Eina_QuadTree *quad;
	Eina_QuadTree_Root *root;

	const void *object;

	size_t index;

	Eina_Bool change:1;
	Eina_Bool delete_me:1;
	Eina_Bool visible:1;
	Eina_Bool hidden:1;
};

static int _eina_log_qd_dom = -1;
static Eina_Mempool *root_mp = NULL;
static Eina_Mempool *items_mp = NULL;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_log_qd_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_log_qd_dom, __VA_ARGS__)


static int _eina_quadtree_item_cmp(const void *a, const void *b)
{
	const Eina_QuadTree_Item *i = a;
	const Eina_QuadTree_Item *j = b;

	return i->index - j->index;
}

static Eina_QuadTree_Root *eina_quadtree_root_free(Eina_QuadTree * q,
						   Eina_QuadTree_Root *
						   root)
{
	Eina_QuadTree_Item *item;

	if (!root)
		return NULL;

	EINA_MAGIC_CHECK_QUADTREE_ROOT(root, NULL);

	EINA_LIST_FREE(root->both, item)
	    eina_mempool_free(items_mp, item);

	root->left = eina_quadtree_root_free(q, root->left);
	root->right = eina_quadtree_root_free(q, root->right);

	EINA_MAGIC_SET(root, 0);
	eina_mempool_free(root_mp, root);

	return NULL;
}

static Eina_QuadTree_Root *eina_quadtree_root_rebuild_pre(Eina_QuadTree *
							  q,
							  Eina_Inlist **
							  change,
							  Eina_QuadTree_Root
							  * root)
{
	Eina_QuadTree_Item *item;

	if (!root)
		return NULL;

	EINA_LIST_FREE(root->both, item) {
		if (item->visible)
			*change =
			    eina_inlist_append(*change,
					       EINA_INLIST_GET(item));
		else if (!item->hidden) {
			q->hidden = eina_list_append(q->hidden, item);
			item->hidden = EINA_TRUE;
			item->root = NULL;
		}
	}

	root->left = eina_quadtree_root_rebuild_pre(q, change, root->left);
	root->right =
	    eina_quadtree_root_rebuild_pre(q, change, root->right);

	EINA_MAGIC_SET(root, 0);
	if (q->root_count > 50)
		eina_mempool_free(root_mp, root);
	else {
		eina_trash_push(&q->root_trash, root);
		q->root_count++;
	}

	return NULL;
}

static size_t
_eina_quadtree_split(Eina_Inlist * objects,
		     Eina_QuadTree_Root * root,
		     Eina_Inlist ** left,
		     Eina_Inlist ** right,
		     Eina_Quad_Callback func, int border, int middle)
{
	Eina_QuadTree_Item *object;

	middle /= 2;

	if (middle <= 4)
		while (objects) {
			object =
			    EINA_INLIST_CONTAINER_GET(objects,
						      Eina_QuadTree_Item);
			objects = objects->next;

			object->change = EINA_FALSE;
			if (!object->visible) {
				if (!object->hidden) {
					object->hidden = EINA_TRUE;
					object->quad->hidden =
					    eina_list_append(object->quad->
							     hidden,
							     object);
				}

				continue;
			}

			if (object->hidden) {
				object->hidden = EINA_FALSE;
				object->quad->hidden =
				    eina_list_remove(object->quad->hidden,
						     object);
			}

			if (!object->delete_me) {
				if (root->sorted)
					root->both =
					    eina_list_sorted_insert(root->
								    both,
								    _eina_quadtree_item_cmp,
								    object);
				else
					root->both =
					    eina_list_append(root->both,
							     object);

				object->root = root;
			} else
				eina_quadtree_del(object);
	} else
		while (objects) {
			object =
			    EINA_INLIST_CONTAINER_GET(objects,
						      Eina_QuadTree_Item);
			objects = objects->next;

			object->change = EINA_FALSE;
			if (!object->visible) {
				if (!object->hidden) {
					object->hidden = EINA_TRUE;
					object->quad->hidden =
					    eina_list_append(object->quad->
							     hidden,
							     object);
				}

				continue;
			}

			if (object->hidden) {
				object->hidden = EINA_FALSE;
				object->quad->hidden =
				    eina_list_remove(object->quad->hidden,
						     object);
			}

			if (!object->delete_me) {
				switch (func
					(object->object,
					 border + middle)) {
				case EINA_QUAD_LEFT:
					*left =
					    eina_inlist_append(*left,
							       EINA_INLIST_GET
							       (object));
					break;

				case EINA_QUAD_RIGHT:
					*right =
					    eina_inlist_append(*right,
							       EINA_INLIST_GET
							       (object));
					break;

				case EINA_QUAD_BOTH:
					root->both =
					    eina_list_append(root->both,
							     object);
					object->root = root;
					break;

				default:
					abort();
				}
			} else
				eina_quadtree_del(object);
		}

	return middle;
}


static Eina_QuadTree_Root *_eina_quadtree_update(Eina_QuadTree * q,
						 Eina_QuadTree_Root *
						 parent,
						 Eina_QuadTree_Root * root,
						 Eina_Inlist * objects,
						 Eina_Bool direction,
						 Eina_Rectangle * size)
{
	Eina_Inlist *right = NULL;
	Eina_Inlist *left = NULL;
	size_t w2;
	size_t h2;

	if (!objects)
		return root;

	if (!root) {
		root = eina_trash_pop(&q->root_trash);
		if (!root)
			root =
			    eina_mempool_malloc(root_mp,
						sizeof
						(Eina_QuadTree_Root));
		else
			q->root_count--;

		if (!root)
			/* FIXME: NOT GOOD TIMING, WE ARE GOING TO LEAK MORE MEMORY */
			return NULL;

		root->parent = parent;
		root->both = NULL;
		root->left = NULL;
		root->right = NULL;
		root->sorted = EINA_TRUE;

		EINA_MAGIC_SET(root, EINA_MAGIC_QUADTREE_ROOT);
	}

	w2 = 0;
	h2 = 0;

	if (direction)
		w2 = _eina_quadtree_split(objects, root,
					  &left, &right,
					  q->func.h, size->x, size->w);
	else
		h2 = _eina_quadtree_split(objects, root,
					  &left, &right,
					  q->func.v, size->y, size->h);

	size->w -= w2;
	size->h -= h2;
	root->left = _eina_quadtree_update(q, root,
					   root->left, left,
					   !direction, size);
	size->x += w2;
	size->y += h2;
	root->right = _eina_quadtree_update(q, root,
					    root->right, right,
					    !direction, size);
	size->x -= w2;
	size->y -= h2;
	size->w += w2;
	size->h += h2;

	return root;
}

static Eina_Inlist *_eina_quadtree_merge(Eina_Inlist * result,
					 Eina_List * both)
{
	Eina_QuadTree_Item *item;
	Eina_QuadTree_Item *b;
	Eina_Inlist *moving;

	if (!both)
		return result;

	if (!result) {
		Eina_List *l;

		EINA_LIST_FOREACH(both, l, item)
		    if (item->visible)
			result =
			    eina_inlist_append(result,
					       EINA_INLIST_GET(item));

		return result;
	}

	moving = result;

	item = EINA_INLIST_CONTAINER_GET(moving, Eina_QuadTree_Item);
	b = eina_list_data_get(both);

	while (both && moving) {
		if (!b->visible) {
			both = eina_list_next(both);
			b = eina_list_data_get(both);
			continue;
		}

		if (_eina_quadtree_item_cmp(item, b) < 0) {
			/* moving is still lower than item, so we can continue to the next one. */
			moving = moving->next;
			item =
			    EINA_INLIST_CONTAINER_GET(moving,
						      Eina_QuadTree_Item);
		} else {
			/* we just get above the limit of both, so insert it */
			result = eina_inlist_prepend_relative(result,
							      EINA_INLIST_GET
							      (b), moving);
			both = eina_list_next(both);
			b = eina_list_data_get(both);
		}
	}

	item = EINA_INLIST_CONTAINER_GET(result->last, Eina_QuadTree_Item);

	while (both) {
		b = eina_list_data_get(both);
		if (b->visible) {
			if (_eina_quadtree_item_cmp(item, b) < 0)
				break;

			result = eina_inlist_prepend_relative(result,
							      EINA_INLIST_GET
							      (b),
							      result->
							      last);
		}

		both = eina_list_next(both);
	}

	while (both) {
		b = eina_list_data_get(both);
		if (b->visible)
			result =
			    eina_inlist_append(result, EINA_INLIST_GET(b));

		both = eina_list_next(both);
	}

	return result;
}

static Eina_Inlist *_eina_quadtree_collide(Eina_Inlist * result,
					   Eina_QuadTree_Root * root,
					   Eina_Bool direction,
					   Eina_Rectangle * size,
					   Eina_Rectangle * target)
{
	if (!root)
		return result;

	if (!root->sorted) {
		root->both =
		    eina_list_sort(root->both, -1,
				   _eina_quadtree_item_cmp);
		root->sorted = EINA_TRUE;
	}

	result = _eina_quadtree_merge(result, root->both);
	DBG("%p: %i in both for (%i, %i - %i, %i)",
	    root, eina_list_count(root->both),
	    size->x, size->y, size->w, size->h);

	if (direction) {
		int middle = size->w / 2;

		size->w -= middle;
		if (eina_spans_intersect
		    (size->x, size->w, target->x, target->w))
			result =
			    _eina_quadtree_collide(result, root->left,
						   !direction, size,
						   target);

		size->x += middle;
		if (eina_spans_intersect
		    (size->x, size->w, target->x, target->w))
			result =
			    _eina_quadtree_collide(result, root->right,
						   !direction, size,
						   target);

		size->x -= middle;
		size->w += middle;
	} else {
		int middle = size->h / 2;

		size->h -= middle;
		if (eina_spans_intersect
		    (size->y, size->h, target->y, target->h))
			result =
			    _eina_quadtree_collide(result, root->left,
						   !direction, size,
						   target);

		size->y += middle;
		if (eina_spans_intersect
		    (size->y, size->h, target->y, target->h))
			result =
			    _eina_quadtree_collide(result, root->right,
						   !direction, size,
						   target);

		size->y -= middle;
		size->h += middle;
	}

	return result;
}

static void _eina_quadtree_remove(Eina_QuadTree_Item * object)
{
	if (!object->root)
		return;

	object->root->both = eina_list_remove(object->root->both, object);
	if (object->root->both)
		goto end;

	if (object->root->left)
		goto end;

	if (object->root->right)
		goto end;

	/* The root is not useful anymore... */
	if (object->root->parent) {
		if (object->root->parent->left == object->root)
			object->root->parent->left = NULL;
		else
			object->root->parent->right = NULL;

		object->root->parent = NULL;
	} else
		object->quad->root = NULL;

	if (object->quad->root_count > 50)
		eina_mempool_free(root_mp, object->root);
	else {
		eina_trash_push(&object->quad->root_trash, object->root);
		object->quad->root_count++;
	}

      end:
	object->root = NULL;
}

EAPI Eina_QuadTree *eina_quadtree_new(size_t w, size_t h,
				      Eina_Quad_Callback vertical,
				      Eina_Quad_Callback horizontal)
{
	Eina_QuadTree *result;

	if (!vertical || !horizontal || h == 0 || w == 0)
		return NULL;

	result = calloc(1, sizeof(Eina_QuadTree));
	if (!result)
		return NULL;

	result->func.v = vertical;
	result->func.h = horizontal;

	result->geom.w = w;
	result->geom.h = h;

	result->change = NULL;

	result->lost = EINA_TRUE;

	EINA_MAGIC_SET(result, EINA_MAGIC_QUADTREE);

	return result;
}

EAPI void eina_quadtree_free(Eina_QuadTree * q)
{
	Eina_QuadTree_Item *item;

	if (!q)
		return;

	EINA_MAGIC_CHECK_QUADTREE(q);

	while (q->change) {
		item =
		    EINA_INLIST_CONTAINER_GET(q->change,
					      Eina_QuadTree_Item);
		q->change = q->change->next;
		if (!item->hidden)
			eina_mempool_free(items_mp, item);
	}

	EINA_LIST_FREE(q->hidden, item)
	    eina_mempool_free(items_mp, item);

	eina_quadtree_root_free(q, q->root);

	while (q->items_trash) {
		item = eina_trash_pop(&q->items_trash);
		eina_mempool_free(items_mp, item);
	}

	while (q->root_trash) {
		Eina_QuadTree_Root *root;

		root = eina_trash_pop(&q->root_trash);
		eina_mempool_free(root_mp, root);
	}

	EINA_MAGIC_SET(q, 0);
	free(q);
}

EAPI Eina_QuadTree_Item *eina_quadtree_add(Eina_QuadTree * q,
					   const void *object)
{
	Eina_QuadTree_Item *result;

	EINA_MAGIC_CHECK_QUADTREE(q, NULL);

	if (!object)
		return NULL;

	result = eina_trash_pop(&q->items_trash);
	if (!result)
		result =
		    eina_mempool_malloc(items_mp,
					sizeof(Eina_QuadTree_Item));
	else
		q->items_count--;

	if (!result)
		return NULL;

	result->quad = q;
	result->root = NULL;
	result->object = object;

	result->index = q->index++;

	result->change = EINA_TRUE;
	result->delete_me = EINA_FALSE;
	result->visible = EINA_TRUE;
	result->hidden = EINA_FALSE;

	EINA_MAGIC_SET(result, EINA_MAGIC_QUADTREE_ITEM);

	/* Insertion is delayed until we really need to use it */
	q->change = eina_inlist_append(q->change, EINA_INLIST_GET(result));

	return result;
}

EAPI Eina_Bool eina_quadtree_del(Eina_QuadTree_Item * object)
{
	if (!object)
		return EINA_FALSE;

	EINA_MAGIC_CHECK_QUADTREE_ITEM(object, EINA_FALSE);

	_eina_quadtree_remove(object);

	if (object->change) {
		/* This object is still in the update array, delaying it's removal ! */
		object->delete_me = EINA_TRUE;
		object->visible = EINA_TRUE;
		return EINA_TRUE;
	}

	if (object->hidden) {
		object->quad->hidden =
		    eina_list_remove(object->quad->hidden, object);
		object->hidden = EINA_TRUE;
	}

	/* This object is not anymore inside the tree, we can remove it now ! */
	EINA_MAGIC_SET(object, 0);
	if (object->quad->items_count > 256)
		eina_mempool_free(items_mp, object);
	else {
		object->quad->items_count++;
		eina_trash_push(&object->quad->items_trash, object);
	}

	return EINA_TRUE;
}

EAPI Eina_Bool eina_quadtree_change(Eina_QuadTree_Item * object)
{
	EINA_MAGIC_CHECK_QUADTREE_ITEM(object, EINA_FALSE);

	if (object->delete_me || !object->visible)
		return EINA_FALSE;

	if (object->quad->resize)
		return EINA_TRUE;

	/* Delaying change until needed */
	if (!object->change)
		object->quad->change =
		    eina_inlist_append(object->quad->change,
				       EINA_INLIST_GET(object));

	object->change = EINA_TRUE;

	_eina_quadtree_remove(object);

	return EINA_TRUE;
}

EAPI Eina_Bool eina_quadtree_hide(Eina_QuadTree_Item * object)
{
	EINA_MAGIC_CHECK_QUADTREE_ITEM(object, EINA_FALSE);

	object->visible = EINA_FALSE;

	return EINA_TRUE;
}

EAPI Eina_Bool eina_quadtree_show(Eina_QuadTree_Item * object)
{
	EINA_MAGIC_CHECK_QUADTREE_ITEM(object, EINA_FALSE);

	object->quad->lost = EINA_TRUE;

	if (object->visible)
		return EINA_TRUE;

	object->visible = EINA_TRUE;
	if (!object->change)
		return eina_quadtree_change(object);

	return EINA_TRUE;
}

EAPI Eina_Inlist *eina_quadtree_collide(Eina_QuadTree * q, int x, int y,
					int w, int h)
{
	Eina_Rectangle canvas;

	EINA_MAGIC_CHECK_QUADTREE(q, NULL);

	/* Now we need the tree to be up to date, so it's time */
	if (q->resize) {	/* Full rebuild needed ! */
		DBG("resizing quadtree");
		q->root =
		    eina_quadtree_root_rebuild_pre(q, &q->change, q->root);
		q->resize = EINA_FALSE;
	}

	EINA_RECTANGLE_SET(&canvas, 0, 0, q->geom.w, q->geom.h);

	if (q->change) {
		DBG("updating quadtree content");
		q->root =
		    _eina_quadtree_update(q, NULL, q->root, q->change,
					  EINA_FALSE, &canvas);
		q->change = NULL;
		q->lost = EINA_TRUE;
	}

	if (q->target.x != x
	    || q->target.y != y || q->target.w != w || q->target.h != h) {
		DBG("new target");
		EINA_RECTANGLE_SET(&q->target, x, y, w, h);
		q->lost = EINA_TRUE;
	}

	if (q->lost) {
		DBG("computing collide");
		q->cached = _eina_quadtree_collide(NULL, q->root,
						   EINA_FALSE, &canvas,
						   &q->target);
		q->lost = EINA_FALSE;
	}

	return q->cached;
}

EAPI void *eina_quadtree_object(Eina_Inlist * item)
{
	Eina_QuadTree_Item *qi;

	if (!item)
		return NULL;

	qi = EINA_INLIST_CONTAINER_GET(item, Eina_QuadTree_Item);
	if (!qi)
		return NULL;

	EINA_MAGIC_CHECK_QUADTREE_ITEM(qi, NULL);

	if (!qi->visible)
		return NULL;

	return (void *) qi->object;
}

EAPI void eina_quadtree_resize(Eina_QuadTree * q, size_t w, size_t h)
{
	EINA_MAGIC_CHECK_QUADTREE(q);

	if (q->geom.w == w && q->geom.h == h)
		return;

	q->resize = EINA_TRUE;
	q->geom.w = w;
	q->geom.h = h;
}

EAPI void eina_quadtree_cycle(Eina_QuadTree * q)
{
	EINA_MAGIC_CHECK_QUADTREE(q);

	q->index = 0;
}

EAPI void eina_quadtree_increase(Eina_QuadTree_Item * object)
{
	size_t tmp;

	tmp = object->quad->index++;
	if (object->index == tmp)
		return;

	object->index = tmp;
	if (object->root)
		object->root->sorted = EINA_FALSE;
}

Eina_Bool eina_quadtree_init(void)
{
	_eina_log_qd_dom = eina_log_domain_register("eina_quadtree",
						    EINA_LOG_COLOR_DEFAULT);
	if (_eina_log_qd_dom < 0) {
		EINA_LOG_ERR
		    ("Could not register log domain: eina_quadtree");
		return EINA_FALSE;
	}
#define EMS(n) eina_magic_string_static_set(n, n ## _STR)
	EMS(EINA_MAGIC_QUADTREE);
	EMS(EINA_MAGIC_QUADTREE_ROOT);
	EMS(EINA_MAGIC_QUADTREE_ITEM);
#undef EMS

	items_mp =
	    eina_mempool_add("chained_mempool", "QuadTree Item", NULL,
			     sizeof(Eina_QuadTree_Item), 320);
	root_mp =
	    eina_mempool_add("chained_mempool", "QuadTree Root", NULL,
			     sizeof(Eina_QuadTree_Root), 32);

	return EINA_TRUE;
}

Eina_Bool eina_quadtree_shutdown(void)
{
	eina_log_domain_unregister(_eina_log_qd_dom);
	_eina_log_qd_dom = -1;
	return EINA_TRUE;
}
