/* EINA - EFL data type library
 * Copyright (C) 2010 Cedric BAIL
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

#ifndef EINA_QUADTREE_H_
#define EINA_QUADTREE_H_

#include "eina_config.h"

#include "eina_inlist.h"

typedef struct _Eina_QuadTree Eina_QuadTree;
typedef struct _Eina_QuadTree_Item Eina_QuadTree_Item;

typedef enum {
	EINA_QUAD_LEFT,
	EINA_QUAD_RIGHT,
	EINA_QUAD_BOTH
} Eina_Quad_Direction;

typedef Eina_Quad_Direction(*Eina_Quad_Callback) (const void *object,
						  size_t middle);

EAPI Eina_QuadTree *eina_quadtree_new(size_t w, size_t h,
				      Eina_Quad_Callback vertical,
				      Eina_Quad_Callback horizontal);
EAPI void eina_quadtree_free(Eina_QuadTree * q);
EAPI void eina_quadtree_resize(Eina_QuadTree * q, size_t w, size_t h);

EAPI void eina_quadtree_cycle(Eina_QuadTree * q);
EAPI void eina_quadtree_increase(Eina_QuadTree_Item * object);

EAPI Eina_QuadTree_Item *eina_quadtree_add(Eina_QuadTree * q,
					   const void *object);
EAPI Eina_Bool eina_quadtree_del(Eina_QuadTree_Item * object);
EAPI Eina_Bool eina_quadtree_change(Eina_QuadTree_Item * object);
EAPI Eina_Bool eina_quadtree_hide(Eina_QuadTree_Item * object);
EAPI Eina_Bool eina_quadtree_show(Eina_QuadTree_Item * object);

EAPI Eina_Inlist *eina_quadtree_collide(Eina_QuadTree * q, int x, int y,
					int w, int h);
EAPI void *eina_quadtree_object(Eina_Inlist * list);

#endif
