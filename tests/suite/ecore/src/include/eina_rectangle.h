/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga
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

#ifndef EINA_RECTANGLE_H_
#define EINA_RECTANGLE_H_

#include "eina_types.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Rectangle_Group Rectangle
 *
 * @{
 */

/**
 * @typedef Eina_Rectangle
 * Simple rectangle structure.
 */
typedef struct _Eina_Rectangle {
	int x;
	 /**< top-left x co-ordinate of rectangle */
	int y;
	 /**< top-left y co-ordinate of rectangle */
	int w;
	 /**< width of rectangle */
	int h;
	 /**< height of rectangle */
} Eina_Rectangle;

/**
 * @typedef Eina_Rectangle_Pool
 * Type for an opaque pool of rectangle.
 */
typedef struct _Eina_Rectangle_Pool Eina_Rectangle_Pool;

static inline int eina_spans_intersect(int c1, int l1, int c2,
				       int l2) EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_rectangle_is_empty(const Eina_Rectangle *
						r) EINA_ARG_NONNULL(1)
    EINA_WARN_UNUSED_RESULT;
static inline void eina_rectangle_coords_from(Eina_Rectangle * r, int x,
					      int y, int w,
					      int h) EINA_ARG_NONNULL(1);
static inline Eina_Bool eina_rectangles_intersect(const Eina_Rectangle *
						  r1,
						  const Eina_Rectangle *
						  r2) EINA_ARG_NONNULL(1,
								       2)
    EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_rectangle_xcoord_inside(const Eina_Rectangle *
						     r,
						     int x)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_rectangle_ycoord_inside(const Eina_Rectangle *
						     r,
						     int y)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_rectangle_coords_inside(const Eina_Rectangle *
						     r, int x,
						     int y)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline void eina_rectangle_union(Eina_Rectangle * dst,
					const Eina_Rectangle *
					src) EINA_ARG_NONNULL(1, 2);
static inline Eina_Bool eina_rectangle_intersection(Eina_Rectangle * dst,
						    const Eina_Rectangle *
						    src)
EINA_ARG_NONNULL(1, 2) EINA_WARN_UNUSED_RESULT;
static inline void eina_rectangle_rescale_in(const Eina_Rectangle * out,
					     const Eina_Rectangle * in,
					     Eina_Rectangle *
					     res) EINA_ARG_NONNULL(1, 2,
								   3);
static inline void eina_rectangle_rescale_out(const Eina_Rectangle * out,
					      const Eina_Rectangle * in,
					      Eina_Rectangle *
					      res) EINA_ARG_NONNULL(1, 2,
								    3);

EAPI Eina_Rectangle_Pool *eina_rectangle_pool_new(int w, int h)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI Eina_Rectangle_Pool *eina_rectangle_pool_get(Eina_Rectangle * rect)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_rectangle_pool_geometry_get(Eina_Rectangle_Pool * pool,
						int *w, int *h)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
EAPI void *eina_rectangle_pool_data_get(Eina_Rectangle_Pool * pool)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI void eina_rectangle_pool_data_set(Eina_Rectangle_Pool * pool,
				       const void *data)
EINA_ARG_NONNULL(1);
EAPI void eina_rectangle_pool_free(Eina_Rectangle_Pool *
				   pool) EINA_ARG_NONNULL(1);
EAPI int eina_rectangle_pool_count(Eina_Rectangle_Pool *
				   pool) EINA_ARG_NONNULL(1)
    EINA_WARN_UNUSED_RESULT;
EAPI Eina_Rectangle *eina_rectangle_pool_request(Eina_Rectangle_Pool *
						 pool, int w, int h)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI void eina_rectangle_pool_release(Eina_Rectangle *
				      rect) EINA_ARG_NONNULL(1);

/**
 * @def EINA_RECTANGLE_SET
 * @brief Macro to set the values of a #Eina_Rectangle.
 *
 * @param Rectangle The rectangle to set the values.
 * @param X The X coordinate of the top left corner of the rectangle.
 * @param Y The Y coordinate of the top left corner of the rectangle.
 * @param W The width of the rectangle.
 * @param H The height of the rectangle.
 *
 * This macro set the values of @p Rectangle. (@p X, @p Y) is the
 * coordinates of the top left corner of @p Rectangle, @p W is its
 * width and @p H is its height.
 */
#define EINA_RECTANGLE_SET(Rectangle, X, Y, W, H) \
                          (Rectangle)->x = X;     \
                          (Rectangle)->y = Y;     \
                          (Rectangle)->w = W;     \
                          (Rectangle)->h = H;

EAPI Eina_Rectangle *eina_rectangle_new(int x, int y, int w, int h)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI void eina_rectangle_free(Eina_Rectangle * rect) EINA_ARG_NONNULL(1);

#include "eina_inline_rectangle.x"

/**
 * @}
 */

/**
 * @}
 */

#endif /*_EINA_RECTANGLE_H_*/
