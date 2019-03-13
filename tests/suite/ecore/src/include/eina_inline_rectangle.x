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

#ifndef EINA_INLINE_RECTANGLE_H__
#define EINA_INLINE_RECTANGLE_H__

/**
 * @addtogroup Eina_Rectangle_Group Rectangle
 *
 * @brief These functions provide rectangle management.
 *
 * @{
 */

/**
 * @brief Check if the given spans intersect.
 *
 * @param c1 The column of the first span.
 * @param l1 The length of the first span.
 * @param c2 The column of the second span.
 * @param l2 The length of the second span.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if the  given spans intersect,
 * #EINA_FALSE otherwise.
 */
static inline int
eina_spans_intersect(int c1, int l1, int c2, int l2)
{
	return (!(((c2 + l2) <= c1) || (c2 >= (c1 + l1))));
}

/**
 * @brief Check if the given rectangle is empty.
 *
 * @param r The rectangle to check.
 * @return #EINA_TRUE if the rectangle is empty, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if @p r is empty, #EINA_FALSE
 * otherwise. No check is done on @p r, so it must be a valid
 * rectangle.
 */
static inline Eina_Bool
eina_rectangle_is_empty(const Eina_Rectangle *r)
{
	return ((r->w < 1) || (r->h < 1)) ? EINA_TRUE : EINA_FALSE;
}

/**
 * @brief Set the coordinates and size of the given rectangle.
 *
 * @param r The rectangle.
 * @param x The top-left x coordinate of the rectangle.
 * @param y The top-left y coordinate of the rectangle.
 * @param w The width of the rectangle.
 * @param h The height of the rectangle.
 *
 * This function sets its top-left x coordinate to @p x, its top-left
 * y coordinate to @p y, its width to @p w and its height to @p h. No
 * check is done on @p r, so it must be a valid rectangle.
 */
static inline void
eina_rectangle_coords_from(Eina_Rectangle *r, int x, int y, int w, int h)
{
	r->x = x;
	r->y = y;
	r->w = w;
	r->h = h;
}

/**
 * @brief Check if the given rectangles intersect.
 *
 * @param r1 The first rectangle.
 * @param r2 The second rectangle.
 * @return #EINA_TRUE if the rectangles intersect, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if @p r1 and @p r2 intersect,
 * #EINA_FALSE otherwise. No check is done on @p r1 and @p r2, so they
 * must be valid rectangles.
 */
static inline Eina_Bool
eina_rectangles_intersect(const Eina_Rectangle *r1, const Eina_Rectangle *r2)
{
	return (eina_spans_intersect(r1->x, r1->w, r2->x, r2->w) && eina_spans_intersect(r1->y, r1->h, r2->y, r2->h)) ? EINA_TRUE : EINA_FALSE;
}

/**
 * @brief Check if the given x-coordinate is in the rectangle .
 *
 * @param r The rectangle.
 * @param x The x coordinate.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if @p x is in @p r with respect to
 * the horizontal direction, #EINA_FALSE otherwise. No check is done
 * on @p r, so it must be a valid rectangle.
 */
static inline Eina_Bool
eina_rectangle_xcoord_inside(const Eina_Rectangle *r, int x)
{
	return ((x >= r->x) && (x < (r->x + r->w))) ? EINA_TRUE : EINA_FALSE;
}

/**
 * @brief Check if the given y-coordinate is in the rectangle .
 *
 * @param r The rectangle.
 * @param y The y coordinate.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if @p y is in @p r with respect to
 * the vertical direction, #EINA_FALSE otherwise. No check is done
 * on @p r, so it must be a valid rectangle.
 */
static inline Eina_Bool
eina_rectangle_ycoord_inside(const Eina_Rectangle *r, int y)
{
	return ((y >= r->y) && (y < (r->y + r->h))) ? EINA_TRUE : EINA_FALSE;
}

/**
 * @brief Check if the given point is in the rectangle .
 *
 * @param r The rectangle.
 * @param x The x coordinate of the point.
 * @param y The y coordinate of the point.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function returns #EINA_TRUE if the point of coordinate (@p x,
 * @p y) is in @p r, #EINA_FALSE otherwise. No check is done on @p r,
 * so it must be a valid rectangle.
 */
static inline Eina_Bool
eina_rectangle_coords_inside(const Eina_Rectangle *r, int x, int y)
{
	return (eina_rectangle_xcoord_inside(r, x) && eina_rectangle_ycoord_inside(r, y)) ? EINA_TRUE : EINA_FALSE;
}

/**
 * @brief Get the union of two rectangles.
 *
 * @param dst The first rectangle.
 * @param src The second rectangle.
 *
 * This function get the union of the rectangles @p dst and @p src. The
 * result is stored in @p dst. No check is done on @p dst or @p src,
 * so they must be valid rectangles.
 */
static inline void
eina_rectangle_union(Eina_Rectangle *dst, const Eina_Rectangle *src)
{
	/* left */
	if (dst->x > src->x)
	{
		dst->w += dst->x - src->x;
		dst->x = src->x;
	}
	/* right */
	if ((dst->x + dst->w) < (src->x + src->w))
		dst->w = src->x + src->w;
	/* top */
	if (dst->y > src->y)
	{
		dst->h += dst->y - src->y;
		dst->y = src->y;
	}
	/* bottom */
	if ((dst->y + dst->h) < (src->y + src->h))
		dst->h = src->y + src->h;
}

/**
 * @brief Get the intersection of two rectangles.
 *
 * @param dst The first rectangle.
 * @param src The second rectangle.
 * @return #EINA_TRUE if the rectangles intersect, #EINA_FALSE
 * otherwise.
 *
 * This function get the intersection of the rectangles @p dst and
 * @p src. The result is stored in @p dst. No check is done on @p dst
 * or @p src, so they must be valid rectangles.
 */
static inline Eina_Bool
eina_rectangle_intersection(Eina_Rectangle *dst, const Eina_Rectangle *src)
{
	if (!(eina_rectangles_intersect(dst, src)))
		return EINA_FALSE;

	/* left */
	if (dst->x < src->x)
	{
		dst->w += dst->x - src->x;
		dst->x = src->x;
		if (dst->w < 0)
			dst->w = 0;
	}
	/* right */
	if ((dst->x + dst->w) > (src->x + src->w))
		dst->w = src->x + src->w - dst->x;
	/* top */
	if (dst->y < src->y)
	{
		dst->h += dst->y - src->y;
		dst->y = src->y;
		if (dst->h < 0)
			dst->h = 0;
	}
	/* bottom */
	if ((dst->y + dst->h) > (src->y + src->h))
		dst->h = src->y + src->h - dst->y;

	return EINA_TRUE;
}

static inline void
eina_rectangle_rescale_in(const Eina_Rectangle *out, const Eina_Rectangle *in, Eina_Rectangle *res)
{
	res->x = in->x - out->x;
	res->y = in->y - out->y;
	res->w = in->w;
	res->h = in->h;
}

static inline void
eina_rectangle_rescale_out(const Eina_Rectangle *out, const Eina_Rectangle *in, Eina_Rectangle *res)
{
	res->x = out->x + in->x;
	res->y = out->y + in->y;
	res->w = out->w;
	res->h = out->h;
}

/**
 * @}
 */

#endif
