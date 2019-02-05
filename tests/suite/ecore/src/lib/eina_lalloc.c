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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "eina_config.h"
#include "eina_private.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_lalloc.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

struct _Eina_Lalloc {
	void *data;
	int num_allocated;
	int num_elements;
	int acc;
	Eina_Lalloc_Alloc alloc_cb;
	Eina_Lalloc_Free free_cb;
};

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
 * @addtogroup Eina_Lalloc_Group Lazy allocator
 *
 * @{
 */

EAPI Eina_Lalloc *eina_lalloc_new(void *data,
				  Eina_Lalloc_Alloc alloc_cb,
				  Eina_Lalloc_Free free_cb, int num_init)
{
	Eina_Lalloc *a;

	EINA_SAFETY_ON_NULL_RETURN_VAL(alloc_cb, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(free_cb, NULL);

	a = calloc(1, sizeof(Eina_Lalloc));
	a->data = data;
	a->alloc_cb = alloc_cb;
	a->free_cb = free_cb;
	if (num_init > 0) {
		a->num_allocated = num_init;
		a->alloc_cb(a->data, a->num_allocated);
	}

	return a;
}

EAPI void eina_lalloc_free(Eina_Lalloc * a)
{
	EINA_SAFETY_ON_NULL_RETURN(a);
	EINA_SAFETY_ON_NULL_RETURN(a->free_cb);
	a->free_cb(a->data);
	free(a);
}

EAPI Eina_Bool eina_lalloc_element_add(Eina_Lalloc * a)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(a, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(a->alloc_cb, EINA_FALSE);

	if (a->num_elements == a->num_allocated) {
		if (a->alloc_cb(a->data, (1 << a->acc)) == EINA_TRUE) {
			a->num_allocated = (1 << a->acc);
			a->acc++;
		} else
			return EINA_FALSE;
	}

	a->num_elements++;

	return EINA_TRUE;
}

EAPI Eina_Bool eina_lalloc_elements_add(Eina_Lalloc * a, int num)
{
	int tmp;

	EINA_SAFETY_ON_NULL_RETURN_VAL(a, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(a->alloc_cb, EINA_FALSE);

	tmp = a->num_elements + num;
	if (tmp > a->num_allocated) {
		int allocated;
		int acc;

		allocated = a->num_allocated;
		acc = a->acc;

		while (tmp > allocated) {
			allocated = (1 << acc);
			acc++;
		}

		if (a->alloc_cb(a->data, allocated) == EINA_TRUE) {
			a->num_allocated = allocated;
			a->acc = acc;
		} else
			return EINA_FALSE;
	}

	a->num_elements += num;

	return EINA_TRUE;
}

/**
 * @}
 */
