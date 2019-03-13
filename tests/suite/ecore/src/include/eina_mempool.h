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

#ifndef EINA_MEMPOOL_H_
#define EINA_MEMPOOL_H_

#include "eina_types.h"
#include "eina_error.h"
#include "eina_module.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Memory_Pool_Group Memory Pool
 *
 * @{
 */

/**
 * @typedef Eina_Mempool
 * Mempool type.
 */
typedef struct _Eina_Mempool Eina_Mempool;

/**
 * @typedef Eina_Mempool_Backend
 * Mempool backend type.
 */
typedef struct _Eina_Mempool_Backend Eina_Mempool_Backend;

EAPI extern Eina_Error EINA_ERROR_NOT_MEMPOOL_MODULE;

EAPI Eina_Mempool *eina_mempool_add(const char *module,
				    const char *context,
				    const char *options, ...)
EINA_MALLOC EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI void eina_mempool_del(Eina_Mempool * mp) EINA_ARG_NONNULL(1);

static inline void *eina_mempool_realloc(Eina_Mempool * mp, void *element,
					 unsigned int size)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline void *eina_mempool_malloc(Eina_Mempool * mp,
					unsigned int size)
EINA_MALLOC EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
static inline void eina_mempool_free(Eina_Mempool * mp,
				     void *element) EINA_ARG_NONNULL(1);

EAPI void eina_mempool_gc(Eina_Mempool * mp) EINA_ARG_NONNULL(1);
EAPI void eina_mempool_statistics(Eina_Mempool * mp) EINA_ARG_NONNULL(1);

EAPI Eina_Bool eina_mempool_register(Eina_Mempool_Backend *
				     be) EINA_ARG_NONNULL(1);
EAPI void eina_mempool_unregister(Eina_Mempool_Backend *
				  be) EINA_ARG_NONNULL(1);

EAPI unsigned int eina_mempool_alignof(unsigned int size);

#include "eina_inline_mempool.x"

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_MEMPOOL_H_ */
