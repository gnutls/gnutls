/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric Bail
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

#ifndef EINA_COUNTER_H_
#define EINA_COUNTER_H_

#include "eina_types.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Counter_Group Counter
 *
 * @{
 */

/**
 * @typedef Eina_Counter
 * Counter type.
 */
typedef struct _Eina_Counter Eina_Counter;

EAPI Eina_Counter *eina_counter_new(const char *name)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI void eina_counter_free(Eina_Counter * counter) EINA_ARG_NONNULL(1);
EAPI void eina_counter_start(Eina_Counter * counter) EINA_ARG_NONNULL(1);
EAPI void eina_counter_stop(Eina_Counter * counter,
			    int specimen) EINA_ARG_NONNULL(1);
EAPI char *eina_counter_dump(Eina_Counter * counter) EINA_ARG_NONNULL(1);

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_COUNTER_H_ */
