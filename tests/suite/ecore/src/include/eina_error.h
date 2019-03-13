/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga, Cedric Bail
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

#ifndef EINA_ERROR_H_
#define EINA_ERROR_H_

#include <stdarg.h>

#include "eina_types.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Error_Group Error
 *
 * @{
 */

/**
 * @typedef Eina_Error
 * Error type.
 */
typedef int Eina_Error;

/**
 * @var EINA_ERROR_OUT_OF_MEMORY
 * Error identifier corresponding to a lack of memory.
 */
EAPI extern Eina_Error EINA_ERROR_OUT_OF_MEMORY;

EAPI Eina_Error eina_error_msg_register(const char *msg)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Error eina_error_msg_static_register(const char *msg)
EINA_ARG_NONNULL(1) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Bool eina_error_msg_modify(Eina_Error error,
				     const char *msg) EINA_ARG_NONNULL(2);
EAPI Eina_Error eina_error_get(void);
EAPI void eina_error_set(Eina_Error err);
EAPI const char *eina_error_msg_get(Eina_Error error) EINA_PURE;

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_ERROR_H_ */
