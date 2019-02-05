/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric BAIL, Vincent Torri
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

#ifndef EINA_CONVERT_H_
#define EINA_CONVERT_H_

#include "eina_types.h"
#include "eina_error.h"

#include "eina_fp.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Convert_Group Convert
 *
 * @{
 */

/**
 * @var EINA_ERROR_CONVERT_P_NOT_FOUND
 * Error identifier corresponding to string not containing 'p'.
 */
EAPI extern Eina_Error EINA_ERROR_CONVERT_P_NOT_FOUND;

/**
 * @var EINA_ERROR_CONVERT_0X_NOT_FOUND
 * Error identifier corresponding to string not containing '0x'.
 */
EAPI extern Eina_Error EINA_ERROR_CONVERT_0X_NOT_FOUND;

/**
 * @var EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH
 * Error identifier corresponding to length of the string being too small.
 */
EAPI extern Eina_Error EINA_ERROR_CONVERT_OUTRUN_STRING_LENGTH;

EAPI int eina_convert_itoa(int n, char *s) EINA_ARG_NONNULL(2);
EAPI int eina_convert_xtoa(unsigned int n, char *s) EINA_ARG_NONNULL(2);

EAPI int eina_convert_dtoa(double d, char *des) EINA_ARG_NONNULL(2);
EAPI Eina_Bool eina_convert_atod(const char *src,
				 int length,
				 long long *m,
				 long *e) EINA_ARG_NONNULL(1, 3, 4);

EAPI int eina_convert_fptoa(Eina_F32p32 fp, char *des) EINA_ARG_NONNULL(2);
EAPI Eina_Bool eina_convert_atofp(const char *src,
				  int length,
				  Eina_F32p32 * fp) EINA_ARG_NONNULL(1, 3);

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_CONVERT_H_ */
