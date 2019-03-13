/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Jorge Luis Zapata Muga, Cedric Bail
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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Copyright (C) 2008 Peter Wehrfritz
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies of the Software and its Copyright notices. In addition publicly
 *  documented acknowledgment must be given that this software has been used if no
 *  source code of this software is made available publicly. This includes
 *  acknowledgments in either Copyright notices, Manuals, Publicity and Marketing
 *  documents or any documentation provided with any product containing this
 *  software. This License does not apply to any software that links to the
 *  libraries provided by this software (statically or dynamically), but only to
 *  the software provided.
 *
 *  Please see the OLD-COPYING.PLAIN for a plain-english explanation of this notice
 *  and it's intent.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef EINA_BINSHARE_H_
#define EINA_BINSHARE_H_

#include "eina_types.h"

/**
 * @addtogroup Eina_Data_Types_Group Data Types
 *
 * @{
 */

/**
 * @defgroup Eina_Binshare_Group Binary Share
 *
 * @{
 */

EAPI Eina_Bool eina_binshare_init(void);
EAPI Eina_Bool eina_binshare_shutdown(void);
EAPI const void *eina_binshare_add_length(const void *obj,
					  unsigned int olen)
EINA_PURE EINA_WARN_UNUSED_RESULT;
EAPI const void *eina_binshare_ref(const void *obj);
EAPI void eina_binshare_del(const void *obj);
EAPI int eina_binshare_length(const void *obj) EINA_WARN_UNUSED_RESULT;
EAPI void eina_binshare_dump(void);

/**
 * @brief Retrieve an instance of a blob for use in a program.
 *
 * @param   ptr The binary blob to retrieve an instance of.
 * @return  A pointer to an instance of the string on success.
 *          @c NULL on failure.
 *
 * This macro retrieves an instance of @p obj. If @p obj is
 * @c NULL, then @c NULL is returned. If @p obj is already stored, it
 * is just returned and its reference counter is increased. Otherwise
 * it is added to the blobs to be searched and a duplicated blob
 * of @p obj is returned.
 *
 * This macro essentially calls eina_binshare_add_length with ptr and sizeof(*ptr)
 * as the parameters. It's useful for pointers to structures.
 *
 * @see eina_stringshare_add_length()
 */
#define eina_binshare_add(ptr) eina_binshare_add_length(ptr, sizeof(*ptr))

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_STRINGSHARE_H_ */
