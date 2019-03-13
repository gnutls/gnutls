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

#ifndef EINA_SHARE_COMMON_H_
#define EINA_SHARE_COMMON_H_

#include "eina_types.h"
#include "eina_magic.h"

typedef struct _Eina_Share Eina_Share;

struct dumpinfo {
	int used, saved, dups, unique;
};

Eina_Bool eina_share_common_init(Eina_Share ** share,
				 Eina_Magic node_magic,
				 const char *node_magic_STR);
Eina_Bool eina_share_common_shutdown(Eina_Share ** share);
const char *eina_share_common_add_length(Eina_Share * share,
					 const char *str,
					 unsigned int slen,
					 unsigned int null_size)
    EINA_WARN_UNUSED_RESULT;
const char *eina_share_common_ref(Eina_Share * share, const char *str);
void eina_share_common_del(Eina_Share * share, const char *str);
int eina_share_common_length(Eina_Share * share,
			     const char *str) EINA_CONST
    EINA_WARN_UNUSED_RESULT;
void eina_share_common_dump(Eina_Share * share,
			    void (*additional_dump) (struct dumpinfo *),
			    int used);


/* Population functions */
void eina_share_common_population_add(Eina_Share * share, int slen);
void eina_share_common_population_del(Eina_Share * share, int slen);

/* Share logging */
#ifdef CRITICAL
#undef CRITICAL
#endif
#define CRITICAL(...) EINA_LOG_DOM_CRIT(_eina_share_common_log_dom, __VA_ARGS__)

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_share_common_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_share_common_log_dom, __VA_ARGS__)
extern int _eina_share_common_log_dom;

#endif				/* EINA_STRINGSHARE_H_ */
