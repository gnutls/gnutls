/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls-idna.h>
#include <stringprep.h>
#include <idna.h>

int safe_idna_to_ascii_8z (const char *input, unsigned ilen, char **output, int flags)
{
	uint32_t *ucs4;
	size_t ucs4len;
	int rc;

	ucs4 = stringprep_utf8_to_ucs4 (input, ilen, &ucs4len);
	if (!ucs4)
		return IDNA_ICONV_ERROR;

	rc = idna_to_ascii_4z (ucs4, output, flags);
	free (ucs4);

	return rc;
}
