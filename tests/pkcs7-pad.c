/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

/* Test that _gnutls_pkcs7_unpad is branch-free, using valgrind */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <string.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "utils.h"

static inline void _gnutls_memory_mark_undefined(void *addr, size_t size)
{
#ifdef HAVE_VALGRIND_MEMCHECK_H
	if (RUNNING_ON_VALGRIND)
		VALGRIND_MAKE_MEM_UNDEFINED(addr, size);
#endif
}

static inline void _gnutls_memory_mark_defined(void *addr, size_t size)
{
#ifdef HAVE_VALGRIND_MEMCHECK_H
	if (RUNNING_ON_VALGRIND)
		VALGRIND_MAKE_MEM_DEFINED(addr, size);
#endif
}

extern unsigned int _gnutls_pkcs7_unpad(const uint8_t *block,
					unsigned int block_size);

static unsigned int wrap_pkcs7_unpad(uint8_t *block, unsigned int block_size)
{
	unsigned int padding;

	_gnutls_memory_mark_undefined(block, block_size);

	padding = _gnutls_pkcs7_unpad(block, block_size);

	_gnutls_memory_mark_defined(block, block_size);
	_gnutls_memory_mark_defined(&padding, sizeof(padding));

	return padding;
}

#define PAD 5

void doit(void)
{
	uint8_t block[16];
	unsigned int padding;

	memset(block, 0xFF, sizeof(block));
	memset(&block[sizeof(block) - PAD], PAD, PAD);

	padding = wrap_pkcs7_unpad(block, sizeof(block));
	if (padding != PAD)
		fail("padding should be %d\n", PAD);

	/* The last padding byte exceeds the block size */
	block[sizeof(block) - 1] = sizeof(block) + 1;
	padding = wrap_pkcs7_unpad(block, sizeof(block));
	if (padding != 0)
		fail("padding should be 0\n");
	block[sizeof(block) - 1] = PAD;

	/* The last padding byte is zero */
	block[sizeof(block) - 1] = 0;
	padding = wrap_pkcs7_unpad(block, sizeof(block));
	if (padding != 0)
		fail("padding should be 0\n");
	block[sizeof(block) - 1] = PAD;

	/* The first padding byte is invalid */
	block[sizeof(block) - PAD] = PAD + 1;
	padding = wrap_pkcs7_unpad(block, sizeof(block));
	if (padding != 0)
		fail("padding should be 0\n");
	block[sizeof(block) - PAD] = PAD;

	/* The byte before the first padding equals to PAD */
	block[sizeof(block) - PAD - 1] = PAD;
	padding = wrap_pkcs7_unpad(block, sizeof(block));
	if (padding != PAD)
		fail("padding should be %d\n", PAD);
	block[sizeof(block) - PAD - 1] = 0xFF;
}
