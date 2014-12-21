/*
 * Copyright (C) 2014 Nikos Mavrogiannopoulos
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
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef SOFTHSM_H
# define SOFTHSM_H

#define LIB1 "/usr/lib64/softhsm/libsofthsm.so"
#define LIB2 "/usr/lib/softhsm/libsofthsm.so"
#define LIB3 "/usr/local/lib/softhsm/libsofthsm.so"

inline static const char *softhsm_lib(void) 
{
	const char *lib;

	if (access(LIB1, R_OK) == 0) {
		lib = LIB1;
	} else if (access(LIB2, R_OK) == 0) {
		lib = LIB2;
	} else if (access(LIB3, R_OK) == 0) {
		lib = LIB3;
	} else {
		fprintf(stderr, "cannot find softhsm module\n");
		exit(77);
	}

	return lib;
}

inline static const char *softhsm_bin(void) 
{
	const char *bin;

	if (access("/usr/bin/softhsm", X_OK) == 0) {
		bin = "/usr/bin/softhsm";
	} else if (access("/usr/local/bin/softhsm", X_OK) == 0) {
		bin = "/usr/local/bin/softhsm";
	} else {
		fprintf(stderr, "cannot find softhsm module\n");
		exit(77);
	}

	return bin;
}

#endif
