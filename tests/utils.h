/*
 * Copyright (C) 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef UTILS_H
# define UTILS_H

# include <string.h>
# include <stdarg.h>
# include <gnutls/gnutls.h>

extern int debug;
extern int error_count;
extern int break_on_error;

extern char *pkcs3;

extern void fail (const char *format, ...);
extern void success (const char *format, ...);

extern void escapeprint (const char *str, size_t len);
extern void hexprint (const char *str, size_t len);
extern void binprint (const char *str, size_t len);

/* This must be implemented elsewhere. */
extern void doit (void);

#endif /* UTILS_H */
