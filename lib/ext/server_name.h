/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2010, 2011 Free Software
 * Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
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
#ifndef EXT_SERVER_NAME_H
#define EXT_SERVER_NAME_H

#include <gnutls_extensions.h>

typedef struct
{
  opaque name[MAX_SERVER_NAME_SIZE];
  unsigned name_length;
  gnutls_server_name_type_t type;
} server_name_st;

#define MAX_SERVER_NAME_EXTENSIONS 3

typedef struct
{
  server_name_st server_names[MAX_SERVER_NAME_EXTENSIONS];
  /* limit server_name extensions */
  unsigned server_names_size;
} server_name_ext_st;

extern extension_entry_st ext_mod_server_name;

#endif
