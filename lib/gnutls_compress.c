/*
 * Copyright (C) 2000, 2004, 2005, 2007, 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file contains the functions which convert the TLS plaintext
 * packet to TLS compressed packet.
 */

#include "gnutls_int.h"
#include "gnutls_compress.h"
#include "gnutls_errors.h"
#include "gnutls_compress_int.h"
#include <gnutls/gnutls.h>

/* These functions allocate the return value internally
 */
int
_gnutls_m_plaintext2compressed (gnutls_session_t session,
				gnutls_datum_t * compressed,
				const gnutls_datum_t * plaintext)
{
  int size;
  opaque *data;

  size =
    _gnutls_compress (session->connection_state.write_compression_state,
		      plaintext->data, plaintext->size, &data,
		      MAX_RECORD_SEND_SIZE + EXTRA_COMP_SIZE);
  if (size < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_COMPRESSION_FAILED;
    }
  compressed->data = data;
  compressed->size = size;

  return 0;
}

int
_gnutls_m_compressed2plaintext (gnutls_session_t session,
				gnutls_datum_t * plain,
				const gnutls_datum_t * compressed)
{
  int size;
  opaque *data;

  size =
    _gnutls_decompress (session->connection_state.read_compression_state,
			compressed->data, compressed->size, &data,
			MAX_RECORD_RECV_SIZE);
  if (size < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_DECOMPRESSION_FAILED;
    }
  plain->data = data;
  plain->size = size;

  return 0;
}


/* Compression Section */
#define GNUTLS_COMPRESSION_ENTRY(name, id, wb, ml, cl)	\
  { #name, name, id, wb, ml, cl}


#define MAX_COMP_METHODS 5
const int _gnutls_comp_algorithms_size = MAX_COMP_METHODS;

struct gnutls_compression_entry
{
  const char *name;
  gnutls_compression_method_t id;
  int num;			/* the number reserved in TLS for the specific compression method */

  /* used in zlib compressor */
  int window_bits;
  int mem_level;
  int comp_level;
};
typedef struct gnutls_compression_entry gnutls_compression_entry;

gnutls_compression_entry _gnutls_compression_algorithms[MAX_COMP_METHODS] = {
  GNUTLS_COMPRESSION_ENTRY (GNUTLS_COMP_NULL, 0x00, 0, 0, 0),
#ifdef HAVE_LIBZ
  /* draft-ietf-tls-compression-02 */
  GNUTLS_COMPRESSION_ENTRY (GNUTLS_COMP_DEFLATE, 0x01, 15, 8, 3),
#endif
  {0, 0, 0, 0, 0, 0}
};

static const gnutls_compression_method_t supported_compressions[] = {
#ifdef USE_LZO
  GNUTLS_COMP_LZO,
#endif
#ifdef HAVE_LIBZ
  GNUTLS_COMP_DEFLATE,
#endif
  GNUTLS_COMP_NULL,
  0
};

#define GNUTLS_COMPRESSION_LOOP(b)	   \
  const gnutls_compression_entry *p;					\
  for(p = _gnutls_compression_algorithms; p->name != NULL; p++) { b ; }
#define GNUTLS_COMPRESSION_ALG_LOOP(a)					\
  GNUTLS_COMPRESSION_LOOP( if(p->id == algorithm) { a; break; } )
#define GNUTLS_COMPRESSION_ALG_LOOP_NUM(a)				\
  GNUTLS_COMPRESSION_LOOP( if(p->num == num) { a; break; } )

/* Compression Functions */
int
_gnutls_compression_priority (gnutls_session_t session,
			      gnutls_compression_method_t algorithm)
{				/* actually returns the priority */
  unsigned int i;
  for (i = 0; i < session->internals.priorities.compression.algorithms; i++)
    {
      if (session->internals.priorities.compression.priority[i] == algorithm)
	return i;
    }
  return -1;
}

/**
 * gnutls_compression_get_name - Returns a string with the name of the specified compression algorithm
 * @algorithm: is a Compression algorithm
 *
 * Convert a #gnutls_compression_method_t value to a string.
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified compression algorithm, or %NULL.
 **/
const char *
gnutls_compression_get_name (gnutls_compression_method_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->name + sizeof ("GNUTLS_COMP_") - 1);

  return ret;
}

/**
 * gnutls_compression_get_id - Returns the gnutls id of the specified in string algorithm
 * @name: is a compression method name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified in a string compression method, or
 *   %GNUTLS_COMP_UNKNOWN on error.
 **/
gnutls_compression_method_t
gnutls_compression_get_id (const char *name)
{
  gnutls_compression_method_t ret = GNUTLS_COMP_UNKNOWN;

  GNUTLS_COMPRESSION_LOOP (if
      (strcasecmp
       (p->name + sizeof ("GNUTLS_COMP_") - 1,
	name) == 0) ret = p->id);

  return ret;
}

/**
 * gnutls_compression_list - Get a list of supported compression methods
 *
 * Get a list of compression methods.  Note that to be able to use LZO
 * compression, you must link to libgnutls-extra and call
 * gnutls_global_init_extra().
 *
 * Returns: a zero-terminated list of #gnutls_compression_method_t
 *   integers indicating the available compression methods.
 **/
const gnutls_compression_method_t *
gnutls_compression_list (void)
{
  return supported_compressions;
}

/* return the tls number of the specified algorithm */
int
_gnutls_compression_get_num (gnutls_compression_method_t algorithm)
{
  int ret = -1;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->num);

  return ret;
}

int
_gnutls_compression_get_wbits (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->window_bits);
  return ret;
}

int
_gnutls_compression_get_mem_level (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->mem_level);
  return ret;
}

int
_gnutls_compression_get_comp_level (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->comp_level);
  return ret;
}

/* returns the gnutls internal ID of the TLS compression
 * method num
 */
gnutls_compression_method_t
_gnutls_compression_get_id (int num)
{
  gnutls_compression_method_t ret = -1;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP_NUM (ret = p->id);

  return ret;
}

int
_gnutls_compression_is_ok (gnutls_compression_method_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->id);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}



/* For compression  */

#define MIN_PRIVATE_COMP_ALGO 0xEF

/* returns the TLS numbers of the compression methods we support
 */
#define SUPPORTED_COMPRESSION_METHODS session->internals.priorities.compression.algorithms
int
_gnutls_supported_compression_methods (gnutls_session_t session,
				       uint8_t ** comp)
{
  unsigned int i, j;

  *comp = gnutls_malloc (sizeof (uint8_t) * SUPPORTED_COMPRESSION_METHODS);
  if (*comp == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  for (i = j = 0; i < SUPPORTED_COMPRESSION_METHODS; i++)
    {
      int tmp =
	_gnutls_compression_get_num (session->internals.
				     priorities.compression.priority[i]);

      /* remove private compression algorithms, if requested.
       */
      if (tmp == -1 || (tmp >= MIN_PRIVATE_COMP_ALGO &&
			session->internals.enable_private == 0))
	{
	  gnutls_assert ();
	  continue;
	}

      (*comp)[j] = (uint8_t) tmp;
      j++;
    }

  if (j == 0)
    {
      gnutls_assert ();
      gnutls_free (*comp);
      *comp = NULL;
      return GNUTLS_E_NO_COMPRESSION_ALGORITHMS;
    }
  return j;
}
