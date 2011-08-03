/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

#include <gnutls_int.h>
#include <algorithms.h>
#include <gnutls_errors.h>
#include <x509/common.h>


/* TLS Versions */

typedef struct
{
  const char *name;
  gnutls_protocol_t id;         /* gnutls internal version number */
  int major;                    /* defined by the protocol */
  int minor;                    /* defined by the protocol */
  transport_t transport;	/* Type of transport, stream or datagram */
  int supported;                /* 0 not supported, > 0 is supported */
} gnutls_version_entry;

static const gnutls_version_entry sup_versions[] = {
  {"SSL3.0", GNUTLS_SSL3, 3, 0, GNUTLS_STREAM, 1},
  {"TLS1.0", GNUTLS_TLS1, 3, 1, GNUTLS_STREAM, 1},
  {"TLS1.1", GNUTLS_TLS1_1, 3, 2, GNUTLS_STREAM, 1},
  {"TLS1.2", GNUTLS_TLS1_2, 3, 3, GNUTLS_STREAM, 1},
  {"DTLS1.0", GNUTLS_DTLS1_0, 254, 255, GNUTLS_DGRAM, 1}, /* 1.1 over datagram */
  {0, 0, 0, 0, 0}
};

#define GNUTLS_VERSION_LOOP(b) \
        const gnutls_version_entry *p; \
                for(p = sup_versions; p->name != NULL; p++) { b ; }

#define GNUTLS_VERSION_ALG_LOOP(a) \
	GNUTLS_VERSION_LOOP( if(p->id == version) { a; break; })

/* Version */
int
_gnutls_version_priority (gnutls_session_t session, gnutls_protocol_t version)
{                               /* actually returns the priority */
  unsigned int i;

  for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
    {
      if (session->internals.priorities.protocol.priority[i] == version)
        return i;
    }
  return -1;
}

gnutls_protocol_t
_gnutls_version_lowest (gnutls_session_t session)
{                               /* returns the lowest version supported */
  unsigned int i, min = 0xff;
  gnutls_protocol_t cur_prot;

  for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
    {
      cur_prot = session->internals.priorities.protocol.priority[i];

      if (cur_prot < min && _gnutls_version_is_supported(session, cur_prot))
	min = cur_prot;
    }

  if (min == 0xff)
    return GNUTLS_VERSION_UNKNOWN;      /* unknown version */

  return min;
}

gnutls_protocol_t
_gnutls_version_max (gnutls_session_t session)
{                               /* returns the maximum version supported */
  unsigned int i, max = 0x00;
  gnutls_protocol_t cur_prot;

  for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
    {
      cur_prot = session->internals.priorities.protocol.priority[i];

      if (cur_prot > max && _gnutls_version_is_supported(session, cur_prot))
	max = cur_prot;
    }

  if (max == 0x00)
    return GNUTLS_VERSION_UNKNOWN;      /* unknown version */

  return max;
}


/**
 * gnutls_protocol_get_name:
 * @version: is a (gnutls) version number
 *
 * Convert a #gnutls_protocol_t value to a string.
 *
 * Returns: a string that contains the name of the specified TLS
 *   version (e.g., "TLS1.0"), or %NULL.
 **/
const char *
gnutls_protocol_get_name (gnutls_protocol_t version)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_VERSION_ALG_LOOP (ret = p->name);
  return ret;
}

/**
 * gnutls_protocol_get_id:
 * @name: is a protocol name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified protocol, or
 * %GNUTLS_VERSION_UNKNOWN on error.
 **/
gnutls_protocol_t
gnutls_protocol_get_id (const char *name)
{
  gnutls_protocol_t ret = GNUTLS_VERSION_UNKNOWN;

  GNUTLS_VERSION_LOOP (
    if (strcasecmp (p->name, name) == 0) 
      {
        ret = p->id;
        break;
      }
  );

  return ret;
}

/**
 * gnutls_protocol_list:
 *
 * Get a list of supported protocols, e.g. SSL 3.0, TLS 1.0 etc.
 *
 * This function is not threat safe.
 *
 * Returns: a (0)-terminated list of #gnutls_protocol_t integers
 * indicating the available protocols.
 *
 **/
const gnutls_protocol_t *
gnutls_protocol_list (void)
{
static gnutls_protocol_t supported_protocols[MAX_ALGOS] = {0};

  if (supported_protocols[0] == 0)
    {
      int i = 0;

      GNUTLS_VERSION_LOOP (supported_protocols[i++]=p->id);
      supported_protocols[i++]=0;
    }

  return supported_protocols;
}

int
_gnutls_version_get_minor (gnutls_protocol_t version)
{
  int ret = -1;

  GNUTLS_VERSION_ALG_LOOP (ret = p->minor);
  return ret;
}

gnutls_protocol_t
_gnutls_version_get (int major, int minor)
{
  int ret = -1;

  GNUTLS_VERSION_LOOP (if ((p->major == major) && (p->minor == minor))
                       ret = p->id);
  return ret;
}

int
_gnutls_version_get_major (gnutls_protocol_t version)
{
  int ret = -1;

  GNUTLS_VERSION_ALG_LOOP (ret = p->major);
  return ret;
}

/* Version Functions */

int
_gnutls_version_is_supported (gnutls_session_t session,
                              const gnutls_protocol_t version)
{
  int ret = 0;

  GNUTLS_VERSION_ALG_LOOP (ret = p->supported && p->transport == session->internals.transport);

  if (ret == 0)
    return 0;

  if (_gnutls_version_priority (session, version) < 0)
    return 0;                   /* disabled by the user */
  else
    return 1;
}


/* This function determines if the version specified has a
   cipher-suite selected PRF hash function instead of the old
   hardcoded MD5+SHA1. */
int
_gnutls_version_has_selectable_prf (gnutls_protocol_t version)
{
  switch (version)
    {
    case GNUTLS_DTLS1_0:
    case GNUTLS_TLS1_1:
    case GNUTLS_TLS1_0:
    case GNUTLS_SSL3:
      return 0;
    default:
      return 1;
    }
}

/* This function determines if the version specified has selectable
   signature/hash functions for certificate authentification. */
int
_gnutls_version_has_selectable_sighash (gnutls_protocol_t version)
{
  switch (version)
    {
    case GNUTLS_DTLS1_0:
    case GNUTLS_TLS1_1:
    case GNUTLS_TLS1_0:
    case GNUTLS_SSL3:
      return 0;
    default:
      return 1;
    }
}

/* This function determines if the version specified has support for
   TLS extensions. */
int
_gnutls_version_has_extensions (gnutls_protocol_t version)
{
  switch (version)
    {
    case GNUTLS_SSL3:
      return 0;
    default:
      /* Versions after TLS 1.0 are required to handle extensions.
       * SSL 3.0 also required extensions to be ignored, but
       * some earlier draft didn't.
       */
      return 1;
    }
}

/* This function determines if the version specified has explicit IVs
   (for CBC attack prevention). */
int
_gnutls_version_has_explicit_iv (gnutls_protocol_t version)
{
  switch (version)
    {
    case GNUTLS_TLS1_0:
    case GNUTLS_SSL3:
      return 0;
    default:
      /* All versions after TLS 1.1 have explicit IV */
      return 1;
    }
}

