/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2008, 2009, 2010
 * Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* Functions that relate to the TLS hello extension parsing.
 * Hello extensions are packets appended in the TLS hello packet, and
 * allow for extra functionality.
 */

#include "gnutls_int.h"
#include "gnutls_extensions.h"
#include "gnutls_errors.h"
#include "ext_max_record.h"
#include <ext_cert_type.h>
#include <ext_server_name.h>
#include <ext_oprfi.h>
#include <ext_srp.h>
#include <ext_session_ticket.h>
#include <ext_safe_renegotiation.h>
#include <ext_signature.h>
#include <ext_safe_renegotiation.h>
#include <gnutls_num.h>

typedef struct
{
  const char *name;
  uint16_t type;
  gnutls_ext_parse_type_t parse_type;

  /* this function must return 0 when Not Applicable
   * size of extension data if ok
   * < 0 on other error.
   */
  gnutls_ext_recv_func recv_func;

  /* this function must return 0 when Not Applicable
   * size of extension data if ok
   * GNUTLS_E_INT_RET_0 if extension data size is zero
   * < 0 on other error.
   */
  gnutls_ext_send_func send_func;
} gnutls_extension_entry;

static size_t extfunc_size = 0;
static gnutls_extension_entry *extfunc = NULL;

static gnutls_ext_recv_func
_gnutls_ext_func_recv (uint16_t type, gnutls_ext_parse_type_t parse_type)
{
  size_t i;

  for (i = 0; i < extfunc_size; i++)
    if (extfunc[i].type == type)
      if (parse_type == GNUTLS_EXT_ANY || extfunc[i].parse_type == parse_type)
	return extfunc[i].recv_func;

  return NULL;
}

static const char *
_gnutls_extension_get_name (uint16_t type)
{
  size_t i;

  for (i = 0; i < extfunc_size; i++)
    if (extfunc[i].type == type)
      return extfunc[i].name;

  return NULL;
}

/* Checks if the extension we just received is one of the 
 * requested ones. Otherwise it's a fatal error.
 */
static int
_gnutls_extension_list_check (gnutls_session_t session, uint16_t type)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      int i;

      for (i = 0; i < session->internals.extensions_sent_size; i++)
	{
	  if (type == session->internals.extensions_sent[i])
	    return 0;		/* ok found */
	}

      return GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION;
    }

  return 0;
}

int
_gnutls_parse_extensions (gnutls_session_t session,
			  gnutls_ext_parse_type_t parse_type,
			  const opaque * data, int data_size)
{
  int next, ret;
  int pos = 0;
  uint16_t type;
  const opaque *sdata;
  gnutls_ext_recv_func ext_recv;
  uint16_t size;

#ifdef DEBUG
  int i;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    for (i = 0; i < session->internals.extensions_sent_size; i++)
      {
	_gnutls_debug_log ("EXT[%d]: expecting extension '%s'\n",
			   session,
			   _gnutls_extension_get_name
			   (session->internals.extensions_sent[i]));
      }
#endif

  DECR_LENGTH_RET (data_size, 2, 0);
  next = _gnutls_read_uint16 (data);
  pos += 2;

  DECR_LENGTH_RET (data_size, next, 0);

  do
    {
      DECR_LENGTH_RET (next, 2, 0);
      type = _gnutls_read_uint16 (&data[pos]);
      pos += 2;

      _gnutls_debug_log ("EXT[%p]: Found extension '%s/%d'\n", session,
			 _gnutls_extension_get_name (type), type);

      if ((ret = _gnutls_extension_list_check (session, type)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      DECR_LENGTH_RET (next, 2, 0);
      size = _gnutls_read_uint16 (&data[pos]);
      pos += 2;

      DECR_LENGTH_RET (next, size, 0);
      sdata = &data[pos];
      pos += size;

      ext_recv = _gnutls_ext_func_recv (type, parse_type);
      if (ext_recv == NULL)
	continue;


      if ((ret = ext_recv (session, sdata, size)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

    }
  while (next > 2);

  return 0;

}

/* Adds the extension we want to send in the extensions list.
 * This list is used to check whether the (later) received
 * extensions are the ones we requested.
 */
void
_gnutls_extension_list_add (gnutls_session_t session, uint16_t type)
{

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      if (session->internals.extensions_sent_size < MAX_EXT_TYPES)
	{
	  session->internals.extensions_sent[session->internals.
					     extensions_sent_size] = type;
	  session->internals.extensions_sent_size++;
	}
      else
	{
	  _gnutls_debug_log ("extensions: Increase MAX_EXT_TYPES\n");
	}
    }
}

int
_gnutls_gen_extensions (gnutls_session_t session, opaque * data,
			size_t data_size, gnutls_ext_parse_type_t parse_type)
{
  int size;
  uint16_t pos = 0;
  opaque *sdata;
  size_t sdata_size;
  size_t i;

  if (data_size < 2)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* allocate enough data for each extension.
   */
  sdata_size = data_size;
  sdata = gnutls_malloc (sdata_size);
  if (sdata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  pos += 2;
  for (i = 0; i < extfunc_size; i++)
    {
      gnutls_extension_entry *p = &extfunc[i];

      if (p->send_func == NULL)
	continue;

      if (parse_type != GNUTLS_EXT_ANY && p->parse_type != parse_type)
	continue;

      size = p->send_func (session, sdata, sdata_size);
      if (size > 0 || size == GNUTLS_E_INT_RET_0)
	{
	  if (size == GNUTLS_E_INT_RET_0)
	    size = 0;

	  if (data_size < pos + (size_t) size + 4)
	    {
	      gnutls_assert ();
	      gnutls_free (sdata);
	      return GNUTLS_E_INTERNAL_ERROR;
	    }

	  /* write extension type */
	  _gnutls_write_uint16 (p->type, &data[pos]);
	  pos += 2;

	  /* write size */
	  _gnutls_write_uint16 (size, &data[pos]);
	  pos += 2;

	  memcpy (&data[pos], sdata, size);
	  pos += size;

	  /* add this extension to the extension list
	   */
	  _gnutls_extension_list_add (session, p->type);

	  _gnutls_debug_log ("EXT[%p]: Sending extension %s\n",
			     session, p->name);
	}
      else if (size < 0)
	{
	  gnutls_assert ();
	  gnutls_free (sdata);
	  return size;
	}
    }

  size = pos;
  pos -= 2;			/* remove the size of the size header! */

  _gnutls_write_uint16 (pos, data);

  if (size == 2)
    {				/* empty */
      size = 0;
    }

  gnutls_free (sdata);
  return size;

}

int
_gnutls_ext_init (void)
{
  int ret;

  ret = gnutls_ext_register (GNUTLS_EXTENSION_MAX_RECORD_SIZE,
			     "MAX_RECORD_SIZE",
			     GNUTLS_EXT_TLS,
			     _gnutls_max_record_recv_params,
			     _gnutls_max_record_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;

  ret = gnutls_ext_register (GNUTLS_EXTENSION_CERT_TYPE,
			     "CERT_TYPE",
			     GNUTLS_EXT_TLS,
			     _gnutls_cert_type_recv_params,
			     _gnutls_cert_type_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;

  ret = gnutls_ext_register (GNUTLS_EXTENSION_SERVER_NAME,
			     "SERVER_NAME",
			     GNUTLS_EXT_APPLICATION,
			     _gnutls_server_name_recv_params,
			     _gnutls_server_name_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;

  ret = gnutls_ext_register (GNUTLS_EXTENSION_SAFE_RENEGOTIATION,
			     "SAFE_RENEGOTIATION",
			     GNUTLS_EXT_MANDATORY,
			     _gnutls_safe_renegotiation_recv_params,
			     _gnutls_safe_renegotiation_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;

#ifdef ENABLE_OPRFI
  ret = gnutls_ext_register (GNUTLS_EXTENSION_OPAQUE_PRF_INPUT,
			     "OPAQUE_PRF_INPUT",
			     GNUTLS_EXT_TLS,
			     _gnutls_oprfi_recv_params,
			     _gnutls_oprfi_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;
#endif

#ifdef ENABLE_SRP
  ret = gnutls_ext_register (GNUTLS_EXTENSION_SRP,
			     "SRP",
			     GNUTLS_EXT_TLS,
			     _gnutls_srp_recv_params,
			     _gnutls_srp_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;
#endif

#ifdef ENABLE_SESSION_TICKET
  ret = gnutls_ext_register (GNUTLS_EXTENSION_SESSION_TICKET,
			     "SESSION_TICKET",
			     GNUTLS_EXT_TLS,
			     _gnutls_session_ticket_recv_params,
			     _gnutls_session_ticket_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;
#endif

  ret = gnutls_ext_register (GNUTLS_EXTENSION_SIGNATURE_ALGORITHMS,
			     "SIGNATURE_ALGORITHMS",
			     GNUTLS_EXT_TLS,
			     _gnutls_signature_algorithm_recv_params,
			     _gnutls_signature_algorithm_send_params);
  if (ret != GNUTLS_E_SUCCESS)
    return ret;

  return GNUTLS_E_SUCCESS;
}

void
_gnutls_ext_deinit (void)
{
  gnutls_free (extfunc);
  extfunc = NULL;
  extfunc_size = 0;
}

/**
 * gnutls_ext_register:
 * @type: the 16-bit integer referring to the extension type
 * @name: human printable name of the extension used for debugging
 * @parse_type: either #GNUTLS_EXT_TLS or %GNUTLS_EXT_APPLICATION.
 * @recv_func: a function to receive extension data
 * @send_func: a function to send extension data
 *
 * This function is used to register a new TLS extension handler.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 2.6.0
 **/
int
gnutls_ext_register (int type,
		     const char *name,
		     gnutls_ext_parse_type_t parse_type,
		     gnutls_ext_recv_func recv_func,
		     gnutls_ext_send_func send_func)
{
  gnutls_extension_entry *p;

  p = gnutls_realloc (extfunc, sizeof (*extfunc) * (extfunc_size + 1));
  if (!p)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  extfunc = p;

  extfunc[extfunc_size].type = type;
  extfunc[extfunc_size].name = name;
  extfunc[extfunc_size].parse_type = parse_type;
  extfunc[extfunc_size].recv_func = recv_func;
  extfunc[extfunc_size].send_func = send_func;

  extfunc_size++;

  return GNUTLS_E_SUCCESS;
}
