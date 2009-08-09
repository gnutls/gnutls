/*
 * Copyright (C) 2009 Free Software Foundation
 *
 * Author: Jonathan Bastien-Filiatrault
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

#include "gnutls_mbuffers.h"
#include "gnutls_errors.h"

/* Here be mbuffers */

void
_gnutls_mbuffer_init (mbuffer_head_st *buf)
{
  buf->head = NULL;
  buf->tail = &buf->head;

  buf->length = 0;
  buf->byte_length = 0;
}

void
_gnutls_mbuffer_clear (mbuffer_head_st *buf)
{
  mbuffer_st *bufel, *next;

  for(bufel = buf->head; bufel != NULL; bufel = next)
    {
      next = bufel->next;
      gnutls_free(bufel->msg.data);
      gnutls_free(bufel);
    }

  _gnutls_mbuffer_init (buf);
}

int
_gnutls_mbuffer_enqueue (mbuffer_head_st *buf, const gnutls_datum_t *msg)
{
  mbuffer_st *bufel = gnutls_malloc (sizeof (mbuffer_st));

  if (bufel == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  bufel->next = NULL;
  bufel->mark = 0;

  bufel->msg = *msg;

  buf->length++;
  buf->byte_length += msg->size;

  *(buf->tail) = bufel;
  buf->tail = &bufel->next;

  return 0;
}

int
_gnutls_mbuffer_enqueue_copy (mbuffer_head_st *buf, const gnutls_datum_t *msg)
{
  gnutls_datum_t msg_copy;

  msg_copy.data = gnutls_malloc (msg->size);

  if (msg_copy.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  msg_copy.size = msg->size;
  memcpy (msg_copy.data, msg->data, msg_copy.size);

  return _gnutls_mbuffer_enqueue (buf, &msg_copy);
}

void
_gnutls_mbuffer_get_head (mbuffer_head_st *buf, gnutls_datum_t *msg)
{
  mbuffer_st *bufel;

  if (buf->head)
    {
      bufel = buf->head;
      msg->data = bufel->msg.data + bufel->mark;
      msg->size = bufel->msg.size - bufel->mark;
    }
  else
    {
      msg->data = NULL;
      msg->size = 0;
    }
}

static inline void
remove_front (mbuffer_head_st *buf)
{
  mbuffer_st *bufel;

  if(!buf->head)
    return;

  bufel = buf->head;
  buf->head = bufel->next;

  buf->byte_length -= (bufel->msg.size - bufel->mark);
  buf->length -= 1;
  gnutls_free(bufel->msg.data);
  gnutls_free(bufel);

  if (!buf->head)
    buf->tail = &buf->head;
}

int
_gnutls_mbuffer_remove_bytes (mbuffer_head_st *buf, size_t bytes)
{
  size_t left = bytes;
  mbuffer_st *bufel, *next;

  if (bytes > buf->byte_length)
    return -1;

  for (bufel = buf->head; bufel != NULL && left > 0; bufel = next)
    {
      next = bufel->next;

      if(left >= (bufel->msg.size - bufel->mark))
	{
	  left -= (bufel->msg.size - bufel->mark);
	  remove_front(buf);
	}
      else
	{
	  bufel->mark += left;
	  buf->byte_length -= left;
	  left = 0;
	}
    }

  return 0;
}
