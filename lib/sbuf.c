/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The gnutls library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls/sbuf.h>

#include <sbuf.h>

/**
 * gnutls_init:
 * @isb: is a pointer to a #gnutls_sbuf_t structure.
 * @session: a GnuTLS session
 * @flags: should be zero or %GNUTLS_SBUF_QUEUE_FLUSHES
 *
 * This function initializes a #gnutls_sbuf_t structure associated
 * with the provided session. If the flag %GNUTLS_SBUF_QUEUE_FLUSHES
 * is set then gnutls_sbuf_queue() will flush when the maximum
 * data size for a record is reached.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
int gnutls_sbuf_init (gnutls_sbuf_t * isb, gnutls_session_t session,
                      unsigned int flags)
{
struct gnutls_sbuf_st* sb;

  sb = gnutls_malloc(sizeof(*sb));
  if (sb == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  _gnutls_buffer_init(&sb->buf);
  sb->session = session;
  sb->flags = flags;
  
  *isb = sb;
  
  return 0;
}

/**
 * gnutls_sbuf_deinit:
 * @sb: is a #gnutls_sbuf_t structure.
 *
 * This function clears all buffers associated with the @sb
 * structure. The GnuTLS session associated with the structure
 * is left intact.
 *
 * Since: 3.1.7
 **/
void gnutls_sbuf_deinit(gnutls_sbuf_t sb)
{
  _gnutls_buffer_clear(&sb->buf);
  gnutls_free(sb);
}

/**
 * gnutls_sbuf_write:
 * @sb: is a #gnutls_sbuf_t structure.
 * @data: contains the data to send
 * @data_size: is the length of the data
 *
 * This function is the buffered equivalent of gnutls_record_send().
 * Instead of sending the data immediately the data are buffered
 * until gnutls_sbuf_queue() is called, or if the flag %GNUTLS_SBUF_QUEUE_FLUSHES
 * is set, until the number of bytes for a full record is reached.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes written is returned, otherwise
 *  an error code is returned.
 *
 * Since: 3.1.7
 **/
ssize_t gnutls_sbuf_write (gnutls_sbuf_t sb, const void *data,
                           size_t data_size)
{
int ret;
  
  ret = _gnutls_buffer_append_data(&sb->buf, data, data_size);
  if (ret < 0)
    return gnutls_assert_val(ret);
  
  while ((sb->flags & GNUTLS_SBUF_QUEUE_FLUSHES) && 
       sb->buf.length >= MAX_RECORD_SEND_SIZE(sb->session))
    {
      do
        {
          ret = gnutls_record_send(sb->session, sb->buf.data, sb->buf.length);
        }
      while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
      if (ret < 0)
        return gnutls_assert_val(ret);

      sb->buf.data += ret;
      sb->buf.length -= ret;
    }
  
  return data_size;
}

/**
 * gnutls_sbuf_printf:
 * @sb: is a #gnutls_sbuf_t structure.
 * @fmt: printf-style format 
 *
 * This function allows writing to a %gnutls_sbuf_t using printf
 * style arguments.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes written is returned, otherwise
 *  an error code is returned.
 *
 * Since: 3.1.7
 **/
ssize_t gnutls_sbuf_printf (gnutls_sbuf_t sb, const char *fmt, ...)
{
int ret;
va_list args;
int len;
char* str;

  va_start(args, fmt);
  len = vasprintf(&str, fmt, args);
  va_end(args);
  
  if (len < 0 || !str)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
  
  ret = gnutls_sbuf_write (sb, str, len);
  
  gnutls_free(str);

  return ret;
}

/**
 * gnutls_sbuf_flush:
 * @sb: is a #gnutls_sbuf_t structure.
 *
 * This function flushes the buffer @sb. All the data stored are transmitted.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes sent, otherwise a negative error code.
 *
 * Since: 3.1.7
 **/
ssize_t gnutls_sbuf_flush (gnutls_sbuf_t sb)
{
int ret;
ssize_t total = 0;

  while(sb->buf.length > 0)
    {
      do
        {
          ret = gnutls_record_send(sb->session, sb->buf.data, sb->buf.length);
        }
      while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
      if (ret < 0)
        return gnutls_assert_val(ret);

      sb->buf.data += ret;
      sb->buf.length -= ret;
      total += ret;
    }

  return total;
}

/**
 * gnutls_sbuf_handshake:
 * @sb: is a #gnutls_sbuf_t structure.
 *
 * This function performs a handshake on the underlying session.
 * Only fatal errors are returned by this function.
 *
 * Returns: On success, zero is returned, otherwise a negative error code.
 *
 * Since: 3.1.7
 **/
int gnutls_sbuf_handshake(gnutls_sbuf_t sb)
{
int ret, ret2;

  do
    {
      ret = gnutls_handshake(sb->session);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  if (ret < 0)
    {
      do
        {
          ret2 = gnutls_alert_send_appropriate(sb->session, ret);
        }
      while (ret2 < 0 && gnutls_error_is_fatal(ret2) == 0);

      return gnutls_assert_val(ret);
    }
    
  return 0;
}

/**
 * gnutls_sbuf_read:
 * @sb: is a #gnutls_sbuf_t structure.
 * @data: the buffer that the data will be read into
 * @data_size: the number of requested bytes
 *
 * This function receives data from the underlying session.
 * Only fatal errors are returned by this function.
 *
 * Returns: The number of bytes received and zero on EOF (for stream
 * connections) or a negative error code.
 *
 * Since: 3.1.7
 **/
ssize_t gnutls_sbuf_read(gnutls_sbuf_t sb, void* data, size_t data_size)
{
int ret;

  do
    {
      ret = gnutls_record_recv(sb->session, data, data_size);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0)
    return gnutls_assert_val(ret);

  return 0;
}
