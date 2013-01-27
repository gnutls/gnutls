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
#include <gnutls/xssl.h>
#include <auth/cert.h>

#include <xssl.h>

/**
 * xssl_cred_deinit:
 * @cred: is a #xssl_cred_t structure.
 *
 * This function deinitializes a #xssl_cred_t structure.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
void xssl_cred_deinit (xssl_cred_t cred)
{
  if (cred->xcred)
    gnutls_certificate_free_credentials(cred->xcred);
  gnutls_free(cred);
}


static int
_verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  xssl_t sb;
  int ret, type;
  const char *hostname = NULL;
  const char *service = NULL;
  const char *tofu_file = NULL;

  sb = gnutls_session_get_ptr(session);
  if (sb == NULL)
    return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

  if (sb->cred == NULL)
    return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

  if (sb->server_name[0] != 0)
    hostname = sb->server_name;

  if (sb->service_name[0] != 0)
    service = sb->service_name;

  if (sb->cred->tofu_file[0] != 0)
    tofu_file = sb->cred->tofu_file;

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  sb->vstatus = 0;
  if (sb->cred->vflags & GNUTLS_VMETHOD_SYSTEM_CAS || sb->cred->vflags & GNUTLS_VMETHOD_GIVEN_CAS)
    {
      ret = gnutls_certificate_verify_peers3 (session, hostname, &status);
      if (ret < 0)
        return gnutls_assert_val(GNUTLS_E_AUTH_ERROR);
      
      sb->vstatus = status;

      if (status != 0) /* Certificate is not trusted */
        return gnutls_assert_val(GNUTLS_E_AUTH_ERROR);
    }

  if (hostname && sb->cred->vflags & GNUTLS_VMETHOD_TOFU)
    {
      const gnutls_datum_t *cert_list;
      unsigned int cert_list_size;

      type = gnutls_certificate_type_get (session);

      /* Do SSH verification */
      cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
      if (cert_list == NULL)
        { 
          sb->vstatus |= GNUTLS_CERT_INVALID;
          return gnutls_assert_val(GNUTLS_E_AUTH_ERROR);
        }

      /* service may be obtained alternatively using getservbyport() */
      ret = gnutls_verify_stored_pubkey(tofu_file, NULL, hostname, service, 
                                    type, &cert_list[0], 0);
      if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND)
        {
          /* host was not seen before. Store the key */
          gnutls_store_pubkey(tofu_file, NULL, hostname, service, 
                              type, &cert_list[0], 0, 0);
        }
      else if (ret == GNUTLS_E_CERTIFICATE_KEY_MISMATCH)
        {
          sb->vstatus |= GNUTLS_CERT_MISMATCH;
          return gnutls_assert_val(GNUTLS_E_AUTH_ERROR);
        }
      else if (ret < 0)
        {
          sb->vstatus |= GNUTLS_CERT_INVALID;
          return gnutls_assert_val(GNUTLS_E_AUTH_ERROR);
        }
    }
  
  /* notify gnutls to continue handshake normally */
  return 0;
}

/**
 * xssl_cred_init:
 * @c: is a pointer to #xssl_cred_t structure.
 * @vflags: the requested peer verification methods
 * @aux: Auxilary data to input any required CA certificate etc.
 * @aux_size: the number of the auxillary data provided
 *
 * This function initializes X.509 certificates in 
 * a #xssl_cred_t structure.
 *
 * The @ca_file and @crl_file are required only if @vflags includes
 * %GNUTLS_VMETHOD_GIVEN_CAS. The @tofu_file may be set if 
 * %GNUTLS_VMETHOD_TOFU is specified.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
int xssl_cred_init (xssl_cred_t *c, unsigned vflags, 
                             gnutls_cinput_st* aux,
                             unsigned aux_size)
{
int ret;
unsigned len, i;
xssl_cred_t cred;

  *c = gnutls_calloc(1, sizeof(*cred));
  if (*c == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  cred = *c;
  cred->vflags = vflags;

  if (cred->xcred == NULL)
    {
      ret = gnutls_certificate_allocate_credentials(&cred->xcred);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }
  
  if (vflags & GNUTLS_VMETHOD_SYSTEM_CAS)
    {
      ret = gnutls_certificate_set_x509_system_trust(cred->xcred);
      if (ret < 0)
        {
          gnutls_assert();
          goto fail1;
        }
    }

  for (i=0;i<aux_size;i++)
    {
      if (aux[i].contents == GNUTLS_CINPUT_KEYPAIR)
        {
          if (aux[i].type == GNUTLS_CINPUT_TYPE_FILE)
            ret = gnutls_certificate_set_x509_key_file(cred->xcred, aux[i].i1.file, aux[i].i2.file, aux[i].fmt);
          else if (aux[i].type == GNUTLS_CINPUT_TYPE_MEM)
            ret = gnutls_certificate_set_x509_key_mem(cred->xcred, &aux[i].i1.mem, &aux[i].i2.mem, aux[i].fmt);
          else if (aux[i].type == GNUTLS_CINPUT_TYPE_PIN_FUNC)
            {
              ret = 0;
              gnutls_certificate_set_pin_function(cred->xcred, aux[i].i1.pin_fn,
                                                  aux[i].i2.udata);
            }

          if (ret < 0)
            {
              gnutls_assert();
              goto fail1;
            }
        }
        
      if (aux[i].contents == GNUTLS_CINPUT_CAS && (vflags & GNUTLS_VMETHOD_GIVEN_CAS))
        {
          if (aux[i].type == GNUTLS_CINPUT_TYPE_FILE)
            ret = gnutls_certificate_set_x509_trust_file(cred->xcred, aux[i].i1.file, aux[i].fmt);
          else       
            ret = gnutls_certificate_set_x509_trust_mem(cred->xcred, &aux[i].i1.mem, aux[i].fmt);

          if (ret < 0)
            {
              gnutls_assert();
              goto fail1;
            }
        } 

      if (aux[i].contents == GNUTLS_CINPUT_CRLS && (vflags & GNUTLS_VMETHOD_GIVEN_CAS))
        {
          if (aux[i].type == GNUTLS_CINPUT_TYPE_FILE)
            ret = gnutls_certificate_set_x509_crl_file(cred->xcred, aux[i].i1.file, aux[i].fmt);
          else       
            ret = gnutls_certificate_set_x509_crl_mem(cred->xcred, &aux[i].i1.mem, aux[i].fmt);

          if (ret < 0)
            {
              gnutls_assert();
              goto fail1;
            }
        }

      if (aux[i].contents == GNUTLS_CINPUT_TOFU_DB && (vflags & GNUTLS_VMETHOD_TOFU))
        {
          if (aux[i].type == GNUTLS_CINPUT_TYPE_FILE)
            {
              len = strlen(aux[i].i1.file);
              if (len >= sizeof(cred->tofu_file))
                {
                  ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
                  goto fail1;
                }
              memcpy(cred->tofu_file, aux[i].i1.file, len+1);
            }
          else
            ret = GNUTLS_E_INVALID_REQUEST;

          if (ret < 0)
            {
              gnutls_assert();
              goto fail1;
            }
        }
    }
  
  gnutls_certificate_set_verify_function (cred->xcred, _verify_certificate_callback);

  return 0;
fail1:
  gnutls_certificate_free_credentials(cred->xcred);
  cred->xcred = NULL;
  gnutls_free(*c);

  return ret;
}

/**
 * xssl_sinit:
 * @isb: is a pointer to a #xssl_t structure.
 * @session: a GnuTLS session
 * @flags: should be zero or %GNUTLS_SBUF_WRITE_FLUSHES
 *
 * This function initializes a #xssl_t structure associated
 * with the provided session. If the flag %GNUTLS_SBUF_WRITE_FLUSHES
 * is set then xssl_queue() will flush when the maximum
 * data size for a record is reached.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
int xssl_sinit (xssl_t * isb, gnutls_session_t session,
                       unsigned int flags)
{
struct xssl_st* sb;

  sb = gnutls_calloc(1, sizeof(*sb));
  if (sb == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  _gnutls_buffer_init(&sb->buf);
  sb->session = session;
  sb->flags = flags;
  
  *isb = sb;
  
  return 0;
}

/**
 * xssl_client_init:
 * @isb: is a pointer to a #xssl_t structure.
 * @hostname: The name of the host to connect to
 * @service: The name of the host to connect to
 * @fd: a socket descriptor
 * @priority: A priority string to use (use %NULL for default)
 * @cred: A credentials structure
 * @status: An authentication failure status
 * @flags: should be zero or %GNUTLS_SBUF_WRITE_FLUSHES
 *
 * This function initializes a #xssl_t structure.
 * If the flag %GNUTLS_SBUF_WRITE_FLUSHES
 * is set then xssl_queue() will flush when the maximum
 * data size for a record is reached.
 *
 * If peer verification fails then %GNUTLS_E_AUTH_ERROR is returned.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
int xssl_client_init (xssl_t * isb, const char* hostname, 
                             const char* service,
                             gnutls_transport_ptr fd, 
                             const char* priority, xssl_cred_t cred,
                             unsigned int *status,
                             unsigned int flags)
{
struct xssl_st* sb;
gnutls_session_t session;
int ret;
unsigned len;

  ret = gnutls_init(&session, GNUTLS_CLIENT);
  if (ret < 0)
    return gnutls_assert_val(ret);

  sb = gnutls_calloc(1, sizeof(*sb));
  if (sb == NULL)
    {
      gnutls_deinit(session);
      ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
      goto fail1;
    }
  _gnutls_buffer_init(&sb->buf);
  sb->session = session;
  sb->flags = flags;
  sb->cred = cred;
  
  /* set session/handshake info 
   */
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  
  if (priority == NULL) priority = "NORMAL:%COMPAT";
  ret = gnutls_priority_set_direct(session, priority, NULL);
  if (ret < 0)
    {
      gnutls_assert();
      goto fail1;
    }
  
  if (cred->xcred)
    {
      ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred->xcred);
      if (ret < 0)
        {
          gnutls_assert();
          goto fail1;
        }
    }

  if (hostname)
    {
      len = strlen(hostname);
      
      if (len >= sizeof(sb->server_name))
        return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
      memcpy(sb->server_name, hostname, len+1);

      ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, len);
      if (ret < 0)
        {
          gnutls_assert();
          goto fail1;
        }
    }

  if (service)
    {
      len = strlen(service);
      
      if (len >= sizeof(sb->service_name))
        return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
      memcpy(sb->service_name, service, len+1);
    }

  gnutls_transport_set_ptr (session, fd);
  gnutls_session_set_ptr( session, sb);

  do
    {
      ret = gnutls_handshake(session);
    }
  while (ret < 0 && gnutls_error_is_fatal (ret) == 0);
  if (status) *status = sb->vstatus;

  if (ret < 0)
    {
      int ret2;
      do
        {
          ret2 = gnutls_alert_send_appropriate(sb->session, ret);
        }
      while (ret2 < 0 && gnutls_error_is_fatal(ret2) == 0);

      return gnutls_assert_val(ret);

      gnutls_assert();
      goto fail1;
    }
  
  *isb = sb;
  
  return 0;

fail1:
  if (sb)
    xssl_deinit(sb);
  
  return ret;
}

/**
 * xssl_server_init:
 * @isb: is a pointer to a #xssl_t structure.
 * @fd: a socket descriptor
 * @priority: A priority string to use (use %NULL for default)
 * @cred: A credentials structure
 * @status: An authentication failure status
 * @flags: should be zero or %GNUTLS_SBUF_WRITE_FLUSHES
 *
 * This function initializes a #xssl_t structure.
 * If the flag %GNUTLS_SBUF_WRITE_FLUSHES
 * is set then xssl_queue() will flush when the maximum
 * data size for a record is reached.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 *
 * Since: 3.1.7
 **/
int xssl_server_init (xssl_t * isb,
                             gnutls_transport_ptr fd, 
                             const char* priority, xssl_cred_t cred,
                             unsigned int *status,
                             unsigned int flags)
{
struct xssl_st* sb;
gnutls_session_t session;
int ret;

  ret = gnutls_init(&session, GNUTLS_SERVER);
  if (ret < 0)
    return gnutls_assert_val(ret);

  sb = gnutls_calloc(1, sizeof(*sb));
  if (sb == NULL)
    {
      gnutls_deinit(session);
      ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
      goto fail1;
    }
  _gnutls_buffer_init(&sb->buf);
  sb->session = session;
  sb->flags = flags;
  sb->cred = cred;
  
  /* set session/handshake info 
   */
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  
  if (priority == NULL) priority = "NORMAL:%COMPAT";
  ret = gnutls_priority_set_direct(session, priority, NULL);
  if (ret < 0)
    {
      gnutls_assert();
      goto fail1;
    }
  
  if (cred->xcred)
    {
      if (cred->xcred->ncerts == 0 && cred->xcred->get_cert_callback2 == NULL)
        {
          ret = gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);
          goto fail1;
        }
      
      ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred->xcred);
      if (ret < 0)
        {
          gnutls_assert();
          goto fail1;
        }
      
    }

  if (cred->vflags & GNUTLS_VMETHOD_GIVEN_CAS)
    gnutls_certificate_server_set_request( session, GNUTLS_CERT_REQUIRE);

  gnutls_transport_set_ptr( session, fd);
  gnutls_session_set_ptr( session, sb);

  do
    {
      ret = gnutls_handshake(session);
    }
  while (ret < 0 && gnutls_error_is_fatal (ret) == 0);
  if (status) *status = sb->vstatus;

  if (ret < 0)
    {
      int ret2;
      do
        {
          ret2 = gnutls_alert_send_appropriate(sb->session, ret);
        }
      while (ret2 < 0 && gnutls_error_is_fatal(ret2) == 0);

      return gnutls_assert_val(ret);

      gnutls_assert();
      goto fail1;
    }
  
  *isb = sb;
  
  return 0;

fail1:
  if (sb)
    xssl_deinit(sb);
  
  return ret;
}

/**
 * xssl_deinit:
 * @sb: is a #xssl_t structure.
 *
 * This function clears all buffers associated with the @sb
 * structure. The GnuTLS session associated with the structure
 * is left intact.
 *
 * Since: 3.1.7
 **/
void xssl_deinit(xssl_t sb)
{
  if (sb->session)
    {
      gnutls_bye(sb->session, GNUTLS_SHUT_WR);
      gnutls_deinit(sb->session);
    }
  _gnutls_buffer_clear(&sb->buf);
  gnutls_free(sb);
}

/**
 * xssl_write:
 * @sb: is a #xssl_t structure.
 * @data: contains the data to send
 * @data_size: is the length of the data
 *
 * This function is the buffered equivalent of gnutls_record_send().
 * Instead of sending the data immediately the data are buffered
 * until xssl_queue() is called, or if the flag %GNUTLS_SBUF_WRITE_FLUSHES
 * is set, until the number of bytes for a full record is reached.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes written is returned, otherwise
 *  an error code is returned.
 *
 * Since: 3.1.7
 **/
ssize_t xssl_write (xssl_t sb, const void *data,
                           size_t data_size)
{
int ret;
  
  ret = _gnutls_buffer_append_data(&sb->buf, data, data_size);
  if (ret < 0)
    return gnutls_assert_val(ret);
  
  while ((sb->flags & GNUTLS_SBUF_WRITE_FLUSHES) && 
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
 * xssl_printf:
 * @sb: is a #xssl_t structure.
 * @fmt: printf-style format 
 *
 * This function allows writing to a %xssl_t using printf
 * style arguments.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes written is returned, otherwise
 *  an error code is returned.
 *
 * Since: 3.1.7
 **/
ssize_t xssl_printf (xssl_t sb, const char *fmt, ...)
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
  
  ret = xssl_write (sb, str, len);
  
  gnutls_free(str);

  return ret;
}

/**
 * xssl_flush:
 * @sb: is a #xssl_t structure.
 *
 * This function flushes the buffer @sb. All the data stored are transmitted.
 *
 * This function must only be used with blocking sockets.
 *
 * Returns: On success, the number of bytes sent, otherwise a negative error code.
 *
 * Since: 3.1.7
 **/
ssize_t xssl_flush (xssl_t sb)
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
 * xssl_read:
 * @sb: is a #xssl_t structure.
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
ssize_t xssl_read(xssl_t sb, void* data, size_t data_size)
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

/**
 * xssl_get_session:
 * @sb: is a #xssl_t structure.
 *
 * Returns: The associated session or %NULL.
 *
 * Since: 3.1.7
 **/
gnutls_session_t xssl_get_session(xssl_t sb)
{
  return sb->session;
}
