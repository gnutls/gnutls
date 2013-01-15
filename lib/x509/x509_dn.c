/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 * Copyright (C) 2005 Andrew Suffield <asuffield@debian.org>
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* This file contains functions to handle X.509 certificate generation.
 */

#include <gnutls_int.h>

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>

enum { CRQ, CRT };

static
int dn_attr_crt_set( unsigned crt_type, void* crt, const char *attr, unsigned attr_len, 
                     const char *value, unsigned value_len)
{
  char _oid[MAX_OID_SIZE];
  const char *oid;
  int ret;
  
  if (value_len == 0 || attr_len == 0)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
    
  if (isdigit(attr[0]) != 0)
    {
      if (attr_len >= sizeof(_oid))
        return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
        
      memcpy(_oid, attr, attr_len);
      _oid[attr_len] = 0;
      
      oid = _oid;

      if (gnutls_x509_dn_oid_known(oid) == 0)
        {
          _gnutls_debug_log("Unknown OID: '%s'\n", oid);
          return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
        }
    }
  else
    {
      oid = _gnutls_ldap_string_to_oid(attr, attr_len);
    }

  if (oid == NULL)
    {
      _gnutls_debug_log("Unknown DN attribute: '%.*s'\n", attr_len, attr);
      return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
    }
    
  if (value[0] == '#')
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
  
  ret = GNUTLS_E_INTERNAL_ERROR;
  if (crt_type == CRT)
    ret = gnutls_x509_crt_set_dn_by_oid(crt, oid, 0, value, value_len);
  else if (crt_type == CRQ)
    ret = gnutls_x509_crq_set_dn_by_oid(crt, oid, 0, value, value_len);
  if (ret < 0)
    return gnutls_assert_val(ret);
    
  return 0;
}

static int
crt_set_dn (unsigned crt_type, void* crt, const char *dn, const char** err)
{
const char *p = dn;
const char *name_start;
const char *name_end;
const char *value_start;
const char *value_end;
unsigned name_len;
unsigned value_len;
int ret;

  if (crt == NULL || dn == NULL)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
    
  /* For each element */
  while (*p != 0 && *p != '\n')
    {
      /* Skip leading whitespace */
      while (isspace(*p))
        p++;
      
      if (err)
        *err = p;

      /* Attribute name */
      name_start = p;
      while (*p != '=' && *p != 0)
        p++;
      name_end = p;

      /* Whitespace */
      while (isspace(*p))
        p++;

      /* Equals sign */
      if (*p != '=')
        {
          *err = p;
          return GNUTLS_E_PARSING_ERROR;
        }
      p++;

      /* Whitespace */
      while (isspace(*p))
        p++;

      /* Attribute value */
      value_start = p;
      while (*p != 0 && (*p != ',' || (*p == ',' && *(p-1) == '\\')) && *p != '\n')
        p++;
      value_end = p;
      while (value_end > value_start && isspace(value_end[-1]))
        value_end--;

      /* Comma, or the end of the string */
      if (*p)
        p++;

      name_len = name_end - name_start;
      value_len = value_end - value_start;

      ret = dn_attr_crt_set(crt_type, crt, name_start, name_len, value_start, value_len);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }
    
  return 0;
}


/**
 * gnutls_x509_crt_set_dn:
 * @crt: a certificate of type #gnutls_x509_crt_t
 * @dn: a comma separated DN string (RFC4514)
 * @err: indicates the error position (if any)
 *
 * This function will set the DN on the provided certificate.
 * The input string should be plain ASCII or UTF-8 encoded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_set_dn (gnutls_x509_crt_t crt, const char *dn, const char** err)
{
  return crt_set_dn( CRT, crt, dn, err);
}

/**
 * gnutls_x509_crq_set_dn:
 * @crq: a certificate of type #gnutls_x509_crq_t
 * @dn: a comma separated DN string (RFC4514)
 * @err: indicates the error position (if any)
 *
 * This function will set the DN on the provided certificate.
 * The input string should be plain ASCII or UTF-8 encoded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crq_set_dn (gnutls_x509_crq_t crq, const char *dn, const char** err)
{
  return crt_set_dn( CRQ, crq, dn, err);
}
