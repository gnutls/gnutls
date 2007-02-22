/*
 * Copyright (C) 2006, 2007 Free Software Foundation
 * Author: Simon Josefsson, Howard Chu
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "utils.h"

static char pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDsDCCAxmgAwIBAgIQbIPmN4vrzAUgFkI4ZMRqADANBgkqhkiG9w0BAQQFADCB\n"
  "zDEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy\n"
  "dXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9y\n"
  "eS9SUEEgSW5jb3JwLiBCeSBSZWYuLExJQUIuTFREKGMpOTgxSDBGBgNVBAMTP1Zl\n"
  "cmlTaWduIENsYXNzIDEgQ0EgSW5kaXZpZHVhbCBTdWJzY3JpYmVyLVBlcnNvbmEg\n"
  "Tm90IFZhbGlkYXRlZDAeFw0wMDEwMjcwMDAwMDBaFw0wMDEyMjYyMzU5NTlaMIIB\n"
  "AzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy\n"
  "dXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9y\n"
  "eS9SUEEgSW5jb3JwLiBieSBSZWYuLExJQUIuTFREKGMpOTgxHjAcBgNVBAsTFVBl\n"
  "cnNvbmEgTm90IFZhbGlkYXRlZDEmMCQGA1UECxMdRGlnaXRhbCBJRCBDbGFzcyAx\n"
  "IC0gTmV0c2NhcGUxGDAWBgNVBAMUD1NpbW9uIEpvc2Vmc3NvbjEdMBsGCSqGSIb3\n"
  "DQEJARYOc2pAZXh0dW5kby5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAvODS\n"
  "FsL+6SSlUMSkIQ4UHg8IVNVtjz4+L8k+32FxvOryhHcRL+d0WsRpJ9tkGk9zB9cJ\n"
  "C/gyWYduqbOppJDoHQIDAQABo4GcMIGZMAkGA1UdEwQCMAAwRAYDVR0gBD0wOzA5\n"
  "BgtghkgBhvhFAQcBCDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy52ZXJpc2ln\n"
  "bi5jb20vcnBhMBEGCWCGSAGG+EIBAQQEAwIHgDAzBgNVHR8ELDAqMCigJqAkhiJo\n"
  "dHRwOi8vY3JsLnZlcmlzaWduLmNvbS9jbGFzczEuY3JsMA0GCSqGSIb3DQEBBAUA\n"
  "A4GBACYWq3ggfSSQSSsitfj2nA01ZCKOmL07M2snEX+wmua7CIyLILjBpYEu8yIe\n"
  "FmItA9OwCXqOzJuMtRif5v5Wj2BN/ndYFA5pnMw+QkiXsy3anoJLJvkDyhV5w6sn\n"
  "jwsxQYobNHpC0mjQRdIZFzShTO/5Gt1yNs3wlZsw4YTv97u2\n"
  "-----END CERTIFICATE-----\n";

void print_dn (gnutls_x509_dn_t dn)
{
  int i, j, ret = 0;
  gnutls_x509_ava_st ava;

  for (i = 0; ret == 0; i++)
    for (j = 0; ret == 0; j++)
      {
	ret = gnutls_x509_dn_get_rdn_ava(dn, i, j, &ava);
	if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
	  {
	    if (j > 0)
	      {
		j = 0;
		ret = 0;
	      }
	    break;
	  }
	if (ret < 0)
	  fail ("get_rdn_ava %d\n", ret);
	printf("dn[%d][%d] OID=%.*s\n\tDATA=%.*s\n", i, j,
	       ava.oid.size, ava.oid.data,
	       ava.value.size, ava.value.data);
      }
}

void
doit (void)
{
  int ret;
  gnutls_datum_t derCert = { pem, sizeof(pem) };
  gnutls_x509_crt_t cert;
  gnutls_x509_dn_t xdn;

  ret = gnutls_global_init ();
  if (ret < 0)
    fail ("init %d\n", ret);

  ret = gnutls_x509_crt_init (&cert);
  if (ret < 0)
    fail ("crt_init %d\n", ret);

  ret = gnutls_x509_crt_import (cert, &derCert, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    fail ("crt_import %d\n", ret);

  ret = gnutls_x509_crt_get_issuer(cert, &xdn);
  if (ret < 0)
    fail ("get_subject %d\n", ret);

  printf ("Issuer:\n");
  print_dn (xdn);

  ret = gnutls_x509_crt_get_subject(cert, &xdn);
  if (ret < 0)
    fail ("get_subject %d\n", ret);

  printf ("Subject:\n");
  print_dn (xdn);

  success ("done\n");

  gnutls_x509_crt_deinit (cert);
  gnutls_global_deinit ();
}
