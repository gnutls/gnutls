/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

/* Work around problem reported in
   <http://permalink.gmane.org/gmane.comp.lib.gnulib.bugs/15755>.*/
#if GETTIMEOFDAY_CLOBBERS_LOCALTIME
#undef localtime
#endif

#include <getpass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/openpgp.h>
#include <time.h>
#include <common.h>

#define SU(x) (x!=NULL?x:"Unknown")

extern int verbose;

const char str_unknown[] = "(unknown)";

/* Hex encodes the given data.
 */
const char *
raw_to_string (const unsigned char *raw, size_t raw_size)
{
    static char buf[1024];
    size_t i;
    if (raw_size == 0)
        return "(empty)";

    if (raw_size * 3 + 1 >= sizeof (buf))
        return "(too large)";

    for (i = 0; i < raw_size; i++)
      {
          sprintf (&(buf[i * 3]), "%02X%s", raw[i],
                   (i == raw_size - 1) ? "" : ":");
      }
    buf[sizeof (buf) - 1] = '\0';

    return buf;
}

static void
print_x509_info_compact (gnutls_session_t session)
{
    gnutls_x509_crt_t crt;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0;
    int ret;
    gnutls_datum_t cinfo;

    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
    if (cert_list_size == 0)
      {
          fprintf (stderr, "No certificates found!\n");
          return;
      }

    gnutls_x509_crt_init (&crt);
    ret =
          gnutls_x509_crt_import (crt, &cert_list[0],
                                  GNUTLS_X509_FMT_DER);
    if (ret < 0)
      {
        fprintf (stderr, "Decoding error: %s\n",
                 gnutls_strerror (ret));
        return;
      }

    ret =
      gnutls_x509_crt_print (crt, GNUTLS_CRT_PRINT_COMPACT, &cinfo);
    if (ret == 0)
      {
        printf ("- X.509 cert: %s\n", cinfo.data);
        gnutls_free (cinfo.data);
      }

    gnutls_x509_crt_deinit (crt);
}

static void
print_x509_info (gnutls_session_t session, int flag, int print_cert)
{
    gnutls_x509_crt_t crt;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0, j;
    int ret;
    
    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
    if (cert_list_size == 0)
      {
          fprintf (stderr, "No certificates found!\n");
          return;
      }

    printf ("- Certificate type: X.509\n");
    printf ("- Got a certificate list of %d certificates.\n",
            cert_list_size);

    for (j = 0; j < cert_list_size; j++)
      {
          gnutls_datum_t cinfo;

          gnutls_x509_crt_init (&crt);
          ret =
              gnutls_x509_crt_import (crt, &cert_list[j],
                                      GNUTLS_X509_FMT_DER);
          if (ret < 0)
            {
                fprintf (stderr, "Decoding error: %s\n",
                         gnutls_strerror (ret));
                return;
            }

          printf ("- Certificate[%d] info:\n - ", j);
          if (flag == GNUTLS_CRT_PRINT_COMPACT && j > 0) flag = GNUTLS_CRT_PRINT_ONELINE;

          ret =
            gnutls_x509_crt_print (crt, flag, &cinfo);
          if (ret == 0)
            {
                printf ("%s\n", cinfo.data);
                gnutls_free (cinfo.data);
            }

          if (print_cert)
            {
                size_t size = 0;
                char *p = NULL;

                ret =
                    gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, p,
                                            &size);
                if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
                  {
                      p = malloc (size);
                      if (!p)
                        {
                            fprintf (stderr, "gnutls_malloc\n");
                            exit (1);
                        }

                      ret =
                          gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM,
                                                  p, &size);
                  }
                if (ret < 0)
                  {
                      fprintf (stderr, "Encoding error: %s\n",
                               gnutls_strerror (ret));
                      return;
                  }

                fputs ("\n", stdout);
                fputs (p, stdout);
                fputs ("\n", stdout);

                gnutls_free (p);
            }

          gnutls_x509_crt_deinit (crt);
      }
}

/* returns true or false, depending on whether the hostname
 * matches to certificate */
static int
verify_x509_hostname (gnutls_session_t session, const char *hostname)
{
  gnutls_x509_crt_t crt;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size = 0;
  int ret;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list_size == 0)
    {
      fprintf (stderr, "No certificates found!\n");
      return 0;
    }

  gnutls_x509_crt_init (&crt);
  ret =
      gnutls_x509_crt_import (crt, &cert_list[0],
                              GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      fprintf (stderr, "Decoding error: %s\n",
               gnutls_strerror (ret));
      return 0;
    }

  /* Check the hostname of the first certificate if it matches
   * the name of the host we connected to.
   */
  if (hostname != NULL)
    {
      if (gnutls_x509_crt_check_hostname (crt, hostname) == 0)
        {
          printf
             ("- The hostname in the certificate does NOT match '%s'\n",
              hostname);
          ret = 0;
        }
      else
        {
          printf ("- The hostname in the certificate matches '%s'.\n",
                  hostname);
          ret = 1;
        }
    }

  gnutls_x509_crt_deinit (crt);

  return ret;
}

#ifdef ENABLE_OPENPGP
/* returns true or false, depending on whether the hostname
 * matches to certificate */
static int
verify_openpgp_hostname (gnutls_session_t session, const char *hostname)
{
  gnutls_openpgp_crt_t crt;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size = 0;
  int ret;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list_size == 0)
    {
      fprintf (stderr, "No certificates found!\n");
      return 0;
    }

  gnutls_openpgp_crt_init (&crt);
  ret =
      gnutls_openpgp_crt_import (crt, &cert_list[0],
                              GNUTLS_OPENPGP_FMT_RAW);
  if (ret < 0)
    {
      fprintf (stderr, "Decoding error: %s\n",
               gnutls_strerror (ret));
      return 0;
    }

  /* Check the hostname of the first certificate if it matches
   * the name of the host we connected to.
   */
  if (gnutls_openpgp_crt_check_hostname (crt, hostname) == 0)
    {
      printf
             ("- The hostname in the certificate does NOT match '%s'\n",
              hostname);
      ret = 0;
    }
  else
    {
      printf ("- The hostname in the certificate matches '%s'.\n",
              hostname);
      ret = 1;
    }

  gnutls_openpgp_crt_deinit (crt);

  return ret;
}

static void
print_openpgp_info_compact (gnutls_session_t session)
{

    gnutls_openpgp_crt_t crt;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0;
    int ret;

    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

    if (cert_list_size > 0)
      {
          gnutls_datum_t cinfo;

          gnutls_openpgp_crt_init (&crt);
          ret = gnutls_openpgp_crt_import (crt, &cert_list[0],
                                           GNUTLS_OPENPGP_FMT_RAW);
          if (ret < 0)
            {
                fprintf (stderr, "Decoding error: %s\n",
                         gnutls_strerror (ret));
                return;
            }

          ret =
              gnutls_openpgp_crt_print (crt, GNUTLS_CRT_PRINT_COMPACT, &cinfo);
          if (ret == 0)
            {
                printf ("- OpenPGP cert: %s\n", cinfo.data);
                gnutls_free (cinfo.data);
            }

          gnutls_openpgp_crt_deinit (crt);
      }
}

static void
print_openpgp_info (gnutls_session_t session, int flag, int print_cert)
{

    gnutls_openpgp_crt_t crt;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0;
    int ret;

    printf ("- Certificate type: OpenPGP\n");

    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

    if (cert_list_size > 0)
      {
          gnutls_datum_t cinfo;

          gnutls_openpgp_crt_init (&crt);
          ret = gnutls_openpgp_crt_import (crt, &cert_list[0],
                                           GNUTLS_OPENPGP_FMT_RAW);
          if (ret < 0)
            {
                fprintf (stderr, "Decoding error: %s\n",
                         gnutls_strerror (ret));
                return;
            }

          ret =
              gnutls_openpgp_crt_print (crt, flag, &cinfo);
          if (ret == 0)
            {
                printf ("- %s\n", cinfo.data);
                gnutls_free (cinfo.data);
            }

          if (print_cert)
            {
                size_t size = 0;
                char *p = NULL;

                ret =
                    gnutls_openpgp_crt_export (crt,
                                               GNUTLS_OPENPGP_FMT_BASE64,
                                               p, &size);
                if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
                  {
                      p = malloc (size);
                      if (!p)
                        {
                            fprintf (stderr, "gnutls_malloc\n");
                            exit (1);
                        }

                      ret =
                          gnutls_openpgp_crt_export (crt,
                                                     GNUTLS_OPENPGP_FMT_BASE64,
                                                     p, &size);
                  }
                if (ret < 0)
                  {
                      fprintf (stderr, "Encoding error: %s\n",
                               gnutls_strerror (ret));
                      return;
                  }

                fputs (p, stdout);
                fputs ("\n", stdout);

                gnutls_free (p);
            }

          gnutls_openpgp_crt_deinit (crt);
      }
}

#endif

/* returns false (0) if not verified, or true (1) otherwise 
 */
int
cert_verify (gnutls_session_t session, const char* hostname)
{
    int rc;
    unsigned int status = 0;
    int type;

    rc = gnutls_certificate_verify_peers2 (session, &status);
    if (rc == GNUTLS_E_NO_CERTIFICATE_FOUND)
      {
          printf ("- Peer did not send any certificate.\n");
          return 0;
      }

    if (rc < 0)
      {
          printf ("- Could not verify certificate (err: %s)\n",
                  gnutls_strerror (rc));
          return 0;
      }

    type = gnutls_certificate_type_get (session);
    if (type == GNUTLS_CRT_X509)
      {

          if (status & GNUTLS_CERT_REVOKED)
              printf ("- Peer's certificate chain revoked\n");
          if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
              printf ("- Peer's certificate issuer is unknown\n");
          if (status & GNUTLS_CERT_SIGNER_NOT_CA)
              printf ("- Peer's certificate issuer is not a CA\n");
          if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
              printf
                  ("- Peer's certificate chain uses insecure algorithm\n");
          if (status & GNUTLS_CERT_NOT_ACTIVATED)
              printf
                  ("- Peer's certificate chain uses not yet valid certificate\n");
          if (status & GNUTLS_CERT_EXPIRED)
              printf
                  ("- Peer's certificate chain uses expired certificate\n");
          if (status & GNUTLS_CERT_INVALID)
              printf ("- Peer's certificate is NOT trusted\n");
          else
              printf ("- Peer's certificate is trusted\n");

          rc = verify_x509_hostname (session, hostname);
          if (rc == 0) status |= GNUTLS_CERT_INVALID;
      }
    else if (type == GNUTLS_CRT_OPENPGP)
      {
          if (status & GNUTLS_CERT_INVALID)
              printf ("- Peer's key is invalid\n");
          else
              printf ("- Peer's key is valid\n");
          if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
              printf ("- Could not find a signer of the peer's key\n");

          rc = verify_openpgp_hostname (session, hostname);
          if (rc == 0) status |= GNUTLS_CERT_INVALID;
      }
    else
      {
        fprintf(stderr, "Unknown certificate type\n");
        status |= GNUTLS_CERT_INVALID;
      }

    if (status)
      return 0;

    return 1;
}

static void
print_dh_info (gnutls_session_t session, const char *str, int print)
{
    printf ("- %sDiffie-Hellman parameters\n", str);
    printf (" - Using prime: %d bits\n",
            gnutls_dh_get_prime_bits (session));
    printf (" - Secret key: %d bits\n",
            gnutls_dh_get_secret_bits (session));
    printf (" - Peer's public key: %d bits\n",
            gnutls_dh_get_peers_public_bits (session));

    if (print)
      {
          int ret;
          gnutls_datum_t raw_gen = { NULL, 0 };
          gnutls_datum_t raw_prime = { NULL, 0 };
          gnutls_dh_params_t dh_params = NULL;
          unsigned char *params_data = NULL;
          size_t params_data_size = 0;

          ret = gnutls_dh_get_group (session, &raw_gen, &raw_prime);
          if (ret)
            {
                fprintf (stderr, "gnutls_dh_get_group %d\n", ret);
                goto out;
            }

          ret = gnutls_dh_params_init (&dh_params);
          if (ret)
            {
                fprintf (stderr, "gnutls_dh_params_init %d\n", ret);
                goto out;
            }

          ret =
              gnutls_dh_params_import_raw (dh_params, &raw_prime,
                                           &raw_gen);
          if (ret)
            {
                fprintf (stderr, "gnutls_dh_params_import_raw %d\n", ret);
                goto out;
            }

          ret = gnutls_dh_params_export_pkcs3 (dh_params,
                                               GNUTLS_X509_FMT_PEM,
                                               params_data,
                                               &params_data_size);
          if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
            {
                fprintf (stderr, "gnutls_dh_params_export_pkcs3 %d\n",
                         ret);
                goto out;
            }

          params_data = gnutls_malloc (params_data_size);
          if (!params_data)
            {
                fprintf (stderr, "gnutls_malloc %d\n", ret);
                goto out;
            }

          ret = gnutls_dh_params_export_pkcs3 (dh_params,
                                               GNUTLS_X509_FMT_PEM,
                                               params_data,
                                               &params_data_size);
          if (ret)
            {
                fprintf (stderr, "gnutls_dh_params_export_pkcs3-2 %d\n",
                         ret);
                goto out;
            }

          printf (" - PKCS#3 format:\n\n%.*s\n", (int) params_data_size,
                  params_data);

        out:
          gnutls_free (params_data);
          gnutls_free (raw_prime.data);
          gnutls_free (raw_gen.data);
          gnutls_dh_params_deinit (dh_params);
      }
}

static void
print_ecdh_info (gnutls_session_t session, const char *str)
{
    int curve;

    printf ("- %sEC Diffie-Hellman parameters\n", str);

    curve = gnutls_ecc_curve_get (session);

    printf (" - Using curve: %s\n", gnutls_ecc_curve_get_name (curve));
    printf (" - Curve size: %d bits\n",
            gnutls_ecc_curve_get_size (curve) * 8);

}

int
print_info (gnutls_session_t session, int print_cert)
{
    const char *tmp;
    gnutls_credentials_type_t cred;
    gnutls_kx_algorithm_t kx;
    unsigned char session_id[33];
    size_t session_id_size = sizeof (session_id);

    /* print session ID */
    gnutls_session_get_id (session, session_id, &session_id_size);
    printf ("- Session ID: %s\n",
            raw_to_string (session_id, session_id_size));

    /* print the key exchange's algorithm name
     */
    kx = gnutls_kx_get (session);

    cred = gnutls_auth_get_type (session);
    switch (cred)
      {
#ifdef ENABLE_ANON
      case GNUTLS_CRD_ANON:
          if (kx == GNUTLS_KX_ANON_ECDH)
              print_ecdh_info (session, "Anonymous ");
          else
              print_dh_info (session, "Anonymous ", verbose);
          break;
#endif
#ifdef ENABLE_SRP
      case GNUTLS_CRD_SRP:
          /* This should be only called in server
           * side.
           */
          if (gnutls_srp_server_get_username (session) != NULL)
              printf ("- SRP authentication. Connected as '%s'\n",
                      gnutls_srp_server_get_username (session));
          break;
#endif
#ifdef ENABLE_PSK
      case GNUTLS_CRD_PSK:
          /* This returns NULL in server side.
           */
          if (gnutls_psk_client_get_hint (session) != NULL)
              printf ("- PSK authentication. PSK hint '%s'\n",
                      gnutls_psk_client_get_hint (session));
          /* This returns NULL in client side.
           */
          if (gnutls_psk_server_get_username (session) != NULL)
              printf ("- PSK authentication. Connected as '%s'\n",
                      gnutls_psk_server_get_username (session));
          if (kx == GNUTLS_KX_DHE_PSK)
              print_dh_info (session, "Ephemeral ", verbose);
          if (kx == GNUTLS_KX_ECDHE_PSK)
              print_ecdh_info (session, "Ephemeral ");
          break;
#endif
      case GNUTLS_CRD_IA:
          printf ("- TLS/IA authentication\n");
          break;
      case GNUTLS_CRD_CERTIFICATE:
          {
              char dns[256];
              size_t dns_size = sizeof (dns);
              unsigned int type;

              /* This fails in client side */
              if (gnutls_server_name_get
                  (session, dns, &dns_size, &type, 0) == 0)
                {
                    printf ("- Given server name[%d]: %s\n", type, dns);
                }
          }

          print_cert_info (session, verbose, print_cert);

          if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
              print_dh_info (session, "Ephemeral ", verbose);
          else if (kx == GNUTLS_KX_ECDHE_RSA
                   || kx == GNUTLS_KX_ECDHE_ECDSA)
              print_ecdh_info (session, "Ephemeral ");
      }

    tmp =
        SU (gnutls_protocol_get_name
            (gnutls_protocol_get_version (session)));
    printf ("- Version: %s\n", tmp);

    tmp = SU (gnutls_kx_get_name (kx));
    printf ("- Key Exchange: %s\n", tmp);

    tmp = SU (gnutls_cipher_get_name (gnutls_cipher_get (session)));
    printf ("- Cipher: %s\n", tmp);

    tmp = SU (gnutls_mac_get_name (gnutls_mac_get (session)));
    printf ("- MAC: %s\n", tmp);

    tmp =
        SU (gnutls_compression_get_name
            (gnutls_compression_get (session)));
    printf ("- Compression: %s\n", tmp);

    if (verbose)
      {
          gnutls_datum_t cb;
          int rc;

          rc = gnutls_session_channel_binding (session,
                                               GNUTLS_CB_TLS_UNIQUE, &cb);
          if (rc)
              fprintf (stderr, "Channel binding error: %s\n",
                       gnutls_strerror (rc));
          else
            {
                size_t i;

                printf ("- Channel binding 'tls-unique': ");
                for (i = 0; i < cb.size; i++)
                    printf ("%02x", cb.data[i]);
                printf ("\n");
            }
      }

    /* Warning: Do not print anything more here. The 'Compression:'
       output MUST be the last non-verbose output.  This is used by
       Emacs starttls.el code. */

    fflush (stdout);

    return 0;
}

void
print_cert_info (gnutls_session_t session, int verbose, int print_cert)
{
int flag;

    if (verbose) flag = GNUTLS_CRT_PRINT_FULL;
    else flag = GNUTLS_CRT_PRINT_COMPACT;

    if (gnutls_certificate_client_get_request_status (session) != 0)
        printf ("- Server has requested a certificate.\n");

    switch (gnutls_certificate_type_get (session))
      {
      case GNUTLS_CRT_X509:
          print_x509_info (session, flag, print_cert);
          break;
#ifdef ENABLE_OPENPGP
      case GNUTLS_CRT_OPENPGP:
          print_openpgp_info (session, flag, print_cert);
          break;
#endif
      default:
          printf ("Unknown type\n");
          break;
      }
}

void
print_cert_info_compact (gnutls_session_t session)
{

    if (gnutls_certificate_client_get_request_status (session) != 0)
        printf ("- Server has requested a certificate.\n");

    switch (gnutls_certificate_type_get (session))
      {
      case GNUTLS_CRT_X509:
          print_x509_info_compact (session);
          break;
#ifdef ENABLE_OPENPGP
      case GNUTLS_CRT_OPENPGP:
          print_openpgp_info_compact (session);
          break;
#endif
      default:
          printf ("Unknown type\n");
          break;
      }
}

void
print_list (const char *priorities, int verbose)
{
    size_t i;
    int ret;
    unsigned int idx;
    const char *name;
    const char *err;
    unsigned char id[2];
    gnutls_kx_algorithm_t kx;
    gnutls_cipher_algorithm_t cipher;
    gnutls_mac_algorithm_t mac;
    gnutls_protocol_t version;
    gnutls_priority_t pcache;
    const unsigned int *list;

    if (priorities != NULL)
      {
          printf ("Cipher suites for %s\n", priorities);

          ret = gnutls_priority_init (&pcache, priorities, &err);
          if (ret < 0)
            {
                fprintf (stderr, "Syntax error at: %s\n", err);
                exit (1);
            }

          for (i = 0;; i++)
            {
                ret =
                    gnutls_priority_get_cipher_suite_index (pcache, i,
                                                            &idx);
                if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
                    break;
                if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE)
                    continue;

                name =
                    gnutls_cipher_suite_info (idx, id, NULL, NULL, NULL,
                                              &version);

                if (name != NULL)
                    printf ("%-50s\t0x%02x, 0x%02x\t%s\n",
                            name, (unsigned char) id[0],
                            (unsigned char) id[1],
                            gnutls_protocol_get_name (version));
            }

          printf("\n");
          {
              ret = gnutls_priority_certificate_type_list (pcache, &list);

              printf ("Certificate types: ");
              if (ret == 0) printf("none\n");
              for (i = 0; i < (unsigned)ret; i++)
                {
                    printf ("CTYPE-%s",
                            gnutls_certificate_type_get_name (list[i]));
                    if (i+1!=(unsigned)ret)
                        printf (", ");
                    else
                        printf ("\n");
                }
          }

          {
              ret = gnutls_priority_protocol_list (pcache, &list);

              printf ("Protocols: ");
              if (ret == 0) printf("none\n");
              for (i = 0; i < (unsigned)ret; i++)
                {
                    printf ("VERS-%s", gnutls_protocol_get_name (list[i]));
                    if (i+1!=(unsigned)ret)
                        printf (", ");
                    else
                        printf ("\n");
                }
          }

          {
              ret = gnutls_priority_compression_list (pcache, &list);

              printf ("Compression: ");
              if (ret == 0) printf("none\n");
              for (i = 0; i < (unsigned)ret; i++)
                {
                    printf ("COMP-%s",
                            gnutls_compression_get_name (list[i]));
                    if (i+1!=(unsigned)ret)
                        printf (", ");
                    else
                        printf ("\n");
                }
          }

          {
              ret = gnutls_priority_ecc_curve_list (pcache, &list);

              printf ("Elliptic curves: ");
              if (ret == 0) printf("none\n");
              for (i = 0; i < (unsigned)ret; i++)
                {
                    printf ("CURVE-%s",
                            gnutls_ecc_curve_get_name (list[i]));
                    if (i+1!=(unsigned)ret)
                        printf (", ");
                    else
                        printf ("\n");
                }
          }

          {
              ret = gnutls_priority_sign_list (pcache, &list);

              printf ("PK-signatures: ");
              if (ret == 0) printf("none\n");
              for (i = 0; i < (unsigned)ret; i++)
                {
                    printf ("SIGN-%s",
                            gnutls_sign_algorithm_get_name (list[i]));
                    if (i+1!=(unsigned)ret)
                        printf (", ");
                    else
                        printf ("\n");
                }
          }

          return;
      }

    printf ("Cipher suites:\n");
    for (i = 0; (name = gnutls_cipher_suite_info
                 (i, id, &kx, &cipher, &mac, &version)); i++)
      {
          printf ("%-50s\t0x%02x, 0x%02x\t%s\n",
                  name,
                  (unsigned char) id[0], (unsigned char) id[1],
                  gnutls_protocol_get_name (version));
          if (verbose)
              printf ("\tKey exchange: %s\n\tCipher: %s\n\tMAC: %s\n\n",
                      gnutls_kx_get_name (kx),
                      gnutls_cipher_get_name (cipher),
                      gnutls_mac_get_name (mac));
      }

    printf("\n");
    {
        const gnutls_certificate_type_t *p =
            gnutls_certificate_type_list ();

        printf ("Certificate types: ");
        for (; *p; p++)
          {
              printf ("CTYPE-%s", gnutls_certificate_type_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_protocol_t *p = gnutls_protocol_list ();

        printf ("Protocols: ");
        for (; *p; p++)
          {
              printf ("VERS-%s", gnutls_protocol_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_cipher_algorithm_t *p = gnutls_cipher_list ();

        printf ("Ciphers: ");
        for (; *p; p++)
          {
              printf ("%s", gnutls_cipher_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_mac_algorithm_t *p = gnutls_mac_list ();

        printf ("MACs: ");
        for (; *p; p++)
          {
              printf ("%s", gnutls_mac_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_kx_algorithm_t *p = gnutls_kx_list ();

        printf ("Key exchange algorithms: ");
        for (; *p; p++)
          {
              printf ("%s", gnutls_kx_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_compression_method_t *p = gnutls_compression_list ();

        printf ("Compression: ");
        for (; *p; p++)
          {
              printf ("COMP-%s", gnutls_compression_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_ecc_curve_t *p = gnutls_ecc_curve_list ();

        printf ("Elliptic curves: ");
        for (; *p; p++)
          {
              printf ("CURVE-%s", gnutls_ecc_curve_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_pk_algorithm_t *p = gnutls_pk_list ();

        printf ("Public Key Systems: ");
        for (; *p; p++)
          {
              printf ("%s", gnutls_pk_algorithm_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }

    {
        const gnutls_sign_algorithm_t *p = gnutls_sign_list ();

        printf ("PK-signatures: ");
        for (; *p; p++)
          {
              printf ("SIGN-%s", gnutls_sign_algorithm_get_name (*p));
              if (*(p + 1))
                  printf (", ");
              else
                  printf ("\n");
          }
    }
}

int check_command(gnutls_session_t session, const char* str)
{
int len = strlen(str);

  if (len > 2 && str[0] == str[1] && str[0] == '*')
    {
      if (strncmp(str, "**REHANDSHAKE**",
          sizeof ("**REHANDSHAKE**") - 1) == 0)
        {
          fprintf (stderr, "*** Sending rehandshake request\n");
                   gnutls_rehandshake (session);
          return 1;
        }
    }
  return 0;
}
