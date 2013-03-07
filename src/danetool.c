/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/openpgp.h>
#include <gnutls/pkcs12.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#ifdef HAVE_DANE
# include <gnutls/dane.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>

/* Gnulib portability files. */
#include <read-file.h>
#include <progname.h>
#include <version-etc.h>

#include <common.h>
#include "danetool-args.h"
#include "certtool-common.h"

static void cmd_parser (int argc, char **argv);
static void dane_info(const char* host, const char* proto, unsigned int port, 
                      unsigned int ca, unsigned int domain, common_info_st * cinfo);

static void dane_check(const char* host, const char* proto, unsigned int port,
                       common_info_st * cinfo);

FILE *outfile;
static gnutls_digest_algorithm_t default_dig;

/* non interactive operation if set
 */
int batch;


static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

int
main (int argc, char **argv)
{
  set_program_name (argv[0]);
  cmd_parser (argc, argv);

  return 0;
}


static void
cmd_parser (int argc, char **argv)
{
  int ret, privkey_op = 0;
  common_info_st cinfo;
  const char* proto = "tcp";
  unsigned int port = 443;

  optionProcess( &danetoolOptions, argc, argv);
  
  if (HAVE_OPT(OUTFILE))
    {
      outfile = safe_open_rw (OPT_ARG(OUTFILE), privkey_op);
      if (outfile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(OUTFILE));
    }
  else
    outfile = stdout;

  default_dig = GNUTLS_DIG_UNKNOWN;
  if (HAVE_OPT(HASH))
    {
      if (strcasecmp (OPT_ARG(HASH), "md5") == 0)
        {
          fprintf (stderr,
                   "Warning: MD5 is broken, and should not be used any more for digital signatures.\n");
          default_dig = GNUTLS_DIG_MD5;
        }
      else if (strcasecmp (OPT_ARG(HASH), "sha1") == 0)
        default_dig = GNUTLS_DIG_SHA1;
      else if (strcasecmp (OPT_ARG(HASH), "sha256") == 0)
        default_dig = GNUTLS_DIG_SHA256;
      else if (strcasecmp (OPT_ARG(HASH), "sha224") == 0)
        default_dig = GNUTLS_DIG_SHA224;
      else if (strcasecmp (OPT_ARG(HASH), "sha384") == 0)
        default_dig = GNUTLS_DIG_SHA384;
      else if (strcasecmp (OPT_ARG(HASH), "sha512") == 0)
        default_dig = GNUTLS_DIG_SHA512;
      else if (strcasecmp (OPT_ARG(HASH), "rmd160") == 0)
        default_dig = GNUTLS_DIG_RMD160;
      else
        error (EXIT_FAILURE, 0, "invalid hash: %s", OPT_ARG(HASH));
    }

  gnutls_global_set_log_function (tls_log_func);
  
  if (HAVE_OPT(DEBUG))
    {
      gnutls_global_set_log_level (OPT_VALUE_DEBUG);
      printf ("Setting log level to %d\n", (int)OPT_VALUE_DEBUG);
    }

  if ((ret = gnutls_global_init ()) < 0)
    error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));

#ifdef ENABLE_PKCS11
  pkcs11_common();
#endif

  memset (&cinfo, 0, sizeof (cinfo));
  
  if (HAVE_OPT(INDER) || HAVE_OPT(INRAW))
    cinfo.incert_format = GNUTLS_X509_FMT_DER;
  else
    cinfo.incert_format = GNUTLS_X509_FMT_PEM;

  if (HAVE_OPT(VERBOSE))
    cinfo.verbose = 1;
  
  if (HAVE_OPT(LOAD_PUBKEY))
    cinfo.pubkey = OPT_ARG(LOAD_PUBKEY);

  if (HAVE_OPT(LOAD_CERTIFICATE))
    cinfo.cert = OPT_ARG(LOAD_CERTIFICATE);

  if (HAVE_OPT(PORT))
    port = OPT_VALUE_PORT;
  if (HAVE_OPT(PROTO))
    proto = OPT_ARG(PROTO);

  if (HAVE_OPT(TLSA_RR))
    dane_info (OPT_ARG(HOST), proto, port,
               HAVE_OPT(CA), ENABLED_OPT(DOMAIN), &cinfo);
  else if (HAVE_OPT(CHECK))
    dane_check (OPT_ARG(CHECK), proto, port, 
                &cinfo);
  else
    USAGE(1);

  fclose (outfile);

#ifdef ENABLE_PKCS11
  gnutls_pkcs11_deinit ();
#endif
  gnutls_global_deinit ();
}

static void dane_check(const char* host, const char* proto, unsigned int port,
                       common_info_st * cinfo)
{
#ifdef HAVE_DANE
dane_state_t s;
dane_query_t q;
int ret, retcode = 0;
unsigned entries;
unsigned int flags = DANE_F_IGNORE_LOCAL_RESOLVER, i;
unsigned int usage, type, match;
gnutls_datum_t data, file;
size_t size;
unsigned vflags = DANE_VFLAG_FAIL_IF_NOT_CHECKED;

  if (ENABLED_OPT(LOCAL_DNS))
    flags = 0;

  if (HAVE_OPT(INSECURE))
    flags |= DANE_F_INSECURE;

  if (HAVE_OPT(CHECK_EE))
    vflags |= DANE_VFLAG_ONLY_CHECK_EE_USAGE;

  if (HAVE_OPT(CHECK_CA))
    vflags |= DANE_VFLAG_ONLY_CHECK_CA_USAGE;

  printf("Querying %s (%s:%d)...\n", host, proto, port);
  ret = dane_state_init(&s, flags);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "dane_state_init: %s", dane_strerror (ret));

  if (HAVE_OPT(DLV))
    {
      ret = dane_state_set_dlv_file(s, OPT_ARG(DLV));
      if (ret < 0)
        error (EXIT_FAILURE, 0, "dane_state_set_dlv_file: %s", dane_strerror (ret));
    }
  
  ret = dane_query_tlsa(s, &q, host, proto, port);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "dane_query_tlsa: %s", dane_strerror (ret));
  
  entries = dane_query_entries(q);
  for (i=0;i<entries;i++)
    {
      ret = dane_query_data(q, i, &usage, &type, &match, &data);
      if (ret < 0)
        error (EXIT_FAILURE, 0, "dane_query_data: %s", dane_strerror (ret));
      
      
      size = buffer_size;
      ret = gnutls_hex_encode(&data, (void*)buffer, &size);
      if (ret < 0)
        error (EXIT_FAILURE, 0, "gnutls_hex_encode: %s", dane_strerror (ret));

      if (entries > 1) printf("\nEntry %d:\n", i+1);

      fprintf(outfile, "_%u._%s.%s. IN TLSA ( %.2x %.2x %.2x %s )\n", port, proto, host, usage, type, match, buffer);
      printf("Certificate usage: %s (%.2x)\n", dane_cert_usage_name(usage), usage);
      printf("Certificate type:  %s (%.2x)\n", dane_cert_type_name(type), type);
      printf("Contents:          %s (%.2x)\n", dane_match_type_name(match), match);
      printf("Data:              %s\n", buffer);

      /* Verify the DANE data */
      if (cinfo->cert)
        {
          gnutls_x509_crt_t *clist;
          unsigned int clist_size, status;
          
          ret = gnutls_load_file(cinfo->cert, &file);
          if (ret < 0)
            error (EXIT_FAILURE, 0, "gnutls_load_file: %s", gnutls_strerror (ret));
        
          ret = gnutls_x509_crt_list_import2( &clist, &clist_size, &file, cinfo->incert_format, 0);
          if (ret < 0)
            error (EXIT_FAILURE, 0, "gnutls_x509_crt_list_import2: %s", gnutls_strerror (ret));

          if (clist_size > 0)
            {
              gnutls_datum_t certs[clist_size];
              gnutls_datum_t out;
              unsigned int i;
              
              for (i=0;i<clist_size;i++)
                {
                  ret = gnutls_x509_crt_export2( clist[i], GNUTLS_X509_FMT_DER, &certs[i]);
                  if (ret < 0)
                    error (EXIT_FAILURE, 0, "gnutls_x509_crt_export2: %s", gnutls_strerror (ret));
                }

              ret = dane_verify_crt( s, certs, clist_size, GNUTLS_CRT_X509, 
                                     host, proto, port, 0, vflags, &status);
              if (ret < 0)
                error (EXIT_FAILURE, 0, "dane_verify_crt: %s", dane_strerror (ret));
                
              ret = dane_verification_status_print(status, &out, 0);
              if (ret < 0)
                error (EXIT_FAILURE, 0, "dane_verification_status_print: %s", dane_strerror (ret));
              
              printf("\nVerification: %s\n", out.data);
              gnutls_free(out.data);
              
              if (status != 0) retcode = 1;

              for (i=0;i<clist_size;i++)
                {
                  gnutls_free(certs[i].data);
                  gnutls_x509_crt_deinit(clist[i]);
                }
              gnutls_free(clist);
            }
        }
    }
  

  dane_query_deinit(q);
  dane_state_deinit(s);
  
  exit(retcode);
#else
  fprintf(stderr, "This functionality was disabled (GnuTLS was not compiled with support for DANE).\n");
  return;
#endif
}

static void dane_info(const char* host, const char* proto, unsigned int port, 
                      unsigned int ca, unsigned int domain, common_info_st * cinfo)
{
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;
  unsigned char digest[64];
  gnutls_datum_t t;
  int ret;
  unsigned int usage, selector, type;
  size_t size;
  
  if (proto == NULL)
    proto = "tcp";
  if (port == 0)
    port = 443;
    
  crt = load_cert (0, cinfo);
  if (crt != NULL && HAVE_OPT(X509))
    {
      selector = 0; /* X.509 */

      size = buffer_size;
      ret = gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_DER, buffer, &size);
      if (ret < 0)
        error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));

      gnutls_x509_crt_deinit (crt);
    }
  else /* use public key only */
    {
      selector = 1;

      ret = gnutls_pubkey_init (&pubkey);
      if (ret < 0)
        error (EXIT_FAILURE, 0, "pubkey_init: %s", gnutls_strerror (ret));

      if (crt != NULL)
        {
          
          ret = gnutls_pubkey_import_x509 (pubkey, crt, 0);
          if (ret < 0)
            {
              error (EXIT_FAILURE, 0, "pubkey_import_x509: %s",
                     gnutls_strerror (ret));
            }

          size = buffer_size;
          ret = gnutls_pubkey_export (pubkey, GNUTLS_X509_FMT_DER, buffer, &size);
          if (ret < 0)
            {
              error (EXIT_FAILURE, 0, "pubkey_export: %s",
                     gnutls_strerror (ret));
            }
          
          gnutls_x509_crt_deinit(crt);
        }
      else
        {
          pubkey = load_pubkey (1, cinfo);

          size = buffer_size;
          ret = gnutls_pubkey_export (pubkey, GNUTLS_X509_FMT_DER, buffer, &size);
          if (ret < 0)
            error (EXIT_FAILURE, 0, "export error: %s", gnutls_strerror (ret));
        }

      gnutls_pubkey_deinit (pubkey);
    }
 
  if (default_dig != GNUTLS_DIG_SHA256 && default_dig != GNUTLS_DIG_SHA512)
    {
      if (default_dig != GNUTLS_DIG_UNKNOWN) fprintf(stderr, "Unsupported digest. Assuming SHA256.\n");
      default_dig = GNUTLS_DIG_SHA256;
    }
  
  ret = gnutls_hash_fast(default_dig, buffer, size, digest);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "hash error: %s", gnutls_strerror (ret));

  if (default_dig == GNUTLS_DIG_SHA256)
    type = 1;
  else type = 2;

  /* DANE certificate classification crap */
  if (domain==0)
    {  
      if (ca) usage = 0;
      else usage = 1;
    }
  else
    {
      if (ca) usage = 2;
      else usage = 3;
    }

  t.data = digest;
  t.size = gnutls_hash_get_len(default_dig);

  size = buffer_size;
  ret = gnutls_hex_encode(&t, (void*)buffer, &size);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "hex encode error: %s", gnutls_strerror (ret));

  fprintf(outfile, "_%u._%s.%s. IN TLSA ( %.2x %.2x %.2x %s )\n", port, proto, host, usage, selector, type, buffer);

}
