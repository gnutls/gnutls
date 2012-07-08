/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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
#include <gnutls/tpm.h>
#include <gnutls/abstract.h>

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

#include "certtool-common.h"
#include "tpmtool-args.h"

static void cmd_parser (int argc, char **argv);
static void tpm_generate(FILE* outfile, unsigned int key_type, unsigned int bits);
static void tpm_pubkey(FILE* infile, FILE* outfile);

static FILE *outfile;
static FILE *infile;
int batch = 0;

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
  int ret, debug = 0;
  unsigned int optct;
  unsigned int key_type = GNUTLS_PK_UNKNOWN;
  unsigned int bits = 0;
  
  optct = optionProcess( &tpmtoolOptions, argc, argv);
  argc += optct;
  argv += optct;
 
  if (HAVE_OPT(DEBUG))
    debug = OPT_VALUE_DEBUG;

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (debug);
  if (debug > 1)
    printf ("Setting log level to %d\n", debug);

  if ((ret = gnutls_global_init ()) < 0)
    error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));

  if (HAVE_OPT(OUTFILE))
    {
      outfile = safe_open_rw (OPT_ARG(OUTFILE), 0);
      if (outfile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(OUTFILE));
    }
  else
    outfile = stdout;

  if (HAVE_OPT(INFILE))
    {
      infile = fopen (OPT_ARG(INFILE), "rb");
      if (infile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(INFILE));
    }
  else
    infile = stdin;

  if (HAVE_OPT(BITS))
    bits = OPT_VALUE_BITS;
  else
    bits = 2048;

  if (HAVE_OPT(GENERATE_RSA))
    {
      key_type = GNUTLS_PK_RSA;
      tpm_generate (outfile, key_type, bits);
    }
  else if (HAVE_OPT(PUBKEY))
    {
      tpm_pubkey (infile, outfile);
    }
  else 
    {
      USAGE(1);
    }
    
  fclose (outfile);

  gnutls_global_deinit ();
}

static void tpm_generate(FILE* outfile, unsigned int key_type, unsigned int bits)
{
  int ret;
  char* srk_pass, *key_pass;
  gnutls_datum_t privkey, pubkey;
  
  srk_pass = getpass ("Enter SRK password: ");
  if (srk_pass != NULL)
    srk_pass = strdup(srk_pass);

  key_pass = getpass ("Enter key password: ");
  if (key_pass != NULL)
    key_pass = strdup(srk_pass);
  
  ret = gnutls_tpm_privkey_generate(key_type, bits, srk_pass, key_pass,
                                    GNUTLS_X509_FMT_PEM, &privkey, &pubkey,
                                    GNUTLS_TPM_SIG_PKCS1V15);

  free(key_pass);
  free(srk_pass);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_tpm_privkey_generate: %s", gnutls_strerror (ret));

  fwrite (pubkey.data, 1, pubkey.size, outfile);
  fputs ("\n", outfile);
  fwrite (privkey.data, 1, privkey.size, outfile);
  fputs ("\n", outfile);
}

static void tpm_pubkey(FILE* infile, FILE* outfile)
{
  int ret;
  char* srk_pass;
  gnutls_datum_t data;
  gnutls_pubkey_t pubkey;
  size_t size;
  
  srk_pass = getpass ("Enter SRK password: ");
  if (srk_pass != NULL)
    srk_pass = strdup(srk_pass);

  data.data = (void*)fread_file (infile, &size);
  data.size = size;
  
  gnutls_pubkey_init(&pubkey);

  ret = gnutls_pubkey_import_tpm_raw(pubkey, &data, GNUTLS_X509_FMT_PEM,
                                     srk_pass);

  free(srk_pass);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_pubkey_import_tpm_raw: %s", gnutls_strerror (ret));

  _pubkey_info(outfile, pubkey);

  gnutls_pubkey_deinit(pubkey);
}
