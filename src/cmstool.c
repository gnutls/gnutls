/*
 * Copyright (C) 2015-2019 Red Hat, Inc.
 * Copyright (C) 2020 Dmitry Baryshkov
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
 * <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/openpgp.h>
#include <gnutls/pkcs12.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

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
#ifndef _WIN32
# include <signal.h>
#endif

/* Gnulib portability files. */
#include <read-file.h>

#include <common.h>
#include "cmstool-options.h"
#include "certtool-common.h"
#include "cmstool-common.h"

static FILE *stdlog = NULL;

static void cmd_parser(int argc, char **argv);

FILE *outfile;
static const char *outfile_name = NULL; /* to delete on exit */

FILE *infile;
static unsigned int incert_format, outcert_format;

const char *get_pass(void)
{
	return getpass("Enter password: ");
}

const char *get_confirmed_pass(bool empty_ok)
{
	return getpass("Enter password: ");
}

/* ensure we cleanup */
void app_exit(int val)
{
	if (val != 0) {
		if (outfile_name)
			(void)remove(outfile_name);
	}
	exit(val);
}

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

int main(int argc, char **argv)
{
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	cmd_parser(argc, argv);

	return 0;
}

static void load_infile(const char *file)
{
	struct stat st;
	if (stat(file, &st) == 0) {
		fix_lbuffer(2*st.st_size);
	}

	infile = fopen(file, "rb");
	if (infile == NULL) {
		fprintf(stderr, "Cannot open %s for reading\n", OPT_ARG(INFILE));
		app_exit(1);
	}
}

static void pkcs7_sign(common_info_st * cinfo, unsigned embed)
{
	unsigned flags = 0;

	if (ENABLED_OPT(TIME))
		flags |= GNUTLS_PKCS7_INCLUDE_TIME;

	if (ENABLED_OPT(INCLUDE_CERT))
		flags |= GNUTLS_PKCS7_INCLUDE_CERT;

	return pkcs7_sign_common(cinfo, embed, flags);
}

static void pkcs7_verify(common_info_st * cinfo, const char *purpose, unsigned display_data)
{
	unsigned flags = 0;

	if (HAVE_OPT(VERIFY_ALLOW_BROKEN))
		flags |= GNUTLS_VERIFY_ALLOW_BROKEN;

	return pkcs7_verify_common(cinfo, purpose, display_data, flags);
}

static void pkcs7_digest(common_info_st * cinfo, unsigned embed)
{
	gnutls_pkcs7_t pkcs7;
	int ret;
	size_t size;
	gnutls_datum_t data;
	unsigned flags = 0;

	ret = gnutls_pkcs7_init(&pkcs7);
	if (ret < 0) {
		fprintf(stderr, "p7_init: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	data.data = (void *) fread_file(infile, 0, &size);
	data.size = size;

	if (!data.data) {
		fprintf(stderr, "%s", infile ? "file" : "standard input");
		app_exit(1);
	}

	if (embed)
		flags |= GNUTLS_PKCS7_EMBED_DATA;

	ret = gnutls_pkcs7_digest(pkcs7, &data, cinfo->hash, flags);
	if (ret < 0) {
		fprintf(stderr, "Error digesting: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	size = lbuffer_size;
	ret =
	    gnutls_pkcs7_export(pkcs7, cinfo->outcert_format, lbuffer, &size);
	if (ret < 0) {
		fprintf(stderr, "pkcs7_export: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	fwrite(lbuffer, 1, size, outfile);

	gnutls_pkcs7_deinit(pkcs7);
	app_exit(0);
}

static void pkcs7_verify_digest(common_info_st * cinfo, unsigned display_data)
{
	gnutls_pkcs7_t pkcs7;
	int ret, ecode;
	size_t size;
	gnutls_datum_t data, detached = {NULL,0};
	gnutls_datum_t tmp = {NULL,0};
	unsigned flags = 0;

	if (HAVE_OPT(VERIFY_ALLOW_BROKEN))
		flags |= GNUTLS_VERIFY_ALLOW_BROKEN;

	ret = gnutls_pkcs7_init(&pkcs7);
	if (ret < 0) {
		fprintf(stderr, "p7_init: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	data.data = (void *) fread_file(infile, 0, &size);
	data.size = size;

	if (!data.data) {
		fprintf(stderr, "%s", infile ? "file" : "standard input");
		app_exit(1);
	}

	ret = gnutls_pkcs7_import(pkcs7, &data, cinfo->incert_format);
	free(data.data);
	if (ret < 0) {
		fprintf(stderr, "import error: %s\n",
			gnutls_strerror(ret));
		app_exit(1);
	}

	if (cinfo->data_file)
		load_data(cinfo, &detached);

	if (!display_data) {
		fprintf(outfile, "eContent Type: %s\n", gnutls_pkcs7_get_embedded_data_oid(pkcs7));
		fprintf(outfile, "Digest: %s\n", gnutls_digest_get_name(gnutls_pkcs7_get_digest_algo(pkcs7)));
	}

	if (!detached.data) {
		ret = gnutls_pkcs7_get_embedded_data(pkcs7, 0, &tmp);
		if (ret < 0) {
			fprintf(stderr, "error getting embedded data: %s\n", gnutls_strerror(ret));
			app_exit(1);
		}

		fwrite(tmp.data, 1, tmp.size, outfile);
		gnutls_free(tmp.data);
		tmp.data = NULL;
	} else {
		fwrite(detached.data, 1, detached.size, outfile);
	}

	ret = gnutls_pkcs7_verify_digest(pkcs7, detached.data!=NULL?&detached:NULL, flags);
	if (ret < 0) {
		fprintf(stderr, "Digest status: verification failed: %s\n", gnutls_strerror(ret));
		ecode = 1;
	} else {
		fprintf(stderr, "Digest status: ok\n");
		ecode = 0;
	}

	gnutls_pkcs7_deinit(pkcs7);
	free(detached.data);
	app_exit(ecode);
}

static void cmd_parser(int argc, char **argv)
{
	int ret, privkey_op = 0;
	common_info_st cinfo;

	optionProcess(&cmstoolOptions, argc, argv);

	if (HAVE_OPT(STDOUT_INFO)) {
		/* print informational messages on stdout instead of stderr */
		stdlog = stdout;
	} else {
		stdlog = stderr;
	}

	if (HAVE_OPT(OUTFILE)) {
		outfile = safe_open_rw(OPT_ARG(OUTFILE), privkey_op);
		if (outfile == NULL) {
			fprintf(stderr, "Cannot open %s for writing\n", OPT_ARG(OUTFILE));
			app_exit(1);
		}
		outfile_name = OPT_ARG(OUTFILE);
	} else {
		outfile = stdout;
	}

	if (!HAVE_OPT(INFILE)) {
		infile = stdin;
	} else {
		load_infile(OPT_ARG(INFILE));
	}


	fix_lbuffer(0);

	if (HAVE_OPT(INDER))
		incert_format = GNUTLS_X509_FMT_DER;
	else
		incert_format = GNUTLS_X509_FMT_PEM;

	if (HAVE_OPT(OUTDER))
		outcert_format = GNUTLS_X509_FMT_DER;
	else
		outcert_format = GNUTLS_X509_FMT_PEM;

	gnutls_global_set_log_function(tls_log_func);

	if (HAVE_OPT(DEBUG)) {
		gnutls_global_set_log_level(OPT_VALUE_DEBUG);
		printf("Setting log level to %d\n", (int) OPT_VALUE_DEBUG);
	}

	if ((ret = gnutls_global_init()) < 0) {
		fprintf(stderr, "global_init: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	memset(&cinfo, 0, sizeof(cinfo));

	/*ask_pass = cinfo.ask_pass = ENABLED_OPT(ASK_PASS); */
	cinfo.hash = GNUTLS_DIG_UNKNOWN;
	if (HAVE_OPT(HASH)) {
		cinfo.hash = hash_to_id(OPT_ARG(HASH));
		if (cinfo.hash == GNUTLS_DIG_UNKNOWN) {
			fprintf(stderr, "invalid hash: %s\n", OPT_ARG(HASH));
			app_exit(1);
		}
	}

#ifdef ENABLE_PKCS11
	if (HAVE_OPT(PROVIDER)) {
		ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
		if (ret < 0)
			fprintf(stderr, "pkcs11_init: %s",
				gnutls_strerror(ret));
		else {
			ret =
			    gnutls_pkcs11_add_provider(OPT_ARG(PROVIDER),
						       NULL);
			if (ret < 0) {
				fprintf(stderr, "pkcs11_add_provider: %s",
					gnutls_strerror(ret));
				app_exit(1);
			}
		}
	}

	pkcs11_common(&cinfo);
#endif

	if (HAVE_OPT(VERBOSE))
		cinfo.verbose = 1;

	cinfo.cprint = HAVE_OPT(CPRINT);

	if (HAVE_OPT(LOAD_PRIVKEY))
		cinfo.privkey = OPT_ARG(LOAD_PRIVKEY);

	if (HAVE_OPT(LOAD_CRL))
		cinfo.crl = OPT_ARG(LOAD_CRL);

	if (HAVE_OPT(LOAD_DATA))
		cinfo.data_file = OPT_ARG(LOAD_DATA);

	if (HAVE_OPT(LOAD_PUBKEY))
		cinfo.pubkey = OPT_ARG(LOAD_PUBKEY);

	cinfo.incert_format = incert_format;
	cinfo.outcert_format = outcert_format;
	cinfo.outtext = ENABLED_OPT(TEXT) && outcert_format == GNUTLS_X509_FMT_PEM;

	if (HAVE_OPT(LOAD_CERTIFICATE))
		cinfo.cert = OPT_ARG(LOAD_CERTIFICATE);

	if (HAVE_OPT(LOAD_CA_CERTIFICATE))
		cinfo.ca = OPT_ARG(LOAD_CA_CERTIFICATE);

	if (HAVE_OPT(PKCS_CIPHER))
		cinfo.pkcs_cipher = OPT_ARG(PKCS_CIPHER);

	if (HAVE_OPT(PASSWORD))
		cinfo.password = OPT_ARG(PASSWORD);

	if (HAVE_OPT(NULL_PASSWORD)) {
		cinfo.null_password = 1;
		cinfo.password = "";
	}

	if (HAVE_OPT(EMPTY_PASSWORD)) {
		cinfo.empty_password = 1;
		cinfo.password = "";
	}

	if (HAVE_OPT(INFO))
		pkcs7_info(&cinfo, ENABLED_OPT(SHOW_DATA));
	else if (HAVE_OPT(GENERATE))
		pkcs7_generate(&cinfo);
	else if (HAVE_OPT(SIGN))
		pkcs7_sign(&cinfo, 1);
	else if (HAVE_OPT(DETACHED_SIGN))
		pkcs7_sign(&cinfo, 0);
	else if (HAVE_OPT(VERIFY))
		pkcs7_verify(&cinfo, OPT_ARG(VERIFY_PURPOSE), ENABLED_OPT(SHOW_DATA));
	else if (HAVE_OPT(SMIME_TO_CMS))
		smime_to_pkcs7();
	else if (HAVE_OPT(DIGEST))
		pkcs7_digest(&cinfo, 1);
	else if (HAVE_OPT(VERIFY_DIGEST))
		pkcs7_verify_digest(&cinfo, ENABLED_OPT(SHOW_DATA));
	else
		USAGE(1);

	if (outfile != stdout)
		fclose(outfile);


	free(cinfo.seed);
#ifdef ENABLE_PKCS11
	gnutls_pkcs11_deinit();
#endif
	gnutls_global_deinit();
}
