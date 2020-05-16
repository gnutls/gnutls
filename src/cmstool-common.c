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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Gnulib portability files. */
#include <read-file.h>

#include <cmstool-common.h>

static gnutls_digest_algorithm_t get_dig_for_pub(gnutls_pubkey_t pubkey, common_info_st * cinfo)
{
	gnutls_digest_algorithm_t dig;
	int result;
	unsigned int mand;

	result =
	    gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig,
						       &mand);
	if (result < 0) {
		{
			fprintf(stderr,
				"crt_get_preferred_hash_algorithm: %s\n",
				gnutls_strerror(result));
			app_exit(1);
		}
	}

	/* if algorithm allows alternatives */
	if (mand == 0 && cinfo->hash != GNUTLS_DIG_UNKNOWN)
		dig = cinfo->hash;

	return dig;
}

static gnutls_digest_algorithm_t get_dig(gnutls_x509_crt_t crt, common_info_st * cinfo)
{
	gnutls_digest_algorithm_t dig;
	gnutls_pubkey_t pubkey;
	int result;

	result = gnutls_pubkey_init(&pubkey);
	if (result < 0) {
		fprintf(stderr, "memory error\n");
		app_exit(1);
	}

	result = gnutls_pubkey_import_x509(pubkey, crt, 0);
	if (result < 0) {
		{
			fprintf(stderr, "gnutls_pubkey_import_x509: %s\n",
				gnutls_strerror(result));
			app_exit(1);
		}
	}

	dig = get_dig_for_pub(pubkey, cinfo);

	gnutls_pubkey_deinit(pubkey);

	return dig;
}

static void load_data(common_info_st *cinfo, gnutls_datum_t *data)
{
	FILE *fp;
	size_t size;

	fp = fopen(cinfo->data_file, "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not open %s\n", cinfo->data_file);
		app_exit(1);
	}

	data->data = (void *) fread_file(fp, 0, &size);
	if (data->data == NULL) {
		fprintf(stderr, "Error reading data file");
		app_exit(1);
	}

	data->size = size;
	fclose(fp);
}

static gnutls_x509_trust_list_t load_tl(common_info_st * cinfo)
{
	gnutls_x509_trust_list_t list;
	int ret;

	ret = gnutls_x509_trust_list_init(&list, 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_x509_trust_list_init: %s\n",
			gnutls_strerror(ret));
		app_exit(1);
	}

	if (cinfo->ca == NULL) { /* system */
		ret = gnutls_x509_trust_list_add_system_trust(list, 0, 0);
		if (ret < 0) {
			fprintf(stderr, "Error loading system trust: %s\n",
				gnutls_strerror(ret));
			app_exit(1);
		}
		fprintf(stderr, "Loaded system trust (%d CAs available)\n", ret);
	} else if (cinfo->ca != NULL) {
		ret = gnutls_x509_trust_list_add_trust_file(list, cinfo->ca, cinfo->crl, cinfo->incert_format, 0, 0);
		if (ret < 0) {
			int ret2 = gnutls_x509_trust_list_add_trust_file(list, cinfo->ca, cinfo->crl, GNUTLS_X509_FMT_PEM, 0, 0);
			if (ret2 >= 0)
				ret = ret2;
		}

		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_trust_add_trust_file: %s\n",
				gnutls_strerror(ret));
			app_exit(1);
		}

		fprintf(stderr, "Loaded CAs (%d available)\n", ret);
	}

	return list;
}

void pkcs7_verify_common(common_info_st * cinfo, const char *purpose, unsigned display_data, gnutls_certificate_verify_flags flags)
{
	gnutls_pkcs7_t pkcs7;
	int ret, ecode;
	size_t size;
	gnutls_datum_t data, detached = {NULL,0};
	gnutls_datum_t tmp = {NULL,0};
	int i;
	gnutls_pkcs7_signature_info_st info;
	gnutls_x509_trust_list_t tl = NULL;
	gnutls_typed_vdata_st vdata[2];
	unsigned vdata_size = 0;
	gnutls_x509_crt_t signer = NULL;

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

	if (cinfo->cert != NULL) {
		signer = load_cert(1, cinfo);
	} else { /* trust list */
		tl = load_tl(cinfo);
		if (tl == NULL) {
			fprintf(stderr, "error loading trust list\n");
		}
	}

	if (cinfo->data_file)
		load_data(cinfo, &detached);

	if (purpose) {
		vdata[vdata_size].type = GNUTLS_DT_KEY_PURPOSE_OID;
		vdata[vdata_size].data = (void*)purpose;
		vdata[vdata_size].size = strlen(purpose);
		vdata_size++;
	}

	ecode = 1;
	for (i=0;;i++) {
		ret = gnutls_pkcs7_get_signature_info(pkcs7, i, &info);
		if (ret < 0)
			break;

		if (!display_data) {
			if (i==0) {
				fprintf(outfile, "eContent Type: %s\n", gnutls_pkcs7_get_embedded_data_oid(pkcs7));
				fprintf(outfile, "Signers:\n");
			}

			ret = gnutls_pkcs7_print_signature_info(&info, GNUTLS_CRT_PRINT_COMPACT, &tmp);
			if (ret < 0) {
				fprintf(stderr, "printing error: %s\n",
						gnutls_strerror(ret));
				app_exit(1);
			}

			fprintf(outfile, "%s", tmp.data);
			gnutls_free(tmp.data);
		} else if (i == 0) {
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
		}

		gnutls_pkcs7_signature_info_deinit(&info);

		if (signer) {
			ret = gnutls_pkcs7_verify_direct(pkcs7, signer, i, detached.data!=NULL?&detached:NULL, flags);

			if (ret >= 0 && purpose) {
				unsigned res = gnutls_x509_crt_check_key_purpose(signer, purpose, 0);
				if (res == 0)
					ret = GNUTLS_E_CONSTRAINT_ERROR;
			}

		} else {
			assert(tl != NULL);
			ret = gnutls_pkcs7_verify(pkcs7, tl, vdata, vdata_size, i, detached.data!=NULL?&detached:NULL, flags);
		}
		if (ret < 0) {
			fprintf(stderr, "\tSignature status: verification failed: %s\n", gnutls_strerror(ret));
			ecode = 1;
		} else {
			fprintf(stderr, "\tSignature status: ok\n");
			ecode = 0;
		}
	}


	gnutls_pkcs7_deinit(pkcs7);
	if (signer)
		gnutls_x509_crt_deinit(signer);
	else
		gnutls_x509_trust_list_deinit(tl, 1);
	free(detached.data);
	app_exit(ecode);
}

void pkcs7_sign_common(common_info_st * cinfo, unsigned embed, gnutls_pkcs7_sign_flags flags)
{
	gnutls_pkcs7_t pkcs7;
	gnutls_privkey_t key;
	int ret;
	size_t size;
	gnutls_datum_t data;
	gnutls_x509_crt_t *crts;
	size_t crt_size;
	size_t i;

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

	crts = load_cert_list(1, &crt_size, cinfo);
	key = load_private_key(1, cinfo);

	if (embed)
		flags |= GNUTLS_PKCS7_EMBED_DATA;

	ret = gnutls_pkcs7_sign(pkcs7, *crts, key, &data, NULL, NULL, get_dig(*crts, cinfo), flags);
	if (ret < 0) {
		fprintf(stderr, "Error signing: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	for (i=1;i<crt_size;i++) {
		ret = gnutls_pkcs7_set_crt(pkcs7, crts[i]);
		if (ret < 0) {
			fprintf(stderr, "Error adding cert: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}


	size = lbuffer_size;
	ret =
	    gnutls_pkcs7_export(pkcs7, cinfo->outcert_format, lbuffer, &size);
	if (ret < 0) {
		fprintf(stderr, "pkcs7_export: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	fwrite(lbuffer, 1, size, outfile);

	gnutls_privkey_deinit(key);
	for (i=0;i<crt_size;i++) {
		gnutls_x509_crt_deinit(crts[i]);
	}
	gnutls_free(crts);
	gnutls_pkcs7_deinit(pkcs7);
	app_exit(0);
}

void pkcs7_generate(common_info_st * cinfo)
{
	gnutls_pkcs7_t pkcs7;
	int ret;
	size_t crl_size = 0, crt_size = 0;
	gnutls_x509_crt_t *crts;
	gnutls_x509_crl_t *crls;
	gnutls_datum_t tmp;
	unsigned i;

	crts = load_cert_list(1, &crt_size, cinfo);
	crls = load_crl_list(0, &crl_size, cinfo);

	ret = gnutls_pkcs7_init(&pkcs7);
	if (ret < 0) {
		fprintf(stderr, "p7_init: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	for (i=0;i<crt_size;i++) {
		ret = gnutls_pkcs7_set_crt(pkcs7, crts[i]);
		if (ret < 0) {
			fprintf(stderr, "Error adding cert: %s\n", gnutls_strerror(ret));
			app_exit(1);
		}
		gnutls_x509_crt_deinit(crts[i]);
	}
	gnutls_free(crts);

	for (i=0;i<crl_size;i++) {
		ret = gnutls_pkcs7_set_crl(pkcs7, crls[i]);
		if (ret < 0) {
			fprintf(stderr, "Error adding CRL: %s\n", gnutls_strerror(ret));
			app_exit(1);
		}
		gnutls_x509_crl_deinit(crls[i]);
	}
	gnutls_free(crls);

	ret =
	    gnutls_pkcs7_export2(pkcs7, cinfo->outcert_format, &tmp);
	if (ret < 0) {
		fprintf(stderr, "pkcs7_export: %s\n", gnutls_strerror(ret));
		app_exit(1);
	}

	fwrite(tmp.data, 1, tmp.size, outfile);
	gnutls_free(tmp.data);

	gnutls_pkcs7_deinit(pkcs7);
	app_exit(0);
}

void pkcs7_info(common_info_st *cinfo, unsigned display_data)
{
	gnutls_pkcs7_t pkcs7;
	int ret;
	size_t size;
	gnutls_datum_t data, str;

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

	if (display_data) {
		gnutls_datum_t tmp;

		ret = gnutls_pkcs7_get_embedded_data(pkcs7, 0, &tmp);
		if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			if (ret < 0) {
				fprintf(stderr, "error getting embedded data: %s\n", gnutls_strerror(ret));
				app_exit(1);
			}

			fwrite(tmp.data, 1, tmp.size, outfile);
			gnutls_free(tmp.data);
		} else {
			fprintf(stderr, "no embedded data are available\n");
			app_exit(1);
		}
	} else {
		if (cinfo->outtext) {
			ret = gnutls_pkcs7_print(pkcs7, GNUTLS_CRT_PRINT_FULL, &str);
			if (ret < 0) {
				fprintf(stderr, "printing error: %s\n",
					gnutls_strerror(ret));
				app_exit(1);
			}

			fprintf(outfile, "%s", str.data);
			gnutls_free(str.data);
		}

		size = lbuffer_size;
		ret =
		    gnutls_pkcs7_export(pkcs7, cinfo->outcert_format,
					lbuffer, &size);
		if (ret < 0) {
			fprintf(stderr, "export error: %s\n",
				gnutls_strerror(ret));
			app_exit(1);
		}

		fwrite(lbuffer, 1, size, outfile);
	}

	gnutls_pkcs7_deinit(pkcs7);
}

void smime_to_pkcs7(void)
{
	size_t linesize = 0;
	char *lineptr = NULL;
	ssize_t len;

	/* Find body. We do not handle non-b64 Content-Transfer-Encoding. */
	do {
		len = getline(&lineptr, &linesize, infile);
		if (len == -1) {
			fprintf(stderr,
				"cannot find RFC 2822 header/body separator");
			app_exit(1);
		}
	}
	while (strcmp(lineptr, "\r\n") != 0 && strcmp(lineptr, "\n") != 0);

	/* skip newlines */
	do {
		len = getline(&lineptr, &linesize, infile);
		if (len == -1) {
			fprintf(stderr,
				"message has RFC 2822 header but no body");
			app_exit(1);
		}
	}
	while (strcmp(lineptr, "\r\n") == 0 || strcmp(lineptr, "\n") == 0);

	fprintf(outfile, "%s", "-----BEGIN PKCS7-----\n");

	do {
		while (len > 0
		       && (lineptr[len - 1] == '\r'
			   || lineptr[len - 1] == '\n'))
			lineptr[--len] = '\0';
		if (strcmp(lineptr, "") != 0)
			fprintf(outfile, "%s\n", lineptr);
		len = getline(&lineptr, &linesize, infile);
	}
	while (len != -1);

	fprintf(outfile, "%s", "-----END PKCS7-----\n");

	free(lineptr);
}
