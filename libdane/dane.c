/*
 * Copyright (C) 2012 KU Leuven
 * Copyright (C) 2013 Christian Grothoff
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of libdane.
 *
 * The libdane library is free software; you can redistribute it
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ares.h>
#include <gnutls/dane.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include "../lib/gnutls_int.h"

#ifdef __sun
# pragma fini(lib_deinit)
# pragma init(lib_init)
# define _CONSTRUCTOR
# define _DESTRUCTOR
#else
# define _CONSTRUCTOR __attribute__((constructor))
# define _DESTRUCTOR __attribute__((destructor))
#endif

#define DEBUG
#ifdef DEBUG
#define gnutls_assert() fprintf(stderr, "ASSERT: %s: %d\n", __FILE__, __LINE__);
#define _gnutls_debug_log(str, ...) fprintf(stderr, str, ##__VA_ARGS__)
#define gnutls_assert_val(x) gnutls_assert_val_int(x, __FILE__, __LINE__)
static int gnutls_assert_val_int(int val, const char *file, int line)
{
	fprintf(stderr, "ASSERT: %s: %d\n", file, line);
	return val;
}
#else
#define gnutls_assert()
#define gnutls_assert_val(x) (x)
#define _gnutls_debug_log(...)
#endif

struct dane_state_st {
	ares_channel channel;
	unsigned int flags;
};

struct reply_st {
	uint8_t		  usage;
	uint8_t		  selector;
	uint8_t		  mtype;
	uint8_t		  *data;
	unsigned 	  data_size;
};

struct dane_query_st {
	struct reply_st *entries;
	unsigned int n_entries;
	dane_query_status_t status;
};

/**
 * dane_query_status:
 * @q: The query result structure
 *
 * This function will return the status of the query response.
 * See %dane_query_status_t for the possible types.
 *
 * Returns: The status type.
 **/
dane_query_status_t dane_query_status(dane_query_t q)
{
	return q->status;
}

/**
 * dane_query_entries:
 * @q: The query result structure
 *
 * This function will return the number of entries in a query.
 *
 * Returns: The number of entries.
 **/
unsigned int dane_query_entries(dane_query_t q)
{
	return q->n_entries;
}

/**
 * dane_query_data:
 * @q: The query result structure
 * @idx: The index of the query response.
 * @usage: The certificate usage (see %dane_cert_usage_t)
 * @type: The certificate type (see %dane_cert_type_t)
 * @match: The DANE matching type (see %dane_match_type_t)
 * @data: The DANE data.
 *
 * This function will provide the DANE data from the query
 * response. The data should be treated as constant.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
dane_query_data(dane_query_t q, unsigned int idx,
		unsigned int *usage, unsigned int *type,
		unsigned int *match, gnutls_datum_t *data)
{
	if (idx >= q->n_entries)
		return
		    gnutls_assert_val(DANE_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (usage)
		*usage = q->entries[idx].usage;
	if (type)
		*type = q->entries[idx].selector;
	if (match)
		*match = q->entries[idx].mtype;
	if (data) {
		data->data = q->entries[idx].data;
		data->size = q->entries[idx].data_size;
	}
	return DANE_E_SUCCESS;
}

/**
 * dane_query_to_raw_tlsa:
 * @q: The query result structure
 * @data_entries: Pointer set to the number of entries in the query
 * @dane_data: Pointer to contain an array of DNS rdata items, terminated with a NULL pointer;
 *             caller must guarantee that the referenced data remains
 *             valid until dane_query_deinit() is called.
 * @dane_data_len: Pointer to contain the length n bytes of the dane_data items
 * @secure: Pointer set true if the result is validated securely, false if
 *               validation failed or the domain queried has no security info
 * @bogus: Pointer set true if the result was not secure due to a security failure
 *
 * This function will provide the DANE data from the query
 * response.
 *
 * The pointers dane_data and dane_data_len are allocated with gnutls_malloc()
 * to contain a copy of the data from the query result structure (individual
 * rdata items are not allocated separately). The returned data are only valid
 * during the lifetime of @q.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 */
int
dane_query_to_raw_tlsa(dane_query_t q, unsigned int *data_entries,
		char ***dane_data, int **dane_data_len, int *secure, int *bogus)
{
	size_t data_sz;
	char *data_buf;
	unsigned int idx;

	*data_entries = 0;
	if (bogus)
		*bogus = 0;
	if (secure)
		*secure = 0;
	*dane_data = NULL;
	*dane_data_len = NULL;

	switch (q->status) {
	case DANE_QUERY_DNSSEC_VERIFIED:
		if (secure)
			*secure = 1;
		break;

	case DANE_QUERY_BOGUS:
		if (bogus)
			*bogus = 1;
		break;

	default:
		break;
	}

	/* pack dane_data pointer list followed by dane_data contents */
	data_sz = sizeof (**dane_data) * (q->data_entries + 1);
	for (idx = 0; idx < q->data_entries; idx++)
		data_sz += 3 + q->data[idx].size;

	*dane_data = gnutls_calloc (1, data_sz);
	if (*dane_data == NULL)
		return DANE_E_MEMORY_ERROR;
	data_buf = (char *)*dane_data;
	data_buf += sizeof (**dane_data) * (q->data_entries + 1);

	*dane_data_len = gnutls_calloc (q->data_entries + 1, sizeof (**dane_data_len));
	if (*dane_data_len == NULL) {
		free(*dane_data);
		*dane_data = NULL;
		return DANE_E_MEMORY_ERROR;
	}

	for (idx = 0; idx < q->data_entries; idx++) {
		(*dane_data)[idx] = data_buf;
		(*dane_data)[idx][0] = q->usage[idx];
		(*dane_data)[idx][1] = q->type[idx];
		(*dane_data)[idx][2] = q->match[idx];
		memcpy(&(*dane_data)[idx][3], q->data[idx].data, q->data[idx].size);
		(*dane_data_len)[idx] = 3 + q->data[idx].size;
		data_buf += 3 + q->data[idx].size;
	}
	(*dane_data)[idx] = NULL;
	(*dane_data_len)[idx] = 0;
	*data_entries = q->data_entries;

	return DANE_E_SUCCESS;
}

/**
 * dane_state_init:
 * @s: The structure to be initialized
 * @flags: flags from the %dane_state_flags enumeration
 *
 * This function will initialize a DANE query structure.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int dane_state_init(dane_state_t * s, unsigned int flags)
{
	int ret;
	struct ares_options options;

	*s = calloc(1, sizeof(struct dane_state_st));
	if (*s == NULL)
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);

	memset(&options, 0, sizeof(options));
	options.flags = ARES_FLAG_DNSSEC;
	ret = ares_init_options(&(*s)->channel, &options, ARES_OPT_FLAGS);
	if (ret != ARES_SUCCESS) {
		gnutls_assert();
		ret = DANE_E_INITIALIZATION_ERROR;
		goto cleanup;
	}

	(*s)->flags = flags;

	return DANE_E_SUCCESS;
      cleanup:

	free(*s);

	return ret;
}

/**
 * dane_state_deinit:
 * @s: The structure to be deinitialized
 *
 * This function will deinitialize a DANE query structure.
 *
 **/
void dane_state_deinit(dane_state_t s)
{
	ares_destroy(s->channel);
	free(s);
}

/**
 * dane_state_set_dlv_file:
 * @s: The structure to be deinitialized
 * @file: The file holding the DLV keys.
 *
 * This function will set a file with trusted keys
 * for DLV  (DNSSEC  Lookaside  Validation).
 *
 **/
int dane_state_set_dlv_file(dane_state_t s, const char *file)
{
	return 0;
}

/**
 * dane_query_deinit:
 * @q: The structure to be deinitialized
 *
 * This function will deinitialize a DANE query result structure.
 *
 **/
void dane_query_deinit(dane_query_t q)
{
	unsigned i;

	for (i=0;i<q->n_entries;i++) {
		free(q->entries[i].data);
	}
	free(q->entries);
	free(q);
}


/**
 * dane_raw_tlsa:
 * @s: The DANE state structure
 * @r: A structure to place the result
 * @dane_data: array of DNS rdata items, terminated with a NULL pointer;
 *             caller must guarantee that the referenced data remains
 *             valid until dane_query_deinit() is called.
 * @dane_data_len: the length n bytes of the dane_data items
 * @secure: true if the result is validated securely, false if
 *               validation failed or the domain queried has no security info
 * @bogus: if the result was not secure (secure = 0) due to a security failure,
 *              and the result is due to a security failure, bogus is true.
 *
 * This function will fill in the TLSA (DANE) structure from
 * the given raw DNS record data. The @dane_data must be valid
 * during the lifetime of the query.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
dane_raw_tlsa(dane_state_t s, dane_query_t * r, char *const *dane_data,
	      const int *dane_data_len, int secure, int bogus)
{
	int ret = DANE_E_SUCCESS;
	unsigned int i;
	unsigned entries = 0;
	char *const * p = dane_data;

	while(p[entries]!=NULL) {
		entries++;
	}

	*r = calloc(1, sizeof(struct dane_query_st));
	if (*r == NULL)
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);

	(*r)->n_entries = 0;

	(*r)->entries = calloc(1, sizeof((*r)->entries[0]) * entries);
	if ((*r)->entries == NULL) {
		free(*r);
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);
	}

	for (i = 0; i < entries; i++) {
		if (dane_data[i] == NULL)
			break;

		if (dane_data_len[i] <= 3) {
			ret =
			    gnutls_assert_val
			    (DANE_E_RECEIVED_CORRUPT_DATA);
			goto fail;
		}

		(*r)->entries[i].usage = dane_data[i][0];
		(*r)->entries[i].selector = dane_data[i][1];
		(*r)->entries[i].mtype = dane_data[i][2];
		(*r)->entries[i].data = malloc(dane_data_len[i] - 3);
		if ((*r)->entries[i].data != NULL)
			memcpy((*r)->entries[i].data, &dane_data[i][3], dane_data_len[i] - 3);
		(*r)->entries[i].data_size = dane_data_len[i] - 3;
		(*r)->n_entries++;
	}

	if (!(s->flags & DANE_F_INSECURE) && !secure) {
		if (bogus)
			ret = gnutls_assert_val(DANE_E_INVALID_DNSSEC_SIG);
		else
			ret = gnutls_assert_val(DANE_E_NO_DNSSEC_SIG);
	}

	/* show security status */
	if (secure) {
		(*r)->status = DANE_QUERY_DNSSEC_VERIFIED;
	} else if (bogus) {
		gnutls_assert();
		(*r)->status = DANE_QUERY_BOGUS;
	} else {
		gnutls_assert();
		(*r)->status = DANE_QUERY_NO_DNSSEC;
	}

	return ret;
fail:
	free((*r)->entries);
	free(*r);
	return ret;

}

static void
query_cb(void *arg, int status, int timeouts, uint8_t *buf, int len)
{
dane_query_t r = arg;
struct ares_tlsa_reply *p, *replies = NULL;
unsigned entries = 0, i;

	r->status = DANE_QUERY_BOGUS;
	if(status != ARES_SUCCESS){
		_gnutls_debug_log("failed to lookup: %s\n", ares_strerror(status));
		return;
	}

	status = ares_parse_tlsa_reply(buf, len, &replies);
	if (status == ARES_ENODNSSEC) {
		r->status = DANE_QUERY_NO_DNSSEC;
		return;
	}

	if(status != ARES_SUCCESS){
		_gnutls_debug_log("failed to parse TLSA: %s\n", ares_strerror(status));
		return;
	}

	p = replies;
	while(p != NULL) {
		entries++;
		p=p->next;
	}

	r->entries = calloc(1, entries * sizeof(r->entries[0]));
	if (r->entries == NULL) {
		goto cleanup;
	}

	p = replies;
	i = 0;
	while(p != NULL) {
		r->entries[i].usage = p->usage;
		r->entries[i].selector = p->selector;
		r->entries[i].mtype = p->mtype;
		r->entries[i].data_size = p->data_size;
		r->entries[i].data = p->data; /* steal the allocated value */
		p->data = NULL;
		i++;
		p=p->next;
	}
	r->status = DANE_QUERY_DNSSEC_VERIFIED;
	r->n_entries = entries;

 cleanup:
 	ares_free_data(replies);
	return;
}

static void _CONSTRUCTOR lib_init(void)
{
int ret;

	ret = ares_library_init(ARES_LIB_INIT_ALL);
	if (ret != ARES_SUCCESS) {
		fprintf(stderr, "Error in Ares library initialization: %s\n", ares_strerror(ret));
	}
}

static void _DESTRUCTOR lib_deinit(void)
{
	ares_library_cleanup();
}

static void wait_ares(ares_channel channel)
{
struct timeval *tvp, tv;
fd_set read_fds, write_fds;
int nfds, ret;

	for(;;) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if(nfds == 0)
			 break;

		tvp = ares_timeout(channel, NULL, &tv);
		ret = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if (ret < 0)
			break;
		ares_process(channel, &read_fds, &write_fds);
	}
}

/**
 * dane_query_tlsa:
 * @s: The DANE state structure
 * @r: A structure to place the result
 * @host: The host name to resolve.
 * @proto: The protocol type (tcp, udp, etc.)
 * @port: The service port number (eg. 443).
 *
 * This function will query the DNS server for the TLSA (DANE)
 * data for the given host.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
dane_query_tlsa(dane_state_t s, dane_query_t * r, const char *host,
		const char *proto, unsigned int port)
{
	char ns[1024];
	int ret, id;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, &id, sizeof(id));
	if (ret < 0)
		return gnutls_assert_val(DANE_E_INITIALIZATION_ERROR);
	id &= 0x0000ffff;

	*r = calloc(1, sizeof(struct dane_query_st));
	if (*r == NULL)
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);

	snprintf(ns, sizeof(ns), "_%u._%s.%s", port, proto, host);

	ares_query(s->channel, ns, 1, 52, query_cb, *r);

	wait_ares(s->channel);

	if ((*r)->n_entries == 0) {
		free(*r);
		return gnutls_assert_val(DANE_E_RESOLVING_ERROR);
	}

	return 0;
}


static unsigned int
matches(const gnutls_datum_t * raw1, const gnutls_datum_t * raw2,
	dane_match_type_t match)
{
	uint8_t digest[64];
	int ret;

	if (match == DANE_MATCH_EXACT) {
		if (raw1->size != raw2->size)
			return gnutls_assert_val(0);

		if (memcmp(raw1->data, raw2->data, raw1->size) != 0)
			return gnutls_assert_val(0);

		return 1;
	} else if (match == DANE_MATCH_SHA2_256) {

		if (raw2->size != 32)
			return gnutls_assert_val(0);

		ret =
		    gnutls_hash_fast(GNUTLS_DIG_SHA256, raw1->data,
				     raw1->size, digest);
		if (ret < 0)
			return gnutls_assert_val(0);

		if (memcmp(digest, raw2->data, 32) != 0)
			return gnutls_assert_val(0);

		return 1;
	} else if (match == DANE_MATCH_SHA2_512) {
		if (raw2->size != 64)
			return gnutls_assert_val(0);

		ret =
		    gnutls_hash_fast(GNUTLS_DIG_SHA512, raw1->data,
				     raw1->size, digest);
		if (ret < 0)
			return gnutls_assert_val(0);

		if (memcmp(digest, raw2->data, 64) != 0)
			return gnutls_assert_val(0);

		return 1;
	}

	return gnutls_assert_val(0);
}

static int
crt_to_pubkey(const gnutls_datum_t * raw_crt, gnutls_datum_t * out)
{
	gnutls_pubkey_t pub = NULL;
	gnutls_x509_crt_t crt = NULL;
	int ret;

	out->data = NULL;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
		return gnutls_assert_val(DANE_E_PUBKEY_ERROR);

	ret = gnutls_pubkey_init(&pub);
	if (ret < 0) {
		gnutls_assert();
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	ret = gnutls_x509_crt_import(crt, raw_crt, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	ret = gnutls_pubkey_import_x509(pub, crt, 0);
	if (ret < 0) {
		gnutls_assert();
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	ret = gnutls_pubkey_export2(pub, GNUTLS_X509_FMT_DER, out);
	if (ret < 0) {
		gnutls_assert();
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	ret = 0;
	goto clean_certs;

      cleanup:
	free(out->data);
	out->data = NULL;
      clean_certs:
	if (pub)
		gnutls_pubkey_deinit(pub);
	if (crt)
		gnutls_x509_crt_deinit(crt);

	return ret;
}

static int
verify_ca(const gnutls_datum_t * raw_crt, unsigned raw_crt_size,
	  gnutls_certificate_type_t crt_type,
	  dane_cert_type_t ctype,
	  dane_match_type_t match, gnutls_datum_t * data,
	  unsigned int *verify)
{
	gnutls_datum_t pubkey = { NULL, 0 };
	int ret;
	unsigned int vstatus;
	gnutls_x509_crt_t crt = NULL, ca = NULL;

	if (raw_crt_size < 2)
		return gnutls_assert_val(DANE_E_INVALID_REQUEST);

	if (ctype == DANE_CERT_X509 && crt_type == GNUTLS_CRT_X509) {

		if (!matches(&raw_crt[1], data, match)) {
			gnutls_assert();
			*verify |= DANE_VERIFY_CA_CONSTRAINTS_VIOLATED;
		}

	} else if (ctype == DANE_CERT_PK && crt_type == GNUTLS_CRT_X509) {
		ret = crt_to_pubkey(&raw_crt[1], &pubkey);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		if (!matches(&pubkey, data, match)) {
			gnutls_assert();
			*verify |= DANE_VERIFY_CA_CONSTRAINTS_VIOLATED;
		}
	} else {
		ret = gnutls_assert_val(DANE_E_UNKNOWN_DANE_DATA);
		goto cleanup;
	}

	/* check if the certificate chain is actually a chain */
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		ret = gnutls_assert_val(DANE_E_CERT_ERROR);
		goto cleanup;
	}

	ret = gnutls_x509_crt_init(&ca);
	if (ret < 0) {
		ret = gnutls_assert_val(DANE_E_CERT_ERROR);
		goto cleanup;
	}

	ret =
	    gnutls_x509_crt_import(crt, &raw_crt[0], GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		ret = gnutls_assert_val(DANE_E_CERT_ERROR);
		goto cleanup;
	}

	ret = gnutls_x509_crt_import(ca, &raw_crt[1], GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		ret = gnutls_assert_val(DANE_E_CERT_ERROR);
		goto cleanup;
	}

	ret = gnutls_x509_crt_check_issuer(crt, ca);
	if (ret == 0) {
		gnutls_assert();
		*verify |= DANE_VERIFY_CA_CONSTRAINTS_VIOLATED;
	}

	ret = gnutls_x509_crt_verify(crt, &ca, 1, 0, &vstatus);
	if (ret < 0) {
		ret = gnutls_assert_val(DANE_E_CERT_ERROR);
		goto cleanup;
	}
	if (vstatus != 0)
		*verify |= DANE_VERIFY_CA_CONSTRAINTS_VIOLATED;

	ret = 0;
      cleanup:
	free(pubkey.data);
	if (crt != NULL)
		gnutls_x509_crt_deinit(crt);
	if (ca != NULL)
		gnutls_x509_crt_deinit(ca);
	return ret;
}

static int
verify_ee(const gnutls_datum_t * raw_crt,
	  gnutls_certificate_type_t crt_type, dane_cert_type_t ctype,
	  dane_match_type_t match, gnutls_datum_t * data,
	  unsigned int *verify)
{
	gnutls_datum_t pubkey = { NULL, 0 };
	int ret;

	if (ctype == DANE_CERT_X509 && crt_type == GNUTLS_CRT_X509) {

		if (!matches(raw_crt, data, match)) {
			gnutls_assert();
			*verify |= DANE_VERIFY_CERT_DIFFERS;
		}

	} else if (ctype == DANE_CERT_PK && crt_type == GNUTLS_CRT_X509) {

		ret = crt_to_pubkey(raw_crt, &pubkey);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		if (!matches(&pubkey, data, match)) {
			gnutls_assert();
			*verify |= DANE_VERIFY_CERT_DIFFERS;
		}
	} else {
		ret = gnutls_assert_val(DANE_E_UNKNOWN_DANE_DATA);
		goto cleanup;
	}

	ret = 0;
      cleanup:
	free(pubkey.data);
	return ret;
}

#define CHECK_VRET(ret, checked, record_status, status) \
			if (ret == DANE_E_UNKNOWN_DANE_DATA) { \
				/* skip that entry */ \
				continue; \
			} else if (ret < 0) { \
				gnutls_assert(); \
				goto cleanup; \
			} \
			checked = 1; \
			if (record_status == 0) { \
				status = 0; \
				break; \
			} else { \
				status |= record_status; \
			}

/**
 * dane_verify_crt_raw:
 * @s: A DANE state structure (may be NULL)
 * @chain: A certificate chain
 * @chain_size: The size of the chain
 * @chain_type: The type of the certificate chain
 * @r: DANE data to check against
 * @sflags: Flags for the the initialization of @s (if NULL)
 * @vflags: Verification flags; an OR'ed list of %dane_verify_flags_t.
 * @verify: An OR'ed list of %dane_verify_status_t.
 *
 * This function will verify the given certificate chain against the
 * CA constrains and/or the certificate available via DANE.
 * If no information via DANE can be obtained the flag %DANE_VERIFY_NO_DANE_INFO
 * is set. If a DNSSEC signature is not available for the DANE
 * record then the verify flag %DANE_VERIFY_NO_DNSSEC_DATA is set.
 *
 * Note that the CA constraint only applies for the directly certifying CA
 * and does not account for long CA chains.
 *
 * Due to the many possible options of DANE, there is no single threat
 * model countered. When notifying the user about DANE verification results
 * it may be better to mention: DANE verification did not reject the certificate,
 * rather than mentioning a successful DANE verication.
 *
 * If the @q parameter is provided it will be used for caching entries.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 **/
int
dane_verify_crt_raw(dane_state_t s,
		    const gnutls_datum_t * chain, unsigned chain_size,
		    gnutls_certificate_type_t chain_type,
		    dane_query_t r,
		    unsigned int sflags, unsigned int vflags,
		    unsigned int *verify)
{
	int ret;
	unsigned checked = 0;
	unsigned int usage, type, match, idx;
	gnutls_datum_t data;

	if (chain_type != GNUTLS_CRT_X509)
		return gnutls_assert_val(DANE_E_INVALID_REQUEST);

	if (chain_size == 0)
		return gnutls_assert_val(DANE_E_NO_CERT);

	*verify = 0;
	idx = 0;
	do {
		unsigned int record_verify = 0;

		ret =
		    dane_query_data(r, idx++, &usage, &type, &match,
				    &data);
		if (ret == DANE_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		if (!(vflags & DANE_VFLAG_ONLY_CHECK_EE_USAGE)
		    && (usage == DANE_CERT_USAGE_LOCAL_CA
			|| usage == DANE_CERT_USAGE_CA)) {
			ret =
			    verify_ca(chain, chain_size, chain_type, type,
				      match, &data, &record_verify);
			CHECK_VRET(ret, checked, record_verify, *verify);

		} else if (!(vflags & DANE_VFLAG_ONLY_CHECK_CA_USAGE)
			   && (usage == DANE_CERT_USAGE_LOCAL_EE
			       || usage == DANE_CERT_USAGE_EE)) {
			ret =
			    verify_ee(&chain[0], chain_type, type, match,
				      &data, &record_verify);
			CHECK_VRET(ret, checked, record_verify, *verify);
		}
	}
	while (1);

	if ((vflags & DANE_VFLAG_FAIL_IF_NOT_CHECKED) && checked == 0) {
		ret =
		    gnutls_assert_val(DANE_E_REQUESTED_DATA_NOT_AVAILABLE);
	} else if (checked == 0) {
		*verify |= DANE_VERIFY_UNKNOWN_DANE_INFO;
	} else {
		ret = 0;
	}

      cleanup:
	return ret;
}


/**
 * dane_verify_crt:
 * @s: A DANE state structure (may be NULL)
 * @chain: A certificate chain
 * @chain_size: The size of the chain
 * @chain_type: The type of the certificate chain
 * @hostname: The hostname associated with the chain
 * @proto: The protocol of the service connecting (e.g. tcp)
 * @port: The port of the service connecting (e.g. 443)
 * @sflags: Flags for the the initialization of @s (if NULL)
 * @vflags: Verification flags; an OR'ed list of %dane_verify_flags_t.
 * @verify: An OR'ed list of %dane_verify_status_t.
 *
 * This function will verify the given certificate chain against the
 * CA constrains and/or the certificate available via DANE.
 * If no information via DANE can be obtained the flag %DANE_VERIFY_NO_DANE_INFO
 * is set. If a DNSSEC signature is not available for the DANE
 * record then the verify flag %DANE_VERIFY_NO_DNSSEC_DATA is set.
 *
 * Note that the CA constraint only applies for the directly certifying CA
 * and does not account for long CA chains. Moreover this function does not
 * validate the provided chain.
 *
 * Due to the many possible options of DANE, there is no single threat
 * model countered. When notifying the user about DANE verification results
 * it may be better to mention: DANE verification did not reject the certificate,
 * rather than mentioning a successful DANE verication.
 *
 * If the @q parameter is provided it will be used for caching entries.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 **/
int
dane_verify_crt(dane_state_t s,
		const gnutls_datum_t * chain, unsigned chain_size,
		gnutls_certificate_type_t chain_type,
		const char *hostname, const char *proto, unsigned int port,
		unsigned int sflags, unsigned int vflags,
		unsigned int *verify)
{
	dane_state_t state = NULL;
	dane_query_t r = NULL;
	int ret;

	*verify = 0;
	if (s == NULL) {
		ret = dane_state_init(&state, sflags);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	} else
		state = s;

	ret = dane_query_tlsa(state, &r, hostname, proto, port);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}
	ret = dane_verify_crt_raw(state, chain, chain_size, chain_type,
				  r, sflags, vflags, verify);
      cleanup:
	if (state != s)
		dane_state_deinit(state);
	if (r != NULL)
		dane_query_deinit(r);
	return ret;
}

/**
 * dane_verify_session_crt:
 * @s: A DANE state structure (may be NULL)
 * @session: A gnutls session
 * @hostname: The hostname associated with the chain
 * @proto: The protocol of the service connecting (e.g. tcp)
 * @port: The port of the service connecting (e.g. 443)
 * @sflags: Flags for the the initialization of @s (if NULL)
 * @vflags: Verification flags; an OR'ed list of %dane_verify_flags_t.
 * @verify: An OR'ed list of %dane_verify_status_t.
 *
 * This function will verify session's certificate chain against the
 * CA constrains and/or the certificate available via DANE.
 * See dane_verify_crt() for more information.
 *
 * This will not verify the chain for validity; unless the DANE
 * verification is restricted to end certificates, this has to
 * be performed separately using gnutls_certificate_verify_peers3().
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 **/
int
dane_verify_session_crt(dane_state_t s,
			gnutls_session_t session,
			const char *hostname, const char *proto,
			unsigned int port, unsigned int sflags,
			unsigned int vflags, unsigned int *verify)
{
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size = 0;
	unsigned int type;
	int ret;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list_size == 0) {
		return gnutls_assert_val(DANE_E_NO_CERT);
	}

	type = gnutls_certificate_type_get(session);

	/* this list may be incomplete, try to get the self-signed CA if any */
	if (cert_list_size > 0) {
		gnutls_datum_t new_cert_list[cert_list_size+1];
		gnutls_x509_crt_t crt, ca;
		gnutls_certificate_credentials_t sc;

		ret = gnutls_x509_crt_init(&crt);
		if (ret < 0) {
			gnutls_assert();
			goto failsafe;
		}

		ret = gnutls_x509_crt_import(crt, &cert_list[cert_list_size-1], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			gnutls_x509_crt_deinit(crt);
			goto failsafe;
		}

		/* if it is already self signed continue normally */
		ret = gnutls_x509_crt_check_issuer(crt, crt);
		if (ret != 0) {
			gnutls_assert();
			gnutls_x509_crt_deinit(crt);
			goto failsafe;
		}

		/* chain does not finish in a self signed cert, try to obtain the issuer */
		ret = gnutls_credentials_get(session, GNUTLS_CRD_CERTIFICATE, (void**)&sc);
		if (ret < 0) {
			gnutls_assert();
			gnutls_x509_crt_deinit(crt);
			goto failsafe;
		}

		ret = gnutls_certificate_get_issuer(sc, crt, &ca, 0);
		if (ret < 0) {
			gnutls_assert();
			gnutls_x509_crt_deinit(crt);
			goto failsafe;
		}

		/* make the new list */
		memcpy(new_cert_list, cert_list, cert_list_size*sizeof(gnutls_datum_t));

		ret = gnutls_x509_crt_export2(ca, GNUTLS_X509_FMT_DER, &new_cert_list[cert_list_size]);
		if (ret < 0) {
			gnutls_assert();
			gnutls_x509_crt_deinit(crt);
			goto failsafe;
		}

		ret = dane_verify_crt(s, new_cert_list, cert_list_size+1, type,
			       hostname, proto, port, sflags, vflags,
			       verify);
		if (ret < 0) {
			gnutls_assert();
		}
		gnutls_free(new_cert_list[cert_list_size].data);
		return ret;
	}

 failsafe:
	return dane_verify_crt(s, cert_list, cert_list_size, type,
			       hostname, proto, port, sflags, vflags,
			       verify);
}

/**
 * dane_verification_status_print:
 * @status: The status flags to be printed
 * @type: The certificate type
 * @out: Newly allocated datum with (0) terminated string.
 * @flags: should be zero
 *
 * This function will pretty print the status of a verification
 * process -- eg. the one obtained by dane_verify_crt().
 *
 * The output @out needs to be deallocated using gnutls_free().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
dane_verification_status_print(unsigned int status,
			       gnutls_datum_t * out, unsigned int flags)
{
	gnutls_buffer_st str;
	int ret;

	_gnutls_buffer_init(&str);

	if (status == 0)
		_gnutls_buffer_append_str(&str,
					  _("Certificate matches. "));
	else
		_gnutls_buffer_append_str(&str,
					  _("Verification failed. "));

	if (status & DANE_VERIFY_CA_CONSTRAINTS_VIOLATED)
		_gnutls_buffer_append_str(&str,
					  _
					  ("CA constrains were violated. "));

	if (status & DANE_VERIFY_CERT_DIFFERS)
		_gnutls_buffer_append_str(&str,
					  _("The certificate differs. "));

	if (status & DANE_VERIFY_NO_DANE_INFO)
		_gnutls_buffer_append_str(&str,
					  _
					  ("There were no DANE information. "));

	ret = _gnutls_buffer_to_datum(&str, out);
	if (out->size > 0)
		out->size--;

	return ret;
}
