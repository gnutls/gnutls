/*
 * Copyright (C) 2012 KU Leuven
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of libdane.
 *
 * libdane is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unbound.h>
#include <gnutls/dane.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#define MAX_DATA_ENTRIES 4

struct dane_query_st
{
	unsigned int data_entries;
	dane_cert_usage_t usage[MAX_DATA_ENTRIES];
	dane_cert_type_t  type[MAX_DATA_ENTRIES];
	dane_match_type_t match[MAX_DATA_ENTRIES];
	gnutls_datum_t data[MAX_DATA_ENTRIES];
	struct ub_ctx* ctx;
	struct ub_result* result;
	unsigned int flags;
	dane_query_status_t status;
};

/**
 * dane_query_status:
 * @q: The query structure
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
 * @q: The query structure
 *
 * This function will return the number of entries in a query.
 *
 * Returns: The number of entries.
 **/
unsigned int dane_query_entries(dane_query_t q)
{
	return q->data_entries;
}

/**
 * dane_query_data:
 * @q: The query structure
 * @idx: The index of the query response.
 * @usage: The certificate usage (see %dane_cert_usage_t)
 * @type: The certificate type (see %dane_cert_type_t)
 * @match: The DANE matching type (see %dane_match_type_t)
 * @data: The DANE data.
 *
 * This function will provide the DANE data from the query
 * response.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int dane_query_data(dane_query_t q, unsigned int idx,
			unsigned int *usage, unsigned int *type,
			unsigned int *match, gnutls_datum_t * data)
{
	if (idx >= q->data_entries)
		return DANE_E_REQUESTED_DATA_NOT_AVAILABLE;

	if (usage)
		*usage = q->usage[idx];
	if (type)
		*type = q->type[idx];
	if (match)
		*match = q->match[idx];
	if (data) {
		data->data = q->data[idx].data;
		data->size = q->data[idx].size;
	}

	return DANE_E_SUCCESS;
}

/**
 * dane_query_init:
 * @q: The structure to be initialized
 * @flags: flags from the DANE_F_* definitions
 *
 * This function will initialize a DANE query structure.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int dane_query_init(dane_query_t* q, unsigned int flags)
{
	struct ub_ctx* ctx;
	int ret;

	*q = calloc(1, sizeof(struct dane_query_st));
	if (*q == NULL)
		return DANE_E_MEMORY_ERROR;

	ctx = ub_ctx_create();
	if(!ctx) {
		ret = DANE_E_INITIALIZATION_ERROR;
		goto cleanup;
	}
	ub_ctx_debugout(ctx, stderr);

	if (!(flags & DANE_F_IGNORE_LOCAL_RESOLVER)) {
		if( (ret=ub_ctx_resolvconf(ctx, NULL)) != 0) {
			ret = DANE_E_INITIALIZATION_ERROR;
			goto cleanup;
		}

		if( (ret=ub_ctx_hosts(ctx, NULL)) != 0) {
			ret = DANE_E_INITIALIZATION_ERROR;
			goto cleanup;
		}
	}

	/* read public keys for DNSSEC verification */
	if( (ret=ub_ctx_add_ta_file(ctx, (char*)UNBOUND_ROOT_KEY_FILE)) != 0) {
		ret = DANE_E_INITIALIZATION_ERROR;
		goto cleanup;
	}

	(*q)->ctx = ctx;
	(*q)->flags = flags;
	
	return DANE_E_SUCCESS;
cleanup:

	if (ctx)
		ub_ctx_delete(ctx);
	free(*q);
	
	return ret;
}

/**
 * dane_query_init:
 * @q: The structure to be deinitialized
 *
 * This function will deinitialize a DANE query structure.
 *
 **/
void dane_query_deinit(dane_query_t q)
{
	if (q->result)
	ub_ctx_delete(q->ctx);
		ub_resolve_free(q->result);

	free(q);
}

/**
 * dane_query_resolve_tlsa:
 * @q: The query structure
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
int dane_query_resolve_tlsa(dane_query_t q, const char* host, const char* proto, unsigned int port)
{
	char ns[1024];
	int ret;
	unsigned int i;

	if (q->result) {
		ub_resolve_free(q->result);
		q->result = NULL;
	}
	
	snprintf(ns, sizeof(ns), "_%u._%s.%s", port, proto, host);

	/* query for webserver */
	ret = ub_resolve(q->ctx, ns, 52, 1, &q->result);
	if(ret != 0) {
		return DANE_E_RESOLVING_ERROR;
	}

/* show first result */
	if(!q->result->havedata) {
		return DANE_E_NO_DANE_DATA;
	}

	i = 0;
	do {

		if (q->result->len[i] > 3)
			ret = DANE_E_SUCCESS;
		else {
			return DANE_E_RECEIVED_CORRUPT_DATA;
		}
	
		q->usage[i] = q->result->data[i][0];
		q->type[i] = q->result->data[i][1];
		q->match[i] = q->result->data[i][2];
		q->data[i].data = (void*)&q->result->data[i][3];
		q->data[i].size = q->result->len[i];
		i++;
	} while(q->result->data[i] != NULL);
	
	q->data_entries = i;

	if (q->flags & DANE_F_REQUIRE_DNSSEC) {
		if (!q->result->secure) {
			if (q->result->bogus)
				ret = DANE_E_INVALID_DNSSEC_SIG;
			else
				ret = DANE_E_NO_DNSSEC_SIG;
		}
	}

	/* show security status */
	if (q->result->secure)
		q->status = DANE_QUERY_DNSSEC_VERIFIED;
	else if (q->result->bogus)
		q->status = DANE_QUERY_BOGUS;
	else q->status = DANE_QUERY_NO_DNSSEC;

	return ret;
}

static unsigned int matches(const gnutls_datum_t *raw1, const gnutls_datum_t *raw2, 
							dane_match_type_t match)
{
uint8_t digest[64];
int ret;

	if (match == DANE_MATCH_EXACT) {
		if (raw1->size != raw2->size)
			return 0;

		if (memcmp(raw1->data, raw2->data, raw1->size) != 0)
			return 0;
		
		return 1;
	} else if (match == DANE_MATCH_SHA2_256) {

		if (raw2->size < 32)
			return 0;
		
		ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, raw1->data, raw1->size, digest);
		if (ret < 0)
			return 0;

		if (memcmp(digest, raw2->data, 32) != 0)
			return 0;
		
		return 1;
	} else if (match == DANE_MATCH_SHA2_512) {
		if (raw2->size < 64)
			return 0;
		
		ret = gnutls_hash_fast(GNUTLS_DIG_SHA512, raw1->data, raw1->size, digest);
		if (ret < 0)
			return 0;
		
		if (memcmp(digest, raw2->data, 64) != 0)
			return 0;
		
		return 1;
	}
	
	return 0;
}

static int crt_to_pubkey(const gnutls_datum_t *raw_crt, gnutls_datum_t * out)
{
gnutls_pubkey_t pub = NULL;
gnutls_x509_crt_t crt = NULL;
int ret;
size_t size;

	out->data = NULL;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
		return DANE_E_PUBKEY_ERROR;

	ret = gnutls_pubkey_init( &pub);
	if (ret < 0) {
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}
		
	ret = gnutls_x509_crt_import(crt, raw_crt, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	ret = gnutls_pubkey_import_x509(pub, crt, 0);
	if (ret < 0) {
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}

	size = 0;
	ret = gnutls_pubkey_export(pub, GNUTLS_X509_FMT_DER, NULL, &size);
	if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}
	
	out->data = malloc(size);
	if (out->data == NULL) {
		ret = DANE_E_MEMORY_ERROR;
		goto cleanup;
	}

	ret = gnutls_pubkey_export(pub, GNUTLS_X509_FMT_DER, out->data, &size);
	if (ret < 0) {
		ret = DANE_E_PUBKEY_ERROR;
		goto cleanup;
	}
	
	out->size = size;

	ret = 0;
	goto clean_certs;

cleanup:
	free(out->data);
clean_certs:
	if (pub)
		gnutls_pubkey_deinit(pub);
	if (crt)
		gnutls_x509_crt_deinit(crt);

	return ret;
}

static int verify_ca(const gnutls_datum_t *raw_crt, unsigned raw_crt_size,
					 gnutls_certificate_type_t crt_type,
					 dane_cert_type_t ctype,
					 dane_match_type_t match, gnutls_datum_t * data,
					 unsigned int *verify)
{
gnutls_datum_t pubkey = {NULL, 0};
int ret;

	if (raw_crt_size < 2)
		return DANE_E_INVALID_REQUEST;

	if (ctype == DANE_CERT_X509 && crt_type == GNUTLS_CRT_X509) {
	
		if (!matches(&raw_crt[1], data, match))
			*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;

	} else if (ctype == DANE_CERT_PK && crt_type == GNUTLS_CRT_X509) {
		ret = crt_to_pubkey(&raw_crt[1], &pubkey);
		if (ret < 0)
			goto cleanup;

		if (!matches(&pubkey, data, match))
			*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;
	}

	ret = 0;
cleanup:
	free(pubkey.data);
	return ret;
}

static int verify_ee(const gnutls_datum_t *raw_crt, gnutls_certificate_type_t crt_type,
		 dane_cert_type_t ctype, dane_match_type_t match, gnutls_datum_t * data,
		 unsigned int *verify)
{
gnutls_datum_t pubkey = {NULL, 0};
int ret;

	if (ctype == DANE_CERT_X509 && crt_type == GNUTLS_CRT_X509) {

		if (!matches(raw_crt, data, match))
			*verify |= DANE_VERIFY_CERT_DIFFERS;

	} else if (ctype == DANE_CERT_PK && crt_type == GNUTLS_CRT_X509) {

		ret = crt_to_pubkey(raw_crt, &pubkey);
		if (ret < 0)
			goto cleanup;

		if (!matches(&pubkey, data, match))
			*verify |= DANE_VERIFY_CERT_DIFFERS;
	}

	ret = 0;
cleanup:
	free(pubkey.data);
	return ret;
}

/**
 * dane_verify_crt:
 * @chain: A certificate chain
 * @chain_size: The size of the chain
 * @chain_type: The type of the certificate chain
 * @hostname: The hostname associated with the chain
 * @proto: The protocol of the service connecting (e.g. tcp)
 * @port: The port of the service connecting (e.g. 443)
 * @flags: The %DANE_F flags.
 * @verify: An OR'ed list of %dane_verify_status_t.
 *
 * This function will verify the given certificate chain against the
 * CA constrains and/or the certificate available via DANE. 
 * If no information via DANE can be obtained the flag %DANE_VERIFY_NO_DANE_INFO
 * is set. If a DNSSEC signature is not available for the DANE 
 * record then the verify flag %DANE_VERIFY_NO_DNSSEC_DATA is set.
 * 
 * Note that when verifying untrusted certificates, it is recommended to 
 * use the %DANE_F_REQUIRE_DNSSEC flag.
 * 
 * Due to the many possible options of DANE, there is no single threat
 * model countered. When notifying the user about DANE verification results
 * it may be better to mention: DANE verification did not reject the certificate,
 * rather than mentioning a successful DANE verication.
 * 
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 **/
int dane_verify_crt (
	const gnutls_datum_t *chain, unsigned chain_size,
	gnutls_certificate_type_t chain_type,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int flags, unsigned int *verify)
{
dane_query_t q;
int ret;
unsigned int usage, type, match, idx, status;
gnutls_datum_t data;
	
	if (chain_type != GNUTLS_CRT_X509)
		return DANE_E_INVALID_REQUEST;
	
	*verify = 0;
	
	ret = dane_query_init(&q, flags);
	if (ret < 0) {
		return ret;
	}
	
	ret = dane_query_resolve_tlsa(q, hostname, proto, port);
	if (ret < 0) {
		goto cleanup;
	}

	status = dane_query_status(q);
	if (status == DANE_QUERY_BOGUS) {
		*verify |= DANE_VERIFY_DNSSEC_DATA_INVALID;
		goto cleanup;
	} else if (status == DANE_QUERY_NO_DNSSEC) {
		*verify |= DANE_VERIFY_NO_DNSSEC_DATA;
		goto cleanup;
	}

	idx = 0;
	do {
		ret = dane_query_data(q, idx++, &usage, &type, &match, &data);
		if (ret == DANE_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;

		if (ret < 0) {
			goto cleanup;
		}
	
		if (usage == DANE_CERT_USAGE_LOCAL_CA || usage == DANE_CERT_USAGE_CA) {
			ret = verify_ca(chain, chain_size, chain_type, type, match, &data, verify);
			if (ret < 0)
				goto cleanup;
		
		} else if (usage == DANE_CERT_USAGE_LOCAL_EE || usage == DANE_CERT_USAGE_EE) {
			ret = verify_ee(&chain[0], chain_type, type, match, &data, verify);
			if (ret < 0)
				goto cleanup;
		}
	} while(1);

	ret = 0;

cleanup:
	dane_query_deinit(q);
	return ret;
}

/**
 * dane_verify_session_crt:
 * @session: A gnutls session
 * @hostname: The hostname associated with the chain
 * @proto: The protocol of the service connecting (e.g. tcp)
 * @port: The port of the service connecting (e.g. 443)
 * @flags: The %DANE_F flags.
 * @verify: An OR'ed list of %dane_verify_status_t.
 *
 * This function will verify session's certificate chain against the
 * CA constrains and/or the certificate available via DANE. 
 * See dane_verify_crt() for more information.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 **/
int dane_verify_session_crt (
	gnutls_session_t session,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int flags, unsigned int *verify)
{
const gnutls_datum_t *cert_list;
unsigned int cert_list_size = 0;
unsigned int type;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list_size == 0) {
		return DANE_E_NO_CERT;
	}
	
	type = gnutls_certificate_type_get(session);
	
	return dane_verify_crt(cert_list, cert_list_size, type, hostname, proto, port, flags, verify);
}
