/*
 * Copyright (C) 2012 KU Leuven
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
#include <unbound.h>
#include <gnutls/dane.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include "../lib/gnutls_int.h"

#define MAX_DATA_ENTRIES 4

#ifdef DEBUG
# define gnutls_assert() fprintf(stderr, "ASSERT: %s: %d\n", __FILE__, __LINE__);
# define gnutls_assert_val(x) gnutls_assert_val_int(x, __FILE__, __LINE__)
static int gnutls_assert_val_int (int val, const char *file, int line)
{
  fprintf(stderr, "ASSERT: %s: %d\n", file, line);
  return val;
}
#else
# define gnutls_assert()
# define gnutls_assert_val(x) (x)
#endif

struct dane_state_st
{
	struct ub_ctx* ctx;
	unsigned int flags;
};

struct dane_query_st
{
        struct ub_result* result;
	unsigned int data_entries;
	dane_cert_usage_t usage[MAX_DATA_ENTRIES];
	dane_cert_type_t  type[MAX_DATA_ENTRIES];
	dane_match_type_t match[MAX_DATA_ENTRIES];
	gnutls_datum_t data[MAX_DATA_ENTRIES];
	unsigned int flags;
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
	return q->data_entries;
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
		return gnutls_assert_val(DANE_E_REQUESTED_DATA_NOT_AVAILABLE);

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
 * dane_state_init:
 * @s: The structure to be initialized
 * @flags: flags from the %dane_state_flags enumeration
 *
 * This function will initialize a DANE query structure.
 *
 * Returns: On success, %DANE_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int dane_state_init(dane_state_t* s, unsigned int flags)
{
	struct ub_ctx* ctx;
	int ret;

	*s = calloc(1, sizeof(struct dane_state_st));
	if (*s == NULL)
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);

	ctx = ub_ctx_create();
	if(!ctx) {
                gnutls_assert();
		ret = DANE_E_INITIALIZATION_ERROR;
		goto cleanup;
	}
	ub_ctx_debugout(ctx, stderr);

	if (!(flags & DANE_F_IGNORE_LOCAL_RESOLVER)) {
		if( (ret=ub_ctx_resolvconf(ctx, NULL)) != 0) {
		        gnutls_assert();
			ret = DANE_E_INITIALIZATION_ERROR;
			goto cleanup;
		}

		if( (ret=ub_ctx_hosts(ctx, NULL)) != 0) {
		        gnutls_assert();
			ret = DANE_E_INITIALIZATION_ERROR;
			goto cleanup;
		}
	}

	/* read public keys for DNSSEC verification */
	if( (ret=ub_ctx_add_ta_file(ctx, (char*)UNBOUND_ROOT_KEY_FILE)) != 0) {
	        gnutls_assert();
		ret = DANE_E_INITIALIZATION_ERROR;
		goto cleanup;
	}

	(*s)->ctx = ctx;
	(*s)->flags = flags;
	
	return DANE_E_SUCCESS;
cleanup:

	if (ctx)
		ub_ctx_delete(ctx);
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
	ub_ctx_delete(s->ctx);
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
int dane_state_set_dlv_file(dane_state_t s, const char* file)
{
int ret;
  
  ret = ub_ctx_set_option(s->ctx, (char*)"dlv-anchor-file:", (void*)file);
  if (ret != 0)
    return gnutls_assert_val(DANE_E_FILE_ERROR);
  
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
	ub_resolve_free(q->result);
	free(q);
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
int dane_query_tlsa(dane_state_t s, dane_query_t *r, const char* host, const char* proto, unsigned int port)
{
	char ns[1024];
	int ret;
	unsigned int i;

	*r = calloc(1, sizeof(struct dane_query_st));
	if (*r == NULL)
		return gnutls_assert_val(DANE_E_MEMORY_ERROR);

	snprintf(ns, sizeof(ns), "_%u._%s.%s", port, proto, host);

	/* query for webserver */
	ret = ub_resolve(s->ctx, ns, 52, 1, &(*r)->result);
	if(ret != 0) {
		return gnutls_assert_val(DANE_E_RESOLVING_ERROR);
	}

/* show first result */
	if(!(*r)->result->havedata) {
		return gnutls_assert_val(DANE_E_NO_DANE_DATA);
	}

	i = 0;
	do {

		if ((*r)->result->len[i] > 3)
			ret = DANE_E_SUCCESS;
		else {
			return gnutls_assert_val(DANE_E_RECEIVED_CORRUPT_DATA);
		}
	
		(*r)->usage[i] = (*r)->result->data[i][0];
		(*r)->type[i] = (*r)->result->data[i][1];
		(*r)->match[i] = (*r)->result->data[i][2];
		(*r)->data[i].data = (void*)&(*r)->result->data[i][3];
		(*r)->data[i].size = (*r)->result->len[i] - 3;
		i++;
	} while((*r)->result->data[i] != NULL);
	
	(*r)->data_entries = i;

	if (!(s->flags & DANE_F_INSECURE) && !(*r)->result->secure) {
		if ((*r)->result->bogus)
			ret = gnutls_assert_val(DANE_E_INVALID_DNSSEC_SIG);
		else
			ret = gnutls_assert_val(DANE_E_NO_DNSSEC_SIG);
	}

	/* show security status */
	if ((*r)->result->secure) {
		(*r)->status = DANE_QUERY_DNSSEC_VERIFIED;
	} else if ((*r)->result->bogus) {
	        gnutls_assert();
		(*r)->status = DANE_QUERY_BOGUS;
	} else {
	        gnutls_assert();
	        (*r)->status = DANE_QUERY_NO_DNSSEC;
        }

	return ret;
}

static unsigned int matches(const gnutls_datum_t *raw1, const gnutls_datum_t *raw2, 
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
		
		ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, raw1->data, raw1->size, digest);
		if (ret < 0)
			return gnutls_assert_val(0);

		if (memcmp(digest, raw2->data, 32) != 0)
			return gnutls_assert_val(0);
		
		return 1;
	} else if (match == DANE_MATCH_SHA2_512) {
		if (raw2->size != 64)
			return gnutls_assert_val(0);
		
		ret = gnutls_hash_fast(GNUTLS_DIG_SHA512, raw1->data, raw1->size, digest);
		if (ret < 0)
			return gnutls_assert_val(0);
		
		if (memcmp(digest, raw2->data, 64) != 0)
			return gnutls_assert_val(0);
		
		return 1;
	}
	
	return gnutls_assert_val(0);
}

static int crt_to_pubkey(const gnutls_datum_t *raw_crt, gnutls_datum_t * out)
{
gnutls_pubkey_t pub = NULL;
gnutls_x509_crt_t crt = NULL;
int ret;

	out->data = NULL;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
		return gnutls_assert_val(DANE_E_PUBKEY_ERROR);

	ret = gnutls_pubkey_init( &pub);
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
unsigned int vstatus;
gnutls_x509_crt_t crt = NULL, ca = NULL;

	if (raw_crt_size < 2)
		return gnutls_assert_val(DANE_E_INVALID_REQUEST);

	if (ctype == DANE_CERT_X509 && crt_type == GNUTLS_CRT_X509) {
	
		if (!matches(&raw_crt[1], data, match)) {
		        gnutls_assert();
			*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;
                }

	} else if (ctype == DANE_CERT_PK && crt_type == GNUTLS_CRT_X509) {
		ret = crt_to_pubkey(&raw_crt[1], &pubkey);
		if (ret < 0) {
        	        gnutls_assert();
			goto cleanup;
                }

		if (!matches(&pubkey, data, match)) {
                        gnutls_assert();
			*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;
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

	ret = gnutls_x509_crt_import(crt, &raw_crt[0], GNUTLS_X509_FMT_DER);
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
		*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;
	}

	ret = gnutls_x509_crt_verify(crt, &ca, 1, 0, &vstatus);
	if (ret < 0) {
  	  	ret = gnutls_assert_val(DANE_E_CERT_ERROR);
  	  	goto cleanup;
	}
	if (vstatus != 0)
		*verify |= DANE_VERIFY_CA_CONSTRAINS_VIOLATED;

	ret = 0;
cleanup:
	free(pubkey.data);
	if (crt != NULL)
	  gnutls_x509_crt_deinit(crt);
	if (ca != NULL)
	  gnutls_x509_crt_deinit(ca);
	return ret;
}

static int verify_ee(const gnutls_datum_t *raw_crt, gnutls_certificate_type_t crt_type,
		 dane_cert_type_t ctype, dane_match_type_t match, gnutls_datum_t * data,
		 unsigned int *verify)
{
gnutls_datum_t pubkey = {NULL, 0};
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
int dane_verify_crt (dane_state_t s,
	const gnutls_datum_t *chain, unsigned chain_size,
	gnutls_certificate_type_t chain_type,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int sflags, unsigned int vflags,
	unsigned int *verify)
{
dane_state_t _s = NULL;
dane_query_t r = NULL;
int ret;
unsigned checked = 0;
unsigned int usage, type, match, idx;
gnutls_datum_t data;
	
	if (chain_type != GNUTLS_CRT_X509)
		return gnutls_assert_val(DANE_E_INVALID_REQUEST);
	
	*verify = 0;
	
	if (s == NULL) {
		ret = dane_state_init(&_s, sflags);
		if (ret < 0) {
		        gnutls_assert();
			return ret;
		}
	} else
		_s = s;
	
	ret = dane_query_tlsa(_s, &r, hostname, proto, port);
	if (ret < 0) {
	        gnutls_assert();
		goto cleanup;
	}

	idx = 0;
	do {
		ret = dane_query_data(r, idx++, &usage, &type, &match, &data);
		if (ret == DANE_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
		
		if (!(vflags & DANE_VFLAG_ONLY_CHECK_EE_USAGE) && (usage == DANE_CERT_USAGE_LOCAL_CA || usage == DANE_CERT_USAGE_CA)) {
			ret = verify_ca(chain, chain_size, chain_type, type, match, &data, verify);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
                        }
                        checked = 1;
		} else if (!(vflags & DANE_VFLAG_ONLY_CHECK_CA_USAGE) && (usage == DANE_CERT_USAGE_LOCAL_EE || usage == DANE_CERT_USAGE_EE)) {
			ret = verify_ee(&chain[0], chain_type, type, match, &data, verify);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
                        }
                        checked = 1;
		}
	} while(1);

	if ((vflags & DANE_VFLAG_FAIL_IF_NOT_CHECKED) && checked == 0)
		ret = gnutls_assert_val(DANE_E_REQUESTED_DATA_NOT_AVAILABLE);
	else
		ret = 0;

cleanup:
	if (s == NULL) dane_state_deinit(_s);
	if (r != NULL) dane_query_deinit(r);
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
 * @vflags: Verification flags; should be zero
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
        dane_state_t s,
	gnutls_session_t session,
	const char * hostname, const char* proto, unsigned int port,
	unsigned int sflags, unsigned int vflags,
	unsigned int *verify)
{
const gnutls_datum_t *cert_list;
unsigned int cert_list_size = 0;
unsigned int type;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list_size == 0) {
		return gnutls_assert_val(DANE_E_NO_CERT);
	}
	
	type = gnutls_certificate_type_get(session);
	
	return dane_verify_crt(s, cert_list, cert_list_size, type, hostname, proto, port, sflags, vflags, verify);
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
dane_verification_status_print (unsigned int status,
                       gnutls_datum_t * out, unsigned int flags)
{
  gnutls_buffer_st str;
  int ret;

  _gnutls_buffer_init (&str);

  if (status == 0)
    _gnutls_buffer_append_str (&str, _("Certificate matches. "));
  else
    _gnutls_buffer_append_str (&str, _("Verification failed. "));

  if (status & DANE_VERIFY_CA_CONSTRAINS_VIOLATED)
    _gnutls_buffer_append_str (&str, _("CA constrains were violated. "));

  if (status & DANE_VERIFY_CERT_DIFFERS)
    _gnutls_buffer_append_str (&str, _("The certificate differs. "));

  if (status & DANE_VERIFY_NO_DANE_INFO)
    _gnutls_buffer_append_str (&str, _("There were no DANE information. "));

  ret = _gnutls_buffer_to_datum( &str, out);
  if (out->size > 0) out->size--;
      
  return ret;
}
