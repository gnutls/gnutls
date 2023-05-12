#include "gnutls_int.h"
#include <gnutls/ct.h>
#include <gnutls/crypto.h>
#include <nettle/base64.h>
#include <gnutls/x509-ext.h>

#define SCT_V1_LOGID_SIZE 32

struct ct_log_st {
	char *name;
	char *description;
	gnutls_pubkey_t public_key;
	uint8_t id[SCT_V1_LOGID_SIZE];
	time_t not_before, not_after;
};

struct gnutls_ct_logs_st {
	struct ct_log_st *logs;
	size_t size;
};

static int _gnutls_ct_add_log(struct ct_log_st *log,
			      struct ct_log_st **logs, size_t *size)
{
	struct ct_log_st *new_logs;

	new_logs =
		_gnutls_reallocarray(*logs, *size + 1, sizeof(struct ct_log_st));
	if (new_logs == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	memcpy(&new_logs[*size], log, sizeof(struct ct_log_st));
	(*size)++;
	*logs = new_logs;

	return 0;
}

static int _gnutls_init_log(struct ct_log_st *log,
			    const char *name, const char *description,
			    const gnutls_datum_t *pubkey_data)
{
	int retval;

	if (name && (log->name = strdup(name)) == NULL) {
		gnutls_assert();
		retval = GNUTLS_E_MEMORY_ERROR;
		goto bail;
	}
	if (description && (log->description = strdup(description)) == NULL) {
		gnutls_assert();
		retval = GNUTLS_E_MEMORY_ERROR;
		goto bail;
	}

	if ((retval = gnutls_pubkey_init(&log->public_key)) < 0) {
		gnutls_assert();
		goto bail;
	}

	if ((retval = gnutls_pubkey_import(log->public_key,
					   pubkey_data, GNUTLS_X509_FMT_DER)) < 0) {
		gnutls_assert();
		goto bail;
	}

	return 0;

bail:
	if (log->name)
		gnutls_free(log->name);
	if (log->description)
		gnutls_free(log->description);
	return gnutls_assert_val(retval);
}

static void _gnutls_free_log(struct ct_log_st *log)
{
	if (log->name)
		gnutls_free(log->name);
	if (log->description)
		gnutls_free(log->description);
	gnutls_pubkey_deinit(log->public_key);

}

static int decode_base64(const gnutls_datum_t *src, gnutls_datum_t *dst)
{
	struct base64_decode_ctx ctx;

	base64_decode_init(&ctx);

	dst->data = gnutls_malloc(BASE64_DECODE_LENGTH(src->size));
	if (!dst->data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	if (base64_decode_update(&ctx, &dst->size, dst->data, src->size, src->data) != 1) {
		gnutls_assert();
		goto bail;
	}

	if (base64_decode_final(&ctx) != 1) {
		gnutls_assert();
		goto bail;
	}

	return 0;

bail:
	gnutls_free(dst->data);
	dst->data = NULL;
	return GNUTLS_E_INVALID_UTF8_STRING;
}

static struct ct_log_st *_gnutls_lookup_log_by_id(const struct gnutls_ct_logs_st *logs, const uint8_t *log_id)
{
	struct ct_log_st *cur_log;

	for (unsigned i = 0; i < logs->size; i++) {
		cur_log = &logs->logs[i];
		if (memcmp(cur_log->id, log_id, SCT_V1_LOGID_SIZE) == 0)
			return cur_log;
	}

	return NULL;
}

static int generate_precert(const gnutls_x509_crt_t crt, gnutls_datum_t *out)
{
	int retval;
	size_t output_data_size = 0;

	retval = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER,
					NULL, &output_data_size);
	if (retval != GNUTLS_E_SHORT_MEMORY_BUFFER || output_data_size == 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if ((out->data = gnutls_malloc(output_data_size)) == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	out->size = output_data_size;

	if ((retval = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER,
					     out->data, (size_t *) &output_data_size)) < 0)
		return gnutls_assert_val(retval);

	return retval;
}

static int _gnutls_update_hash_with_precert(gnutls_hash_hd_t md, uint64_t timestamp,
					    const uint8_t *crtder, uint32_t crtder_len,
					    const gnutls_datum_t *issuer_key_hash,
					    const uint8_t *extensions, size_t extensions_len)
{
	int retval;
	uint8_t three_bytes[3] = { 0x00, 0x00, 0x01 };
	uint8_t u16_be[sizeof(uint16_t)], u32_be[sizeof(uint32_t)], u64_be[sizeof(uint64_t)];

	if ((retval = gnutls_hash(md, three_bytes, 2)) < 0)
		return gnutls_assert_val(retval);

	_gnutls_write_uint64(timestamp, u64_be);
	if ((retval = gnutls_hash(md, timestamp, sizeof(timestamp))) < 0)
		return gnutls_assert_val(retval);

	if ((retval = gnutls_hash(md, &three_bytes[1], 2)) < 0)
		return gnutls_assert_val(retval);

	/* Issuer key hash */
	if ((retval = gnutls_hash(md, issuer_key_hash->data, issuer_key_hash->size)) < 0)
		return gnutls_assert_val(retval);

	/* Certificate in DER encoding, with length prefix */
	_gnutls_write_uint24(crtder_len, u32_be);
	if ((retval = gnutls_hash(md, &u32_be[1], 3)) < 0)
		return gnutls_assert_val(retval);
	if ((retval = gnutls_hash(md, crtder, crtder_len)) < 0)
		return gnutls_assert_val(retval);

	/* Extensions, with length prefix */
	/* TODO complete this */

	return 0;
}

static int _gnutls_ct_sct_verify_precert(const gnutls_datum_t *precert_digest, const gnutls_datum_t *signature,
					 gnutls_sign_algorithm_t algo, const struct ct_log_st *log,
					 gnutls_time_func time_func)
{
	time_t curtime;

	if (time_func)
		curtime = time_func(NULL);

	if (time_func && log->not_before > curtime)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	if (time_func && log->not_after < curtime)
		return gnutls_assert_val(GNUTLS_E_EXPIRED);

	/* if (gnutls_pubkey_verify_data2(&log.public_key, algo, 0, precert, signature) < 0) */
	/* 	return gnutls_assert_val(GNUTLS_E_PK_SIG_VERIFY_FAILED); */
	if (gnutls_pubkey_verify_hash2(log->public_key, algo, 0, precert_digest, signature) < 0)
		return gnutls_assert_val(GNUTLS_E_PK_SIG_VERIFY_FAILED);

	return 0;
}

int gnutls_ct_logs_init(gnutls_ct_logs_t * logs)
{
	if (!logs)
		return GNUTLS_E_INVALID_REQUEST;

	*logs = gnutls_malloc(sizeof(struct gnutls_ct_logs_st));
	if (!*logs)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	(*logs)->logs = NULL;
	(*logs)->size = 0;

	return 0;
}

void gnutls_ct_logs_deinit(gnutls_ct_logs_t logs)
{
	if (logs) {
		if (logs->size > 0) {
			for (unsigned i = 0; i < logs->size; i++)
				_gnutls_free_log(&logs->logs[i]);
		}
		gnutls_free(logs->logs);
		gnutls_free(logs);
	}
}

int gnutls_ct_sct_validate(const gnutls_x509_ct_scts_t scts, unsigned idx,
			   const gnutls_ct_logs_t logs,
			   gnutls_x509_crt_t crt, gnutls_time_func time_func)
{
	int retval;
	time_t timestamp;
	gnutls_sign_algorithm_t sigalg;
	gnutls_datum_t logid, signature;
	gnutls_hash_hd_t md;
	struct ct_log_st *log;
	uint8_t signed_data_digest[gnutls_hash_get_len(GNUTLS_DIG_SHA256)];
	gnutls_datum_t signed_data_digest_datum = {
		.data = signed_data_digest,
		.size = gnutls_hash_get_len(GNUTLS_DIG_SHA256)
	};
	gnutls_datum_t ikey_hash, crtder = {
		.data = NULL,
		.size = 0
	};

	if ((retval = gnutls_x509_ct_sct_get(scts, idx,
					     &timestamp, &logid, &sigalg, &signature)) < 0) {
		gnutls_assert();
		return retval;
	}

	if (logid.size != SCT_V1_LOGID_SIZE)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	/* Lookup the log */
	if ((log = _gnutls_lookup_log_by_id(logs, logid.data)) == NULL)
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

	if ((retval = gnutls_hash_init(&md, GNUTLS_DIG_SHA256)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Compute preCert as DER */
	if ((retval = generate_precert(crt, &crtder)) < 0) {
		gnutls_assert();
		goto bail;
	}

	if ((retval = _gnutls_update_hash_with_precert(md, timestamp,
						       crtder.data, crtder.size, &ikey_hash,
						       NULL, 0)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* gnutls_hash_output(md, signed_data_digest); */
	gnutls_hash_deinit(md, signed_data_digest);

	/* if ((retval = gnutls_pubkey_verify_hash2(log->public_key, log->sign_algo, 0, */
	/* 					 &signed_data_digest_datum, &signature)) < 0) */
	/* 	return gnutls_assert_val(retval); */

	return _gnutls_ct_sct_verify_precert(&signed_data_digest_datum, &signature, sigalg, log, time_func);

bail:
	gnutls_hash_deinit(md, NULL);
	_gnutls_free_datum(&crtder);
	return retval;
}

int gnutls_ct_add_log(gnutls_ct_logs_t logs,
		      const char *name, const char *description,
		      const gnutls_datum_t *key,
		      time_t not_before, time_t not_after,
		      unsigned flags)
{
	int retval;
	struct ct_log_st ct_log;
	gnutls_datum_t realkey;
	bool realkey_must_be_freed = 0;

	if (!logs || !key || !key->data || !key->size)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	memset(&ct_log, 0, sizeof(struct ct_log_st));

	/*
	 * If key is in base64, decode it first.
	 * This will allocate new memory that must be freed after public key import.
	 */
	if (flags == GNUTLS_CT_KEY_AS_BASE64) {
		if ((retval = decode_base64(key, &realkey)) < 0) {
			gnutls_assert();
			goto bail;
		}

		key = &realkey;
		realkey_must_be_freed = 1;
	}

	if ((retval = _gnutls_init_log(&ct_log, name, description, key)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Pre-compute key's SHA-256 hash for faster lookup later */
	if ((retval = gnutls_hash_fast(GNUTLS_DIG_SHA256,
				       key->data, key->size, ct_log.id)) < 0) {
		gnutls_assert();
		goto bail;
	}

	if ((retval = _gnutls_ct_add_log(&ct_log, &logs->logs, &logs->size)) < 0) {
		gnutls_assert();
		goto bail;
	}

	retval = 0;

bail:
	if (realkey_must_be_freed)
		_gnutls_free_datum(&realkey);
	return retval;
}
