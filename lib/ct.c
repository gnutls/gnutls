#include "gnutls_int.h"
#include "common.h"
#include "x509_int.h"
#include <alloca.h>
#include <gnutls/ct.h>
#include <gnutls/crypto.h>
#include <nettle/base64.h>
#include <gnutls/x509-ext.h>

#define SHA256_OUTPUT_SIZE 32
#define SCT_V1_LOGID_SIZE SHA256_OUTPUT_SIZE

struct gnutls_ct_log_st {
	char *name;
	gnutls_pubkey_t public_key;
	uint8_t id[SCT_V1_LOGID_SIZE];
	time_t not_before, not_after;
};

struct gnutls_ct_logs_st {
	struct gnutls_ct_log_st *logs;
	size_t size;
};

struct gnutls_ct_sct_st {
	gnutls_datum_t
		logid,
		signature;
	gnutls_sign_algorithm_t signature_algorithm;
	time_t timestamp;
};

static int _gnutls_ct_add_log(struct gnutls_ct_log_st *log,
			      struct gnutls_ct_log_st **logs, size_t *size)
{
	struct gnutls_ct_log_st *new_logs;

	new_logs =
		_gnutls_reallocarray(*logs, *size + 1, sizeof(struct gnutls_ct_log_st));
	if (new_logs == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	memcpy(&new_logs[*size], log, sizeof(struct gnutls_ct_log_st));
	(*size)++;
	*logs = new_logs;

	return 0;
}

static int _gnutls_init_log(struct gnutls_ct_log_st *log,
			    const char *name,
			    const gnutls_datum_t *pubkey_data)
{
	int retval;

	if (name && (log->name = strdup(name)) == NULL) {
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
	return gnutls_assert_val(retval);
}

static void _gnutls_free_log(struct gnutls_ct_log_st *log)
{
	gnutls_free(log->name);
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

static struct gnutls_ct_log_st *_gnutls_lookup_log_by_id(const struct gnutls_ct_logs_st *logs, const uint8_t *log_id)
{
	struct gnutls_ct_log_st *cur_log;

	for (unsigned i = 0; i < logs->size; i++) {
		cur_log = &logs->logs[i];
		if (memcmp(cur_log->id, log_id, SCT_V1_LOGID_SIZE) == 0)
			return cur_log;
	}

	return NULL;
}

static int generate_tbsCertificate(const gnutls_x509_crt_t crt, gnutls_datum_t *out)
{
	/*
	 * Generate a TBSCertificate structure.
	 * According to RFC 9162, sect. 8.1.2:
	 *
	 *   1. Remove the Transparency Information extension
	 *   2. Remove embedded v1 SCTs, identified by OID 1.3.6.1.4.1.11129.2.4.2.
	*/
	asn1_node tbsroot;
	int retval, outlen;
	unsigned char *outbuf = NULL;

	/*
	 * Create a copy of "tbsCertificate" and remove the SCT list extension,
	 * then export the resulting structure to DER.
	 */
	if ((tbsroot = asn1_dup_node(crt->cert, "tbsCertificate")) == NULL) {
		gnutls_assert();
		return -1;
	}

	if ((retval = _gnutls_delete_extension(tbsroot, GNUTLS_X509EXT_OID_CT_SCT_V1)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Query how much space we need to hold the new structure */
	outlen = 0;
	retval = asn1_der_coding(tbsroot, "tbsCertificate", NULL, &outlen, NULL);
	if (retval != ASN1_MEM_ERROR) {
		gnutls_assert();
		retval = _gnutls_asn2err(retval);
		goto bail;
	}

	/* Now outlen holds the necessary amount of space to export the DER encoding */
	if ((outbuf = gnutls_malloc(outlen)) == NULL) {
		gnutls_assert();
		retval = GNUTLS_E_MEMORY_ERROR;
		goto bail;
	}

	if ((retval = asn1_der_coding(tbsroot, "tbsCertificate", outbuf, &outlen, NULL))) {
		gnutls_assert();
		retval = _gnutls_asn2err(retval);
		goto bail;
	}

	out->size = outlen;
	out->data = outbuf;

	return 0;

bail:
	if (outbuf)
		gnutls_free(outbuf);
	asn1_delete_structure(&tbsroot);
	return retval;
}

static int compute_issuer_key_hash(const gnutls_x509_crt_t cert, uint8_t md[])
{
	int retval;

	if ((retval = gnutls_hash_fast(GNUTLS_DIG_SHA256,
				       cert->raw_spki.data, cert->raw_spki.size,
				       md)) < 0)
		return gnutls_assert_val(retval);

	return 0;
}

static int _gnutls_update_hash_with_precert(gnutls_hash_hd_t md, uint64_t timestamp,
					    const uint8_t *crtder, uint32_t crtder_len,
					    const gnutls_datum_t *issuer_key_hash,
					    const uint8_t *extensions, size_t extensions_len)
{
	int retval;
	uint8_t three_bytes[3] = { 0x00, 0x00, 0x01 };
	uint8_t u32_be[sizeof(uint32_t)], u64_be[sizeof(uint64_t)];

	/*
	 * Compute a TimestampedCertificateEntryDataV2 structure, that is,
	 * a TransItem structure of type 'precert_entry_v2'.
	 *
	 * We're dealing with SCTs included in X.509 certs here.
	 *
	 * From RFC 9162, chapt. 4.7:
	 *
	 *     struct {
         *       uint64 timestamp;
         *       opaque issuer_key_hash<32..2^8-1>;
         *       TBSCertificate tbs_certificate;
         *       Extension sct_extensions<0..2^16-1>;
    	 *     } TimestampedCertificateEntryDataV2;
	 */

	if ((retval = gnutls_hash(md, three_bytes, 2)) < 0)
		return gnutls_assert_val(retval);

	_gnutls_write_uint64(timestamp, u64_be);
	if ((retval = gnutls_hash(md, u64_be, sizeof(u64_be))) < 0)
		return gnutls_assert_val(retval);

	if ((retval = gnutls_hash(md, &three_bytes[1], 2)) < 0)
		return gnutls_assert_val(retval);

	/* Issuer key hash */
	if ((retval = gnutls_hash(md, issuer_key_hash->data, issuer_key_hash->size)) < 0)
		return gnutls_assert_val(retval);

	/* Certificate in DER encoding, with length prefix */
	_gnutls_write_uint24(crtder_len, u32_be);
	if ((retval = gnutls_hash(md, u32_be, 3)) < 0)
		return gnutls_assert_val(retval);
	if ((retval = gnutls_hash(md, crtder, crtder_len)) < 0)
		return gnutls_assert_val(retval);

	/* Extensions, with length prefix */
	if ((retval = gnutls_hash(md, three_bytes, 2)) < 0)
		return gnutls_assert_val(retval);

	return 0;
}

static int _gnutls_ct_sct_verify_precert(const gnutls_datum_t *precert_digest, const gnutls_datum_t *signature,
					 gnutls_sign_algorithm_t algo, const struct gnutls_ct_log_st *log,
					 gnutls_time_func time_func)
{
	time_t curtime;

	if (time_func)
		curtime = time_func(NULL);

	/* if (time_func && log->not_before > curtime) */
	/* 	return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST); */
	/* if (time_func && log->not_after < curtime) */
	/* 	return gnutls_assert_val(GNUTLS_E_EXPIRED); */

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

int gnutls_ct_log_init(gnutls_ct_log_t *log,
		       const char *name,
		       const gnutls_datum_t *key, int flags)
{
	int retval;
	gnutls_datum_t realkey = {
		.data = NULL,
		.size = 0
	};

	*log = gnutls_malloc(sizeof(struct gnutls_ct_log_st));
	if (!*log)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

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
	}

	if ((retval = _gnutls_init_log(*log, name, key)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Pre-compute key's SHA-256 hash for faster lookup later */
	if ((retval = gnutls_hash_fast(GNUTLS_DIG_SHA256,
				       key->data, key->size, (*log)->id)) < 0) {
		gnutls_assert();
		goto bail;
	}

	return retval;

bail:
	if (realkey.data)
		_gnutls_free_datum(&realkey);

	return retval;
}

void gnutls_ct_log_deinit(gnutls_ct_log_t log)
{
	_gnutls_free_log(log);
	gnutls_free(log);
}


int gnutls_ct_sct_init(gnutls_ct_sct_t *sct,
		       const gnutls_datum_t *logid,
		       gnutls_sign_algorithm_t signature_algorithm, const gnutls_datum_t *signature,
		       time_t timestamp)
{
	int ret;

	*sct = gnutls_malloc(sizeof(struct gnutls_ct_sct_st));
	if (!*sct)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/*
	 * Currently Log IDs are defined as the SHA-256 hash of the log's public key.
	 * Hence, they cannot be greater than the output of SHA-256.
	 */
 	if (logid->size != SCT_V1_LOGID_SIZE)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	(*sct)->logid.data = NULL;
	(*sct)->logid.size = 0;
	if ((ret = _gnutls_set_datum(&(*sct)->logid, logid->data, logid->size)) < 0) {
		gnutls_assert();
		goto bail;
	}

	if ((ret = _gnutls_set_datum(&(*sct)->signature, signature->data, signature->size)) < 0) {
		gnutls_assert();
		goto bail;
	}

	(*sct)->signature_algorithm = signature_algorithm;
	(*sct)->timestamp = timestamp;

	return 0;

bail:
	if ((*sct)->logid.data)
		_gnutls_free_datum(&(*sct)->logid);

	return ret;
}

void gnutls_ct_sct_deinit(gnutls_ct_sct_t sct)
{
	_gnutls_free_datum(&sct->logid);
	_gnutls_free_datum(&sct->signature);
	gnutls_free(sct);
}

int gnutls_ct_verify(gnutls_ct_sct_t sct,
		     gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
		     const gnutls_ct_logs_t logs,
		     char **log_name)
{
	int retval;
	gnutls_hash_hd_t md;
	gnutls_ct_log_t log;
	uint8_t signature_digest[gnutls_hash_get_len(GNUTLS_DIG_SHA256)],
		issuer_key_digest[gnutls_hash_get_len(GNUTLS_DIG_SHA256)];
	gnutls_datum_t signed_data_digest, issuer_key_hash, crtder = {
		.data = NULL,
		.size = 0
	};

	/* Lookup this SCT in the log store, by its Log ID */
	if ((log = _gnutls_lookup_log_by_id(logs, sct->logid.data)) == NULL)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (log_name)
		*log_name = log->name;  /* TODO should we copy it instead? */

	/* TODO clarify - why SHA-256? */
	if ((retval = gnutls_hash_init(&md, GNUTLS_DIG_SHA256)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Compute TBSCertificate structure, and export as DER */
	if ((retval = generate_tbsCertificate(cert, &crtder)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Compute issuer key hash - hash of the public key of the CA that issued the certificate */
	if ((retval = compute_issuer_key_hash(issuer, issuer_key_digest)) < 0) {
		gnutls_assert();
		goto bail;
	}

	/* Finally, compute the signature input */
	issuer_key_hash.data = issuer_key_digest;
	issuer_key_hash.size = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	if ((retval = _gnutls_update_hash_with_precert(md, sct->timestamp,
						       crtder.data, crtder.size, &issuer_key_hash,
						       NULL, 0)) < 0) {
		gnutls_assert();
		goto bail;
	}

	gnutls_hash_deinit(md, signature_digest);
	_gnutls_free_datum(&crtder);

	signed_data_digest.data = signature_digest;
	signed_data_digest.size = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	return _gnutls_ct_sct_verify_precert(&signed_data_digest,
					     &sct->signature, sct->signature_algorithm, log, NULL);

bail:
	gnutls_hash_deinit(md, NULL);
	_gnutls_free_datum(&crtder);
	return retval;
}

int gnutls_ct_add_log(gnutls_ct_logs_t logs, const gnutls_ct_log_t log)
{
	int retval;

	if (!logs || !log)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if ((retval = _gnutls_ct_add_log(log, &logs->logs, &logs->size)) < 0) {
		gnutls_assert();
		goto end;
	}

	retval = 0;

end:
	return retval;
}

int gnutls_ct_get_log(gnutls_ct_logs_t logs, unsigned idx,
		      gnutls_datum_t *name,
		      gnutls_pubkey_t *public_key)
{
	struct gnutls_ct_log_st *cur_log;

	if (idx >= logs->size)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	cur_log = &logs->logs[idx];

	if (name) {
		name->data = cur_log->name;
		name->size = strlen(cur_log->name);
	}
	if (public_key)
		*public_key = cur_log->public_key;

	return GNUTLS_E_SUCCESS;
}
