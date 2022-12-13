#include "gnutls_int.h"
#include "secrets.h"
#include "dtls13.h"
#include "secrets.h"

#define DTLS_SUPP_EPOCHS 4 //TODO adjust, see 4.2.1. Processing Guidelines
#define DTLS_SEQ_NUM_LIM 64

/* This function returns epoch number based on the last two bits of DTLS13
 * unified header flags (epoch_lob)
 */
// TODO: can we receive new epoch?
uint16_t _dtls13_resolve_epoch(gnutls_session_t session, uint8_t epoch_bits)
{
	uint16_t mask = 0x0003;
	uint16_t current = session->security_parameters.epoch_read;

	for (uint16_t e = current; e > (current - DTLS_SUPP_EPOCHS); e--) {
		if ( e == 0) break;
		if ((uint8_t)(e & mask) == epoch_bits)
			return e;
	}

	return 0; // This will fail on epoch check
}


int _dtls13_resolve_seq_num(gnutls_session_t session, uint64_t *seq_num,
			    uint8_t seq_bits_size, const void *ciphertext,
			    ssize_t ciphertext_size)
{
	int ret;
	record_parameters_st *params;
	uint16_t sn_bits = *(uint16_t*)seq_num;
	uint64_t exp_sn, bit_mask = 0;

	ret = _gnutls_epoch_get(session, EPOCH_READ_CURRENT, &params);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _dtls13_encrypt_seq_num(&sn_bits, seq_bits_size,
				      ciphertext, ciphertext_size, params, 1);
	if (ret < 0)
		return ret;

	bit_mask |= (seq_bits_size) ? 0xffff : 0xff;

	exp_sn = params->read.sequence_number;
	for (uint64_t sn = exp_sn; sn < exp_sn + DTLS_SEQ_NUM_LIM; sn++) {
		if ((uint16_t)(sn & bit_mask) == sn_bits) {
			*seq_num = sn;
			return 0;
		}
	}

	return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

}

//TODO: chachapoly
int _dtls13_encrypt_seq_num(uint16_t *sn_bits, uint8_t sn_bits_size,
			    const void *ciphertext, ssize_t ciphertext_size,
			    record_parameters_st *params, uint8_t read)
{
	int ret;
	gnutls_cipher_hd_t cipher;
	uint8_t dec_text[16];
	uint8_t empty_iv[MAX_CIPHER_IV_SIZE];

	memset(empty_iv, 0, MAX_CIPHER_IV_SIZE);

	gnutls_datum_t key;
	gnutls_datum_t iv = {empty_iv, sizeof(empty_iv)};

	if (read) {
		key.data = params->read.sn_key;
		key.size = params->read.sn_key_size;
	} else {
		key.data = params->write.sn_key;
		key.size = params->write.sn_key_size;
	}

	/* ECB is not available so we use CCM with empty IV */
	ret = gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
	if (ret < 0) {
		_gnutls_record_log("DTLS1.3: failed to decrypt sequence number %s: cipher failed\n", gnutls_strerror(ret));
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ret = gnutls_cipher_encrypt2(cipher, ciphertext, 16, (void*)dec_text, 16);
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	uint8_t tmp[32];
	_gnutls_hard_log("INT: dtls13: SN ciphertext: %s\n",
			 _gnutls_bin2hex(ciphertext, 16, (char *)tmp, sizeof(tmp), NULL));
	_gnutls_hard_log("INT: dtls13: SN mask: %s\n",
			 _gnutls_bin2hex(dec_text, sn_bits_size ? 2 : 1, (char *)tmp, sizeof(tmp), NULL));

	if (sn_bits_size) { // 16bit
		uint16_t mask = (dec_text[0] << 8) | dec_text[1];
		*sn_bits ^= mask;
	} else {
		*dec_text = *dec_text >> 8;
		*sn_bits ^= *dec_text;
	}

	return 0;
}

int gnutls_dtls13_recv_ack(gnutls_session_t session)
{
	int ret;
	uint16_t record_number;
	uint8_t data[1024];
	uint64_t seq_num;

	ret = _gnutls_recv_int(session, GNUTLS_ACK,
				data, 1024, &seq_num,
				session->internals.record_timeout_ms);

	return ret;
}
