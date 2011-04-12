/*
 * Demo on how to use /dev/ncr device for HMAC.
 *
 * Placed under public domain.
 *
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

struct aes_vectors_st {
	const uint8_t *key;
	const uint8_t *plaintext;
	const uint8_t *ciphertext;
} aes_vectors[] = {
	{
	.key =
		    (uint8_t *)
		    "\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    plaintext =
		    (uint8_t *)
		    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    ciphertext =
		    (uint8_t *)
		    "\x4b\xc3\xf8\x83\x45\x0c\x11\x3c\x64\xca\x42\xe1\x11\x2a\x9e\x87",},
	{
	.key =
		    (uint8_t *)
		    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    plaintext =
		    (uint8_t *)
		    "\xf3\x44\x81\xec\x3c\xc6\x27\xba\xcd\x5d\xc3\xfb\x08\xf2\x73\xe6",.
		    ciphertext =
		    (uint8_t *)
		    "\x03\x36\x76\x3e\x96\x6d\x92\x59\x5a\x56\x7c\xc9\xce\x53\x7f\x5e",},
	{
	.key =
		    (uint8_t *)
		    "\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59",.
		    plaintext =
		    (uint8_t *)
		    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    ciphertext =
		    (uint8_t *)
		    "\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65",},
	{
	.key =
		    (uint8_t *)
		    "\xca\xea\x65\xcd\xbb\x75\xe9\x16\x9e\xcd\x22\xeb\xe6\xe5\x46\x75",.
		    plaintext =
		    (uint8_t *)
		    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    ciphertext =
		    (uint8_t *)
		    "\x6e\x29\x20\x11\x90\x15\x2d\xf4\xee\x05\x81\x39\xde\xf6\x10\xbb",},
	{
.key =
		    (uint8_t *)
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe",.
		    plaintext =
		    (uint8_t *)
		    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.
		    ciphertext =
		    (uint8_t *)
		    "\x9b\xa4\xa9\x14\x3f\x4e\x5d\x40\x48\x52\x1c\x4f\x88\x77\xd8\x8e",},};

/* AES cipher */
static int test_aes(void)
{
	gnutls_cipher_hd_t hd;
	int ret, i, j;
	uint8_t _iv[16];
	uint8_t tmp[16];
	gnutls_datum_t key, iv;
	
	fprintf(stdout, "Tests on AES Encryption: ");
	for (i = 0; i < sizeof(aes_vectors) / sizeof(aes_vectors[0]); i++) {
		memset(_iv, 0, sizeof(_iv));
		memset(tmp, 0, sizeof(tmp));
		key.data = (void*)aes_vectors[i].key;
		key.size = 16;
		
		iv.data = _iv;
		iv.size = 16;

		ret = gnutls_cipher_init( &hd, GNUTLS_CIPHER_AES_128_CBC, 
			&key, &iv);
		if (ret < 0) {
			fprintf(stderr, "%d: AES test %d failed\n", __LINE__, i);
			return 1;
		}
		
		ret = gnutls_cipher_encrypt2(hd, aes_vectors[i].plaintext, 16,
			tmp, 16);
		if (ret < 0) {
			fprintf(stderr, "%d: AES test %d failed\n", __LINE__, i);
			return 1;
		}
		
		gnutls_cipher_deinit(hd);

		if (memcmp(tmp, aes_vectors[i].ciphertext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Cipher[%d]: ", 16);
			for (j = 0; j < 16; j++)
				fprintf(stderr, "%.2x:", (int)tmp[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", 16);
			for (j = 0; j < 16; j++)
				fprintf(stderr, "%.2x:",
					(int)aes_vectors[i].ciphertext[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}
	fprintf(stdout, "ok\n");

	fprintf(stdout, "Tests on AES Decryption: ");
	for (i = 0; i < sizeof(aes_vectors) / sizeof(aes_vectors[0]); i++) {

		memset(_iv, 0, sizeof(_iv));
		memset(tmp, 0x33, sizeof(tmp));

		key.data = (void*)aes_vectors[i].key;
		key.size = 16;
		
		iv.data = _iv;
		iv.size = 16;

		ret = gnutls_cipher_init( &hd, GNUTLS_CIPHER_AES_128_CBC, 
			&key, &iv);
		if (ret < 0) {
			fprintf(stderr, "%d: AES test %d failed\n", __LINE__, i);
			return 1;
		}
		
		ret = gnutls_cipher_decrypt2(hd, aes_vectors[i].ciphertext, 16,
			tmp, 16);
		if (ret < 0) {
			fprintf(stderr, "%d: AES test %d failed\n", __LINE__, i);
			return 1;
		}
		
		gnutls_cipher_deinit(hd);

		if (memcmp(tmp, aes_vectors[i].plaintext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Plain[%d]: ", 16);
			for (j = 0; j < 16; j++)
				fprintf(stderr, "%.2x:", (int)tmp[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", 16);
			for (j = 0; j < 16; j++)
				fprintf(stderr, "%.2x:",
					(int)aes_vectors[i].plaintext[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}

	fprintf(stdout, "ok\n");
	fprintf(stdout, "\n");

	return 0;

}

struct hash_vectors_st {
	const char * name;
	int algorithm;
	const uint8_t *key;	/* if hmac */
	int key_size;
	const uint8_t *plaintext;
	int plaintext_size;
	const uint8_t *output;
	int output_size;
} hash_vectors[] = {
	{
	.name = "SHA1",
	.algorithm = GNUTLS_MAC_SHA1,.key = NULL,.plaintext =
		    (uint8_t *) "what do ya want for nothing?",.
		    plaintext_size =
		    sizeof("what do ya want for nothing?") - 1,.output =
		    (uint8_t *)
		    "\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32",.
		    output_size = 20,}
	, {
	.name = "HMAC-MD5",
	.algorithm = GNUTLS_MAC_MD5,.key = (uint8_t *) "Jefe",.key_size =
		    4,.plaintext =
		    (uint8_t *) "what do ya want for nothing?",.
		    plaintext_size =
		    sizeof("what do ya want for nothing?") - 1,.output =
		    (uint8_t *)
		    "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",.
		    output_size = 16,}
	,
	    /* from rfc4231 */
	{
	.name = "HMAC-SHA2-224",
	.algorithm = GNUTLS_MAC_SHA224,.key =
		    (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output =
		    (uint8_t *)
		    "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",.
		    output_size = 28,}
	, {
	.name = "HMAC-SHA2-256",
	.algorithm = GNUTLS_MAC_SHA256,.key =
		    (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output =
		    (uint8_t *)
		    "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",.
		    output_size = 32,}
	, {
	.name = "HMAC-SHA2-384",
	.algorithm = GNUTLS_MAC_SHA384,.key =
		    (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output =
		    (uint8_t *)
		    "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",.
		    output_size = 48,}
	, {
	.name = "HMAC-SHA2-512",
	.algorithm = GNUTLS_MAC_SHA512,.key =
		    (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output =
		    (uint8_t *)
		    "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",.
		    output_size = 64,}
,};

#define HASH_DATA_SIZE 64

/* SHA1 and other hashes */
static int test_hash(void)
{
	uint8_t data[HASH_DATA_SIZE];
	int i, j, ret;
	size_t data_size;

	fprintf(stdout, "Tests on Hashes\n");
	for (i = 0; i < sizeof(hash_vectors) / sizeof(hash_vectors[0]); i++) {

		fprintf(stdout, "\t%s: ", hash_vectors[i].name);
		/* import key */
		if (hash_vectors[i].key != NULL) {

			ret = gnutls_hmac_fast( hash_vectors[i].algorithm,
				hash_vectors[i].key, hash_vectors[i].key_size,
				hash_vectors[i].plaintext, hash_vectors[i].plaintext_size,
				data);
			data_size = gnutls_hmac_get_len(hash_vectors[i].algorithm);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}
		} else {
			ret = gnutls_hash_fast( hash_vectors[i].algorithm,
				hash_vectors[i].plaintext, hash_vectors[i].plaintext_size,
				data);
			data_size = gnutls_hash_get_len(hash_vectors[i].algorithm);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}
		}

		if (data_size != hash_vectors[i].output_size ||
		    memcmp(data, hash_vectors[i].output,
			   hash_vectors[i].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n", i);

			fprintf(stderr, "Output[%d]: ", (int)data_size);
			for (j = 0; j < data_size; j++)
				fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ",
				hash_vectors[i].output_size);
			for (j = 0; j < hash_vectors[i].output_size; j++)
				fprintf(stderr, "%.2x:",
					(int)hash_vectors[i].output[j]);
			fprintf(stderr, "\n");
			return 1;
		}
		
		fprintf(stdout, "ok\n");
	}

	fprintf(stdout, "\n");

	return 0;

}


int main(int argc, char** argv)
{
        gnutls_global_init();

	if (test_aes())
		return 1;

	if (test_hash())
		return 1;

        gnutls_global_deinit();
	return 0;
}
