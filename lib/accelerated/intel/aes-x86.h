#ifndef AES_X86_H
# define AES_X86_H

#include <gnutls_int.h>

void register_x86_crypto (void);

#ifdef __GNUC__
# define ALIGN16 __attribute__ ((aligned (16)))
#else
# define ALIGN16
#endif

#define AES_MAXNR 14
typedef struct
{
  uint32_t ALIGN16 rd_key[4 * (AES_MAXNR + 1)];
  int rounds;
} AES_KEY;

void aesni_ecb_encrypt (const unsigned char *in, unsigned char *out,
                        size_t len, const AES_KEY * key,
                        int enc);

void aesni_cbc_encrypt (const unsigned char *in, unsigned char *out,
                        size_t len, const AES_KEY * key,
                        unsigned char *ivec, const int enc);
int aesni_set_decrypt_key (const unsigned char *userKey, const int bits,
                           AES_KEY * key);
int aesni_set_encrypt_key (const unsigned char *userKey, const int bits,
                           AES_KEY * key);

void aesni_ctr32_encrypt_blocks(const unsigned char *in,
                           unsigned char *out,
                           size_t blocks,
                           const void *key,
                           const unsigned char *ivec);


const gnutls_crypto_cipher_st aes_gcm_struct;

#endif
