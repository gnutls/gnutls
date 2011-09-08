#ifndef AES_X86_H
# define AES_X86_H

#include <gnutls_int.h>

void register_x86_crypto (void);
void register_padlock_crypto(void);

#define ALIGN16(x) \
        ((void *)(((unsigned long)(x)+0x0f)&~(0x0f)))

#define AES_KEY_ALIGN_SIZE 4
#define AES_MAXNR 14
typedef struct
{
  /* We add few more integers to allow alignment 
   * on a 16-byte boundary.
   */
  uint32_t rd_key[4 * (AES_MAXNR + 1)+AES_KEY_ALIGN_SIZE];
  uint32_t rounds;
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


extern const gnutls_crypto_cipher_st aes_gcm_struct;

#endif
