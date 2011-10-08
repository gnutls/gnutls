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

struct aes_vectors_st
{
    const uint8_t *key;
    const uint8_t *plaintext;
    const uint8_t *ciphertext;
};

struct aes_gcm_vectors_st
{
    const uint8_t *key;
    const uint8_t *auth;
    int auth_size;
    const uint8_t *plaintext;
    int plaintext_size;
    const uint8_t *iv;
    const uint8_t *ciphertext;
    const uint8_t *tag;
};

struct aes_gcm_vectors_st aes_gcm_vectors[] = {
    {
     .key =
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .auth = NULL,
     .auth_size = 0,
     .plaintext = NULL,
     .plaintext_size = 0,
     .ciphertext = NULL,
     .iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .tag =
     "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a"},
    {
     .key =
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .auth = NULL,
     .auth_size = 0,
     .plaintext =
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .plaintext_size = 16,
     .ciphertext =
     "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
     .iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .tag =
     "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf"},
    {
     .key =
     "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
     .auth =
     "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
     .auth_size = 20,
     .plaintext =
     "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
     .plaintext_size = 60,
     .ciphertext =
     "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91",
     .iv = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
     .tag =
     "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47"}
};


struct aes_vectors_st aes_vectors[] = {
    {
     .key =
     (uint8_t *)
     "\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .plaintext = (uint8_t *)
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .ciphertext = (uint8_t *)
     "\x4b\xc3\xf8\x83\x45\x0c\x11\x3c\x64\xca\x42\xe1\x11\x2a\x9e\x87",
     },
    {
     .key = (uint8_t *)
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .plaintext = (uint8_t *)
     "\xf3\x44\x81\xec\x3c\xc6\x27\xba\xcd\x5d\xc3\xfb\x08\xf2\x73\xe6",
     .ciphertext = (uint8_t *)
     "\x03\x36\x76\x3e\x96\x6d\x92\x59\x5a\x56\x7c\xc9\xce\x53\x7f\x5e",
     },
    {
     .key = (uint8_t *)
     "\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59",
     .plaintext = (uint8_t *)
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .ciphertext = (uint8_t *)
     "\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65",
     },
    {
     .key = (uint8_t *)
     "\xca\xea\x65\xcd\xbb\x75\xe9\x16\x9e\xcd\x22\xeb\xe6\xe5\x46\x75",
     .plaintext = (uint8_t *)
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .ciphertext = (uint8_t *)
     "\x6e\x29\x20\x11\x90\x15\x2d\xf4\xee\x05\x81\x39\xde\xf6\x10\xbb",
     },
    {
     .key = (uint8_t *)
     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe",
     .plaintext = (uint8_t *)
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     .ciphertext = (uint8_t *)
     "\x9b\xa4\xa9\x14\x3f\x4e\x5d\x40\x48\x52\x1c\x4f\x88\x77\xd8\x8e",
     },
};

/* AES cipher */
static int
test_aes (void)
{
    gnutls_cipher_hd_t hd;
    int ret, i, j;
    uint8_t _iv[16];
    uint8_t tmp[128];
    gnutls_datum_t key, iv;

    fprintf (stdout, "Tests on AES Encryption: ");
    fflush (stdout);
    for (i = 0; i < sizeof (aes_vectors) / sizeof (aes_vectors[0]); i++)
      {
          memset (_iv, 0, sizeof (_iv));
          memset (tmp, 0, sizeof (tmp));
          key.data = (void *) aes_vectors[i].key;
          key.size = 16;

          iv.data = _iv;
          iv.size = 16;

          ret =
              gnutls_cipher_init (&hd, GNUTLS_CIPHER_AES_128_CBC, &key,
                                  &iv);
          if (ret < 0)
            {
                fprintf (stderr, "%d: AES test %d failed\n", __LINE__, i);
                return 1;
            }

          ret = gnutls_cipher_encrypt2 (hd, aes_vectors[i].plaintext, 16,
                                        tmp, 16);
          if (ret < 0)
            {
                fprintf (stderr, "%d: AES test %d failed\n", __LINE__, i);
                return 1;
            }

          gnutls_cipher_deinit (hd);

          if (memcmp (tmp, aes_vectors[i].ciphertext, 16) != 0)
            {
                fprintf (stderr, "AES test vector %d failed!\n", i);

                fprintf (stderr, "Cipher[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:", (int) tmp[j]);
                fprintf (stderr, "\n");

                fprintf (stderr, "Expected[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:",
                             (int) aes_vectors[i].ciphertext[j]);
                fprintf (stderr, "\n");
                return 1;
            }
      }
    fprintf (stdout, "ok\n");

    fprintf (stdout, "Tests on AES Decryption: ");
    fflush (stdout);
    for (i = 0; i < sizeof (aes_vectors) / sizeof (aes_vectors[0]); i++)
      {

          memset (_iv, 0, sizeof (_iv));
          memset (tmp, 0x33, sizeof (tmp));

          key.data = (void *) aes_vectors[i].key;
          key.size = 16;

          iv.data = _iv;
          iv.size = 16;

          ret =
              gnutls_cipher_init (&hd, GNUTLS_CIPHER_AES_128_CBC, &key,
                                  &iv);
          if (ret < 0)
            {
                fprintf (stderr, "%d: AES test %d failed\n", __LINE__, i);
                return 1;
            }

          ret = gnutls_cipher_decrypt2 (hd, aes_vectors[i].ciphertext, 16,
                                        tmp, 16);
          if (ret < 0)
            {
                fprintf (stderr, "%d: AES test %d failed\n", __LINE__, i);
                return 1;
            }

          gnutls_cipher_deinit (hd);

          if (memcmp (tmp, aes_vectors[i].plaintext, 16) != 0)
            {
                fprintf (stderr, "AES test vector %d failed!\n", i);

                fprintf (stderr, "Plain[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:", (int) tmp[j]);
                fprintf (stderr, "\n");

                fprintf (stderr, "Expected[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:",
                             (int) aes_vectors[i].plaintext[j]);
                fprintf (stderr, "\n");
                return 1;
            }
      }

    fprintf (stdout, "ok\n");
    fprintf (stdout, "\n");

    fprintf (stdout, "Tests on AES-GCM: ");
    fflush (stdout);
    for (i = 0; i < sizeof (aes_gcm_vectors) / sizeof (aes_gcm_vectors[0]);
         i++)
      {
          memset (tmp, 0, sizeof (tmp));
          key.data = (void *) aes_gcm_vectors[i].key;
          key.size = 16;

          iv.data = (void *) aes_gcm_vectors[i].iv;
          iv.size = 12;

          ret =
              gnutls_cipher_init (&hd, GNUTLS_CIPHER_AES_128_GCM, &key,
                                  &iv);
          if (ret < 0)
            {
                fprintf (stderr, "%d: AES-GCM test %d failed\n", __LINE__,
                         i);
                return 1;
            }

          if (aes_gcm_vectors[i].auth_size > 0)
            {
                ret =
                    gnutls_cipher_add_auth (hd, aes_gcm_vectors[i].auth,
                                            aes_gcm_vectors[i].auth_size);

                if (ret < 0)
                  {
                      fprintf (stderr, "%d: AES-GCM test %d failed\n",
                               __LINE__, i);
                      return 1;
                  }
            }

          if (aes_gcm_vectors[i].plaintext_size > 0)
            {
                ret =
                    gnutls_cipher_encrypt2 (hd,
                                            aes_gcm_vectors[i].plaintext,
                                            aes_gcm_vectors[i].
                                            plaintext_size, tmp,
                                            aes_gcm_vectors[i].
                                            plaintext_size);
                if (ret < 0)
                  {
                      fprintf (stderr, "%d: AES-GCM test %d failed\n",
                               __LINE__, i);
                      return 1;
                  }
            }


          if (aes_gcm_vectors[i].plaintext_size > 0)
              if (memcmp
                  (tmp, aes_gcm_vectors[i].ciphertext,
                   aes_gcm_vectors[i].plaintext_size) != 0)
                {
                    fprintf (stderr, "AES-GCM test vector %d failed!\n",
                             i);

                    fprintf (stderr, "Cipher[%d]: ",
                             aes_gcm_vectors[i].plaintext_size);
                    for (j = 0; j < aes_gcm_vectors[i].plaintext_size; j++)
                        fprintf (stderr, "%.2x:", (int) tmp[j]);
                    fprintf (stderr, "\n");

                    fprintf (stderr, "Expected[%d]: ",
                             aes_gcm_vectors[i].plaintext_size);
                    for (j = 0; j < aes_gcm_vectors[i].plaintext_size; j++)
                        fprintf (stderr, "%.2x:",
                                 (int) aes_gcm_vectors[i].ciphertext[j]);
                    fprintf (stderr, "\n");
                    return 1;
                }

          gnutls_cipher_tag (hd, tmp, 16);
          if (memcmp (tmp, aes_gcm_vectors[i].tag, 16) != 0)
            {
                fprintf (stderr, "AES-GCM test vector %d failed (tag)!\n",
                         i);

                fprintf (stderr, "Tag[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:", (int) tmp[j]);
                fprintf (stderr, "\n");

                fprintf (stderr, "Expected[%d]: ", 16);
                for (j = 0; j < 16; j++)
                    fprintf (stderr, "%.2x:",
                             (int) aes_gcm_vectors[i].tag[j]);
                fprintf (stderr, "\n");
                return 1;
            }

          gnutls_cipher_deinit (hd);

      }
    fprintf (stdout, "ok\n");
    fprintf (stdout, "\n");


    return 0;

}

struct hash_vectors_st
{
    const char *name;
    int algorithm;
    const uint8_t *key;         /* if hmac */
    int key_size;
    const uint8_t *plaintext;
    int plaintext_size;
    const uint8_t *output;
    int output_size;
} hash_vectors[] =
{
    {
      .name = "SHA1",
      .algorithm = GNUTLS_MAC_SHA1,
      .key = NULL,
      .plaintext =
            (uint8_t *) "what do ya want for nothing?",
      .plaintext_size =
            sizeof ("what do ya want for nothing?") - 1,
      .output =
            (uint8_t *)
            "\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32",
      .output_size = 20,
    },
    {
      .name = "SHA1",
      .algorithm = GNUTLS_MAC_SHA1,
      .key = NULL,
      .plaintext =
            (uint8_t *)
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      .plaintext_size = sizeof
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            - 1,
      .output =
            (uint8_t *)
            "\xbe\xae\xd1\x6d\x65\x8e\xc7\x92\x9e\xdf\xd6\x2b\xfa\xfe\xac\x29\x9f\x0d\x74\x4d",
      .output_size = 20,
    },
    {
      .name = "SHA256",
      .algorithm = GNUTLS_MAC_SHA256,
      .key = NULL,
      .plaintext =
            (uint8_t *)
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      .plaintext_size = sizeof
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            - 1,
      .output =
            (uint8_t *)
            "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
      .output_size = 32,
    },
    {
      .name = "SHA256",
      .algorithm = GNUTLS_MAC_SHA256,
      .key = NULL,
      .plaintext =
            (uint8_t *)
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      .plaintext_size = sizeof
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            - 1,
      .output =
            (uint8_t *)
            "\x50\xea\x82\x5d\x96\x84\xf4\x22\x9c\xa2\x9f\x1f\xec\x51\x15\x93\xe2\x81\xe4\x6a\x14\x0d\x81\xe0\x00\x5f\x8f\x68\x86\x69\xa0\x6c",
      .output_size = 32,
    },
    {
      .name = "SHA512",
      .algorithm = GNUTLS_MAC_SHA512,
      .key = NULL,
      .plaintext =
            (uint8_t *)
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      .plaintext_size = sizeof
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
            - 1,
      .output =
            (uint8_t *)
            "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09",
      .output_size = 64,
    },
    {
    .name = "HMAC-MD5",.algorithm = GNUTLS_MAC_MD5,.key =
            (uint8_t *) "Jefe",.key_size = 4,.plaintext =
            (uint8_t *) "what do ya want for nothing?",.
            plaintext_size =
            sizeof ("what do ya want for nothing?") - 1,.output =
            (uint8_t *)
            "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",.output_size
            = 16,}
    ,
        /* from rfc4231 */
    {
    .name = "HMAC-SHA2-224",.algorithm = GNUTLS_MAC_SHA224,.key =
            (uint8_t *)
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.key_size
            = 20,.plaintext = (uint8_t *) "Hi There",.plaintext_size =
            sizeof ("Hi There") - 1,.output =
            (uint8_t *)
            "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",.output_size
            = 28,}
    ,
    {
    .name = "HMAC-SHA2-256",.algorithm = GNUTLS_MAC_SHA256,.key =
            (uint8_t *)
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.key_size
            = 20,.plaintext = (uint8_t *) "Hi There",.plaintext_size =
            sizeof ("Hi There") - 1,.output =
            (uint8_t *)
            "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",.output_size
            = 32,}
    ,
    {
    .name = "HMAC-SHA2-384",.algorithm = GNUTLS_MAC_SHA384,.key =
            (uint8_t *)
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.key_size
            = 20,.plaintext = (uint8_t *) "Hi There",.plaintext_size =
            sizeof ("Hi There") - 1,.output =
            (uint8_t *)
            "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",.output_size
            = 48,}
    ,
    {
    .name = "HMAC-SHA2-512",.algorithm = GNUTLS_MAC_SHA512,.key =
            (uint8_t *)
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.key_size
            = 20,.plaintext = (uint8_t *) "Hi There",.plaintext_size =
            sizeof ("Hi There") - 1,.output =
            (uint8_t *)
            "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",.output_size
            = 64,}
,};

#define HASH_DATA_SIZE 64

/* SHA1 and other hashes */
static int
test_hash (void)
{
    uint8_t data[HASH_DATA_SIZE];
    int i, j, ret;
    size_t data_size;

    fprintf (stdout, "Tests on Hashes\n");
    for (i = 0; i < sizeof (hash_vectors) / sizeof (hash_vectors[0]); i++)
      {

          fprintf (stdout, "\t%s: ", hash_vectors[i].name);
          /* import key */
          if (hash_vectors[i].key != NULL)
            {
                gnutls_hmac_hd_t hd;
                ret = gnutls_hmac_init( &hd, hash_vectors[i].algorithm, hash_vectors[i].key, hash_vectors[i].key_size);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }

                ret = gnutls_hmac(hd, hash_vectors[i].plaintext, hash_vectors[i].plaintext_size-1);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }

                ret = gnutls_hmac(hd, &hash_vectors[i].plaintext[hash_vectors[i].plaintext_size-1], 1);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }

                gnutls_hmac_output(hd, data);
                gnutls_hmac_deinit(hd, NULL);

                data_size =
                    gnutls_hmac_get_len (hash_vectors[i].algorithm);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }
            }
          else
            {
                gnutls_hash_hd_t hd;
                ret = gnutls_hash_init( &hd, hash_vectors[i].algorithm);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }
                
                ret = gnutls_hash (hd,
                                        hash_vectors[i].plaintext,
                                        1);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }

                ret = gnutls_hash (hd,
                                        &hash_vectors[i].plaintext[1],
                                        hash_vectors[i].plaintext_size-1);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }

                gnutls_hash_output(hd, data);
                gnutls_hash_deinit(hd, NULL);
                
                data_size =
                    gnutls_hash_get_len (hash_vectors[i].algorithm);
                if (ret < 0)
                  {
                      fprintf (stderr, "Error: %s:%d\n", __func__,
                               __LINE__);
                      return 1;
                  }
            }

          if (data_size != hash_vectors[i].output_size ||
              memcmp (data, hash_vectors[i].output,
                      hash_vectors[i].output_size) != 0)
            {
                fprintf (stderr, "HASH test vector %d failed!\n", i);

                fprintf (stderr, "Output[%d]: ", (int) data_size);
                for (j = 0; j < data_size; j++)
                    fprintf (stderr, "%.2x:", (int) data[j]);
                fprintf (stderr, "\n");

                fprintf (stderr, "Expected[%d]: ",
                         hash_vectors[i].output_size);
                for (j = 0; j < hash_vectors[i].output_size; j++)
                    fprintf (stderr, "%.2x:",
                             (int) hash_vectors[i].output[j]);
                fprintf (stderr, "\n");
                return 1;
            }

          fprintf (stdout, "ok\n");
      }

    fprintf (stdout, "\n");

    return 0;

}

static void
tls_log_func (int level, const char *str)
{
    fprintf (stderr, "<%d>| %s", level, str);
}


int
main (int argc, char **argv)
{
    gnutls_global_set_log_function (tls_log_func);
    if (argc > 1)
        gnutls_global_set_log_level (4711);

    gnutls_global_init ();

    if (test_aes ())
        return 1;

    if (test_hash ())
        return 1;

    gnutls_global_deinit ();
    return 0;
}
