#ifndef NETTLE_TESTUTILS_H_INCLUDED
#define NETTLE_TESTUTILS_H_INCLUDED

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "nettle-types.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if HAVE_LIBGMP
# include "bignum.h"
#endif

#if WITH_PUBLIC_KEY
# include "rsa.h"
# include "dsa.h"
#endif

#include "nettle-meta.h"

void *
xalloc(size_t size);

/* Decodes a NUL-terminated hex string. */

unsigned
decode_hex_length(const char *hex);

int
decode_hex(uint8_t *dst, const char *hex);

/* Allocates space */
const uint8_t *
decode_hex_dup(const char *hex);

void
print_hex(unsigned length, const uint8_t *data);

/* The main program */
int
test_main(void);

extern int verbose;

void
test_cipher(const struct nettle_cipher *cipher,
	    unsigned key_length,
	    const uint8_t *key,
	    unsigned length,
	    const uint8_t *cleartext,
	    const uint8_t *ciphertext);

void
test_cipher_cbc(const struct nettle_cipher *cipher,
		unsigned key_length,
		const uint8_t *key,
		unsigned length,
		const uint8_t *cleartext,
		const uint8_t *ciphertext,
		const uint8_t *iv);

void
test_cipher_stream(const struct nettle_cipher *cipher,
		   unsigned key_length,
		   const uint8_t *key,
		   unsigned length,
		   const uint8_t *cleartext,
		   const uint8_t *ciphertext);

void
test_hash(const struct nettle_hash *hash,
	  unsigned length,
	  const uint8_t *data,
	  const uint8_t *digest);

void
test_armor(const struct nettle_armor *armor,
           unsigned data_length,
           const uint8_t *data,
           const uint8_t *ascii);

#if WITH_PUBLIC_KEY
void
test_rsa_set_key_1(struct rsa_public_key *pub,
		   struct rsa_private_key *key);

void
test_rsa_md5(struct rsa_public_key *pub,
	     struct rsa_private_key *key,
	     mpz_t expected);

void
test_rsa_sha1(struct rsa_public_key *pub,
	      struct rsa_private_key *key,
	      mpz_t expected);

void
test_rsa_key(struct rsa_public_key *pub,
	     struct rsa_private_key *key);

void
test_dsa(const struct dsa_public_key *pub,
	 const struct dsa_private_key *key);

void
test_dsa_key(struct dsa_public_key *pub,
	     struct dsa_private_key *key);

#endif /* WITH_PUBLIC_KEY */

#define H2(d, s) decode_hex((d), (s))
#define H(x) decode_hex_dup(x)
#define HL(x) decode_hex_length(x), decode_hex_dup(x)

/* LDATA needs to handle NUL characters. */
#define LLENGTH(x) (sizeof(x) - 1)
#define LDATA(x) (sizeof(x) - 1), x
#define LDUP(x) strlen(x), strdup(x)

#define MEMEQ(length, a, b) (!memcmp((a), (b), (length)))
#define MEMEQH(length, a, b) \
((length) == decode_hex_length((b)) \
 && !memcmp((a), decode_hex_dup((b)), (length)))

#define FAIL() abort()
#define SKIP() exit(77)
#define SUCCESS() return EXIT_SUCCESS

#define ASSERT(x) do { if (!(x)) FAIL(); } while(0)

#endif /* NETTLE_TESTUTILS_H_INCLUDED */
