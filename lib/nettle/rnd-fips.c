/* random-fips.c - FIPS style random number generator
 * Copyright (C) 2008  Free Software Foundation, Inc.
 * Copyright (C) 2013 Red Hat
 *
 * This file is part of GnuTLS.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This is a (heavily) modified for gnutls version of the libgcrypt DRBG.
 */

/*
   The core of this deterministic random number generator is
   implemented according to the document "NIST-Recommended Random
   Number Generator Based on ANSI X9.31 Appendix A.2.4 Using the 3-Key
   Triple DES and AES Algorithms" (2005-01-31).  This implementation
   uses the AES variant.

   There are 3 random context which map to the different levels of
   random quality:

   Generator                Seed and Key        Kernel entropy (init/reseed)
   ------------------------------------------------------------
   GNUTLS_RND_KEY          /dev/random         256/128 bits
   GNUTLS_RND_RANDOM       /dev/random         256/128 bits
   GNUTLS_RND_NONCE        GNUTLS_RND_RANDOM   n/a

   All random generators return their data in 128 bit blocks.  If the
   caller requested less bits, the extra bits are not used.  The key
   for each generator is only set once at the first time a generator
   is used.  The seed value is set with the key and again after 1000
   (SEED_TTL) output blocks; the re-seeding is disabled in test mode.

   The GNUTLS_RND_KEY and GNUTLS_RND_RANDOM generators are
   keyed and seeded from the /dev/urandom device. These generators
   never block.

   In all cases the generators check for a change of PID (e.g., a fork)
   and in that case they are automatically re-keyed and re-seeded.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <assert.h>
#include <fips.h>

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <nettle/aes.h>
#include <nettle/memxor.h>
#include <hash-pjw-bare.h>
#include <locks.h>
#include <rnd-common.h>

#define RND_LOCK if (gnutls_mutex_lock(&rnd_mutex)!=0) abort()
#define RND_UNLOCK if (gnutls_mutex_unlock(&rnd_mutex)!=0) abort()

/* This is the lock we use to serialize access to this RNG.  The extra
   integer variable is only used to check the locking state; that is,
   it is not meant to be thread-safe but merely as a failsafe feature
   to assert proper locking.  */
static void *rnd_mutex;

/* After having retrieved this number of blocks from the RNG, we want
   to do a reseeding.  */
#define SEED_TTL 1000


/* This random context type is used to track properties of one random
   generator. Thee context are usually allocated in secure memory so
   that the seed value is well protected.  There are a couble of guard
   fields to help detecting applications accidently overwriting parts
   of the memory. */
struct rng_context {
	/* The handle of the cipher used by the RNG.  If this one is not
	   NULL a cipher handle along with a random key has been
	   established.  */
	struct aes_ctx cctx;

	/* If this flag is true, the SEED_V buffer below carries a valid
	   seed.  */
	uint8_t is_seeded;

	/* The very first block generated is used to compare the result
	   against the last result.  This flag indicates that such a block
	   is available.  */
	uint8_t compare_value_valid;

	/* A counter used to trigger re-seeding.  */
	unsigned int use_counter;

	/* The buffer containing the seed value V.  */
	unsigned char seed_V[16];

	/* The last result from the x931_aes function.  Only valid if
	   compare_value_valid is set.  */
	unsigned char compare_value[16];

	/* To implement a KAT we need to provide a know DT value.  To
	   accomplish this the x931_get_dt function checks whether this
	   field is not NULL and then uses the 16 bytes at this address for
	   the DT value.  However the last 4 bytes are replaced by the
	   value of field TEST_DT_COUNTER which will be incremented after
	   each invocation of x931_get_dt. We use a pointer and not a buffer
	   because there is no need to put this value into secure memory.  */
	const unsigned char *test_dt_ptr;
	uint32_t test_dt_counter;

	/* We need to keep track of the process which did the initialization
	   so that we can detect a fork.  The volatile modifier is required
	   so that the compiler does not optimize it away in case the getpid
	   function is badly attributed.  */
	pid_t pid;
};

struct fips_ctx {
	struct rng_context nonce_context;
	struct rng_context std_context;
	struct rng_context strong_context;
};

/* --- Local prototypes ---  */
static int x931_reseed(struct rng_context* rng_ctx);
static int get_random(struct rng_context* rng_ctx, void *buffer, size_t length);
static int _rngfips_reinit(struct rng_context* ctx);




/* --- Functions  --- */

/* Get the DT vector for use with the core PRNG function.  Buffer
   needs to be provided by the caller with a size of at least LENGTH
   bytes. RNG_CTX needs to be passed to allow for a KAT.  The 16 byte
   timestamp we construct is made up the real time and three counters:

   Buffer:       00112233445566778899AABBCCDDEEFF
                 !--+---!!--+---!!--+---!!--+---!
   seconds ---------/      |        |       |
   nanoseconds ------------/        |       |
                                    |       |
   counter  ------------------------/       |
   hash    --------------------------------/

   hash is a hash of all the event values (including rusage when present,
   and pid), and counter is a 32-bit running counter.
   
   The output number will be always unique if this function is called 
   less than 2^32 times per nanosecond.
*/
static void
x931_get_dt(struct rng_context *rng_ctx, unsigned char *buffer, size_t length)
{
	struct event_st event;
	uint32_t secs, usecs;
	uint32_t v1, v2;

	assert(length == 16);	/* This length is required for use with AES.  */

	/* If the random context indicates that a test DT should be used,
	   take the DT value from the context. */
	if (rng_ctx->test_dt_ptr) {
		memcpy(buffer, rng_ctx->test_dt_ptr, 16);
		buffer[12] = (rng_ctx->test_dt_counter >> 24);
		buffer[13] = (rng_ctx->test_dt_counter >> 16);
		buffer[14] = (rng_ctx->test_dt_counter >> 8);
		buffer[15] = rng_ctx->test_dt_counter;
		rng_ctx->test_dt_counter++;
		return;
	}

	_rnd_get_event(&event);
	secs = event.now.tv_sec;
	usecs = event.now.tv_nsec;
	/* v2 is a hash of all values including rusage -when present
	 * and getpid(). */
	v1 = event.count;
	v2 = hash_pjw_bare(&event, sizeof(event));
	
	memcpy(buffer, &secs, 4);
	memcpy(buffer+4, &usecs, 4);
	memcpy(buffer+8, &v1, 4);
	memcpy(buffer+12, &v2, 4);
}

/* The core ANSI X9.31, Appendix A.2.4 function using AES.  The caller
   needs to pass a 16 byte buffer for the result, the 16 byte
   datetime_DT value and the 16 byte seed value V.  The caller also
   needs to pass an appropriate KEY and make sure to pass a valid
   seed_V.  The caller also needs to provide two 16 bytes buffer for
   intermediate results, they may be reused by the caller later.

   On return the result is stored at RESULT_R and the SEED_V is
   updated.  May only be used while holding the lock.  */
static void
x931_aes(struct aes_ctx* cctx, unsigned char result_R[16], unsigned char datetime_DT[16], 
	unsigned char seed_V[16])
{
	unsigned char intermediate_I[16];
	unsigned char temp_xor[16];

	/* Let ede*X(Y) represent the AES encryption of Y under the key *X.

	   Let V be a 128-bit seed value which is also kept secret, and XOR
	   be the exclusive-or operator. Let DT be a date/time vector which
	   is updated on each iteration. I is a intermediate value.

	   I = ede*K(DT)  */
	aes_encrypt(cctx, 16, intermediate_I, datetime_DT);

	/* R = ede*K(I XOR V) */
	memxor3(temp_xor, intermediate_I, seed_V, 16);
	aes_encrypt(cctx, 16, result_R, temp_xor);

	/* V = ede*K(R XOR I).  */
	memxor3(temp_xor, result_R, intermediate_I, 16);
	aes_encrypt(cctx, 16, seed_V, temp_xor);

	/* Zero out temporary values.  */
	zeroize_temp_key(intermediate_I, 16);
	zeroize_temp_key(temp_xor, 16);
}


/* The high level driver to x931_aes.  This one does the required
   tests and calls the core function until the entire buffer has been
   filled.  OUTPUT is a caller provided buffer of LENGTH bytes to
   receive the random, RNG_CTX is the context of the RNG.  The context
   must be properly initialized.  Returns 0 on success. */
static int
x931_aes_driver(struct rng_context* rng_ctx, unsigned char *output, size_t length)
{
	unsigned char datetime_DT[16];
	unsigned char result_buffer[16];
	size_t nbytes;
	int ret;

	assert(rng_ctx->is_seeded);

	while (length) {
		/* Unless we are running with a test context, we require a new
		   seed after some time.  */
		if (!rng_ctx->test_dt_ptr
		    && rng_ctx->use_counter > SEED_TTL) {
			
			ret = x931_reseed(rng_ctx);
			if (ret < 0)
				return gnutls_assert_val(ret);

			rng_ctx->use_counter = 0;
		}

		/* Due to the design of the RNG, we always receive 16 bytes (128
		   bit) of random even if we require less.  The extra bytes
		   returned are not used.  In theory we could save them for the
		   next invocation, but that would make the control flow harder
		   to read.  */
		nbytes = length < 16 ? length : 16;

		x931_get_dt(rng_ctx, datetime_DT, 16);
		x931_aes(&rng_ctx->cctx, result_buffer, datetime_DT, rng_ctx->seed_V);
		rng_ctx->use_counter++;

		/* This is the continuous random number generator test */
		if (!rng_ctx->compare_value_valid) {
			/* First time used, only save the result.  */
			memcpy(rng_ctx->compare_value, result_buffer, 16);
			rng_ctx->compare_value_valid = 1;
			continue;
		}
		if (!memcmp(rng_ctx->compare_value, result_buffer, 16)) {
			/* Ooops, we received the same 128 bit block - that should
			   in theory never happen.  The FIPS requirement says that
			   we need to put ourself into the error state in such
			   case.  */
			_gnutls_switch_fips_state(FIPS_STATE_ERROR);
			return GNUTLS_E_LIB_IN_ERROR_STATE;
		}
		memcpy(rng_ctx->compare_value, result_buffer, 16);

		/* Append to outbut.  */
		memcpy(output, result_buffer, nbytes);
		output += nbytes;
		length -= nbytes;
	}
	zeroize_temp_key(result_buffer, 16);

	return 0;
}

/* Generate a key for use with x931_aes.  The function returns a
   handle to the cipher context readily prepared for ECB encryption.
   If FOR_NONCE is true, the key is retrieved by reading random from
   the standard generator.  On error NULL is returned.  */
static int x931_generate_key(struct aes_ctx* ctx)
{
	uint8_t buffer[FIPS140_RND_KEY_SIZE];
	int ret;

	/* Get a key from the standard RNG or from the entropy source.  */
	ret = _rnd_get_system_entropy(buffer, sizeof(buffer));
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* Set the key and delete the buffer because the key is now part of
	   the cipher context.  */
	aes_set_encrypt_key(ctx, sizeof(buffer), buffer);

	zeroize_key(buffer, sizeof(buffer));

	return 0;
}


/* Reseed a generator.  This is also used for the initial seeding. */
static int x931_reseed(struct rng_context* rng_ctx)
{
	int ret;

	/* The other two generators are seeded from /dev/random.  */
	ret = _rnd_get_system_entropy(rng_ctx->seed_V, 16);
	if (ret < 0)
		return gnutls_assert_val(ret);

	rng_ctx->is_seeded = 1;

	return 0;
}


/* Core random function.  This is used for both nonce and random
   generator.  The actual RNG to be used depends on the random context
   RNG_CTX passed.  Note that this function is called with the RNG not
   yet locked.  */
static int get_random(struct rng_context* rng_ctx, void *buffer, size_t length)
{
	int ret;
	
	assert(buffer);
	assert(rng_ctx);

	if (rng_ctx->pid != getpid()) {
		/* We are in a child of us. */
		ret = _rngfips_reinit(rng_ctx);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	if (x931_aes_driver(rng_ctx, buffer, length))
		return gnutls_assert_val(GNUTLS_E_RANDOM_FAILED);

	return 0;
}


/* --- Public Functions --- */

static int _rngfips_reinit(struct rng_context* ctx)
{
int ret;

	ret = x931_generate_key(&ctx->cctx);
	if (ret < 0)
		return gnutls_assert_val(ret);
	
	ret = x931_reseed(ctx);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ctx->pid = getpid();

	return 0;
}

/* Initialize this random subsystem. */
static int _rngfips_init(void** _ctx)
{
/* Basic initialization is required to initialize mutexes and
   do a few checks on the implementation.  */
	struct fips_ctx* ctx;
	int ret;

	ret = gnutls_mutex_init(&rnd_mutex);
	if (ret < 0)
		return gnutls_assert_val(ret);
		
	ret = _rnd_system_entropy_init();
	if (ret < 0)
		return gnutls_assert_val(ret);

	ctx = gnutls_calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	ret = _rngfips_reinit(&ctx->std_context);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _rngfips_reinit(&ctx->strong_context);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _rngfips_reinit(&ctx->nonce_context);
	if (ret < 0)
		return gnutls_assert_val(ret);

	*_ctx = ctx;

	return 0;
}

static int
_rngfips_rnd(void *_ctx, int level, void *buffer, size_t length)
{
struct fips_ctx* ctx = _ctx;
int ret;

	RND_LOCK;
	switch(level) {
		case GNUTLS_RND_RANDOM:
			ret = get_random(&ctx->std_context, buffer, length);
		case GNUTLS_RND_KEY:
			ret = get_random(&ctx->strong_context, buffer, length);
		default:
			ret = get_random(&ctx->nonce_context, buffer, length);
	}
	RND_UNLOCK;
	
	return ret;
}

static void _rngfips_deinit(void * _ctx)
{
struct fips_ctx* ctx = _ctx;
	zeroize_key(ctx, sizeof(*ctx));
	free(ctx);
	gnutls_mutex_deinit(&rnd_mutex);
	rnd_mutex = NULL;
}

static void _rngfips_refresh(void *_ctx)
{
	/* this is predictable RNG. Don't refresh */
	return;
}


/* Run a Know-Answer-Test using a dedicated test context.  Note that
   we can't use the samples from the NISR RNGVS document because they
   don't take the requirement to throw away the first block and use
   that for duplicate check in account.  Thus we made up our own test
   vectors. */
static int selftest_kat(void)
{
	static struct {
		const unsigned char key[16];
		const unsigned char dt[16];
		const unsigned char v[16];
		const unsigned char r[3][16];
	} tv[] = {
		{ 
			{0xb9, 0xca, 0x7f, 0xd6, 0xa0, 0xf5, 0xd3, 0x42, 
			 0x19, 0x6d, 0x84, 0x91, 0x76, 0x1c, 0x3b, 0xbe}, 
			{0x48, 0xb2, 0x82, 0x98, 0x68, 0xc2, 0x80, 0x00,
			 0x00, 0x00, 0x28, 0x18, 0x00, 0x00, 0x25, 0x00}, 
			{0x52, 0x17, 0x8d, 0x29, 0xa2, 0xd5, 0x84, 0x12,
			 0x9d, 0x89, 0x9a, 0x45, 0x82, 0x02, 0xf7, 0x77}, 
			{ 
				{0x42, 0x9c, 0x08, 0x3d, 0x82, 0xf4, 0x8a, 0x40, 
				 0x66, 0xb5, 0x49, 0x27, 0xab, 0x42, 0xc7, 0xc3}, 
				{0x0e, 0xb7, 0x61, 0x3c, 0xfe, 0xb0, 0xbe, 0x73,
				 0xf7, 0x6e, 0x6d, 0x6f, 0x1d, 0xa3, 0x14, 0xfa}, 
				{0xbb, 0x4b, 0xc1, 0x0e, 0xc5, 0xfb, 0xcd, 0x46,
				 0xbe, 0x28, 0x61, 0xe7, 0x03, 0x2b, 0x37, 0x7d}
			}
		}, 
		{ 
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
			{ 
				{0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 
				 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9, 0x8d, 0xbc}, 
				{0xc8, 0xd1, 0xe5, 0x11, 0x59, 0x52, 0xf7, 0xfa,
			     0x37, 0x38, 0xb4, 0xc5, 0xce, 0xb2, 0xb0, 0x9a}, 
			    {0x0d, 0x9c, 0xc5, 0x0d, 0x16, 0xe1, 0xbc, 0xed,
			     0xcf, 0x60, 0x62, 0x09, 0x9d, 0x20, 0x83, 0x7e}
			 }
		}, 
		{ 
			{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 
			{0x80, 0x00, 0x81, 0x01, 0x82, 0x02, 0x83, 0x03,
			 0xa0, 0x20, 0xa1, 0x21, 0xa2, 0x22, 0xa3, 0x23}, 
			{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 
			{ 
				{0x96, 0xed, 0xcc, 0xc3, 0xdd, 0x04, 0x7f, 0x75, 
				 0x63, 0x19, 0x37, 0x6f, 0x15, 0x22, 0x57, 0x56}, 
				{0x7a, 0x14, 0x76, 0x77, 0x95, 0x17, 0x7e, 0xc8,
			     0x92, 0xe8, 0xdd, 0x15, 0xcb, 0x1f, 0xbc, 0xb1}, 
			    {0x25, 0x3e, 0x2e, 0xa2, 0x41, 0x1b, 0xdd, 0xf5,
			     0x21, 0x48, 0x41, 0x71, 0xb3, 0x8d, 0x2f, 0x4c}
			 }
		}
	};
	unsigned tvidx, ridx;
	struct rng_context * test_ctx;
	int ret;
	const char *errtxt = NULL;
	unsigned char result[16];

	test_ctx = gnutls_calloc(1, sizeof *test_ctx);

	RND_LOCK;

	for (tvidx = 0; tvidx < sizeof(tv)/sizeof(tv[0]); tvidx++) {
		/* Setup the key.  */
		aes_set_encrypt_key(&test_ctx->cctx, 16, tv[tvidx].key);
		test_ctx->pid = getpid();

		/* Setup the seed.  */
		memcpy(test_ctx->seed_V, tv[tvidx].v, 16);
		test_ctx->is_seeded = 1;

		/* Setup a DT value.  */
		test_ctx->test_dt_ptr = tv[tvidx].dt;
		test_ctx->test_dt_counter = ((tv[tvidx].dt[12] << 24)
					     | (tv[tvidx].dt[13] << 16)
					     | (tv[tvidx].dt[14] << 8)
					     | (tv[tvidx].dt[15]));

		/* Get and compare the first three results.  */
		for (ridx = 0; ridx < 3; ridx++) {
			/* Compute the next value.  */
			if (x931_aes_driver(test_ctx, result, 16)) {
				errtxt = "X9.31 RNG core function failed";
				ret = GNUTLS_E_SELF_TEST_ERROR;
				goto leave;
			}

			/* Compare it to the known value.  */
			if (memcmp(result, tv[tvidx].r[ridx], 16)) {
				errtxt = "RNG output does not match known value";
				ret = GNUTLS_E_SELF_TEST_ERROR;
				goto leave;
			}
		}

		/* This test is actual pretty pointless because we use a local test
		   context.  */
		if (test_ctx->pid != getpid()) {
			errtxt = "fork detection failed";
			ret = GNUTLS_E_SELF_TEST_ERROR;
			goto leave;
		}

		test_ctx->is_seeded = 0;
	}

	errtxt = "success";
	ret = 0;
leave:
	RND_UNLOCK;

	gnutls_free(test_ctx);
	if (errtxt)
		_gnutls_debug_log("FIPS KAT: %s\n", errtxt);
	return ret;
}


int crypto_rnd_prio = INT_MAX;

gnutls_crypto_rnd_st _gnutls_rnd_ops = {
	.init = _rngfips_init,
	.deinit = _rngfips_deinit,
	.rnd = _rngfips_rnd,
	.rnd_refresh = _rngfips_refresh,
	.self_test = selftest_kat,
};
