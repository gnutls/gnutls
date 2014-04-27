/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
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

/*
 * The following code is an implementation of the AES-128-CBC cipher
 * using intel's AES instruction set. 
 */

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <gnutls_errors.h>
#include <aes-x86.h>
#include <sha-x86.h>
#include <x86-common.h>
#ifdef HAVE_LIBNETTLE
# include <nettle/aes.h>		/* for key generation in 192 and 256 bits */
# include <sha-padlock.h>
#endif
#include <aes-padlock.h>

unsigned int _gnutls_x86_cpuid_s[4];

static unsigned check_optimized_aes(void)
{
	return (_gnutls_x86_cpuid_s[2] & 0x2000000);
}

static unsigned check_ssse3(void)
{
	return (_gnutls_x86_cpuid_s[2] & 0x0000200);
}

#ifdef ASM_X86_64
static unsigned check_pclmul(void)
{
	return (_gnutls_x86_cpuid_s[2] & 0x2);
}
#endif

static int check_padlock(void)
{
	unsigned int edx = padlock_capability();

	return ((edx & (0x3 << 6)) == (0x3 << 6));
}

static int check_phe(void)
{
	unsigned int edx = padlock_capability();

	return ((edx & (0x3 << 10)) == (0x3 << 10));
}

/* We are actually checking for SHA512 */
static int check_phe_sha512(void)
{
	unsigned int edx = padlock_capability();

	return ((edx & (0x3 << 25)) == (0x3 << 25));
}

static int check_phe_partial(void)
{
	const char *text = "test and test";
	uint32_t iv[5] = { 0x67452301UL, 0xEFCDAB89UL,
		0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
	};

	padlock_sha1_blocks(iv, text, sizeof(text) - 1);
	padlock_sha1_blocks(iv, text, sizeof(text) - 1);

	if (iv[0] == 0x9096E2D8UL && iv[1] == 0xA33074EEUL &&
	    iv[2] == 0xCDBEE447UL && iv[3] == 0xEC7979D2UL &&
	    iv[4] == 0x9D3FF5CFUL)
		return 1;
	else
		return 0;
}

static unsigned check_via(void)
{
	unsigned int a, b, c, d;
	gnutls_cpuid(0, &a, &b, &c, &d);

	if ((memcmp(&b, "Cent", 4) == 0 &&
	     memcmp(&d, "aurH", 4) == 0 && memcmp(&c, "auls", 4) == 0)) {
		return 1;
	}

	return 0;
}

static unsigned check_intel_or_amd(void)
{
	unsigned int a, b, c, d;
	gnutls_cpuid(0, &a, &b, &c, &d);

	if ((memcmp(&b, "Genu", 4) == 0 &&
	     memcmp(&d, "ineI", 4) == 0 &&
	     memcmp(&c, "ntel", 4) == 0) ||
	    (memcmp(&b, "Auth", 4) == 0 &&
	     memcmp(&d, "enti", 4) == 0 && memcmp(&c, "cAMD", 4) == 0)) {
		return 1;
	}

	return 0;
}

static
void register_x86_intel_crypto(void)
{
	int ret;

	if (check_intel_or_amd() == 0)
		return;

	gnutls_cpuid(1, &_gnutls_x86_cpuid_s[0], &_gnutls_x86_cpuid_s[1], 
		&_gnutls_x86_cpuid_s[2], &_gnutls_x86_cpuid_s[3]);
	
	if (check_ssse3()) {
		_gnutls_debug_log("Intel SSSE3 was detected\n");

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_128_GCM, 90,
		     &_gnutls_aes_gcm_x86_ssse3);
			if (ret < 0) {
				gnutls_assert();
			}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_256_GCM, 90,
		     &_gnutls_aes_gcm_x86_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_128_CBC, 90, &_gnutls_aes_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_192_CBC, 90, &_gnutls_aes_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_256_CBC, 90, &_gnutls_aes_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA1,
							 80,
							 &_gnutls_sha_x86_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA224,
							 80,
							 &_gnutls_sha_x86_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA256,
							 80,
							 &_gnutls_sha_x86_ssse3);
		if (ret < 0) {
			gnutls_assert();
		}


		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA1,
							 80,
							 &_gnutls_hmac_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA224,
							 80,
							 &_gnutls_hmac_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA256,
							 80,
							 &_gnutls_hmac_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();

#ifdef ENABLE_SHA512
		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA384,
							 80,
							 &_gnutls_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA512,
							 80,
							 &_gnutls_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();
		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA384,
							 80,
							 &_gnutls_hmac_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA512,
							 80,
							 &_gnutls_hmac_sha_x86_ssse3);
		if (ret < 0)
			gnutls_assert();
#endif
	}

	if (check_optimized_aes()) {
		_gnutls_debug_log("Intel AES accelerator was detected\n");
		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_128_CBC, 80, &_gnutls_aesni_x86);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_192_CBC, 80, &_gnutls_aesni_x86);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_256_CBC, 80, &_gnutls_aesni_x86);
		if (ret < 0) {
			gnutls_assert();
		}
#ifdef ASM_X86_64
		if (check_pclmul()) {
			/* register GCM ciphers */
			_gnutls_debug_log
			    ("Intel GCM accelerator was detected\n");
			ret =
			    gnutls_crypto_single_cipher_register
			    (GNUTLS_CIPHER_AES_128_GCM, 80,
			     &_gnutls_aes_gcm_pclmul);
			if (ret < 0) {
				gnutls_assert();
			}

			ret =
			    gnutls_crypto_single_cipher_register
			    (GNUTLS_CIPHER_AES_256_GCM, 80,
			     &_gnutls_aes_gcm_pclmul);
			if (ret < 0) {
				gnutls_assert();
			}
		} else {
			ret =
			    gnutls_crypto_single_cipher_register
			    (GNUTLS_CIPHER_AES_128_GCM, 80,
			     &_gnutls_aes_gcm_x86_aesni);
			if (ret < 0) {
				gnutls_assert();
			}

			ret =
			    gnutls_crypto_single_cipher_register
			    (GNUTLS_CIPHER_AES_256_GCM, 80,
			     &_gnutls_aes_gcm_x86_aesni);
			if (ret < 0) {
				gnutls_assert();
			}


		}
#endif
	}

	/* convert _gnutls_x86_cpuid_s the way openssl asm expects it */
	_gnutls_x86_cpuid_s[1] = _gnutls_x86_cpuid_s[2];

	return;
}

static
void register_x86_padlock_crypto(void)
{
	int ret, phe;

	if (check_via() == 0)
		return;
	if (check_padlock()) {
		_gnutls_debug_log
		    ("Padlock AES accelerator was detected\n");
		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_128_CBC, 80, &_gnutls_aes_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		/* register GCM ciphers */
		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_128_GCM, 80,
		     &_gnutls_aes_gcm_padlock);
		if (ret < 0) {
			gnutls_assert();
		}
#ifdef HAVE_LIBNETTLE
		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_192_CBC, 80, &_gnutls_aes_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_256_CBC, 80, &_gnutls_aes_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_cipher_register
		    (GNUTLS_CIPHER_AES_256_GCM, 80,
		     &_gnutls_aes_gcm_padlock);
		if (ret < 0) {
			gnutls_assert();
		}
#endif
	}
#ifdef HAVE_LIBNETTLE
	phe = check_phe();

	if (phe && check_phe_partial()) {
		_gnutls_debug_log
		    ("Padlock SHA1 and SHA256 (partial) accelerator was detected\n");
		if (check_phe_sha512()) {
			_gnutls_debug_log
			    ("Padlock SHA512 (partial) accelerator was detected\n");
			ret =
			    gnutls_crypto_single_digest_register
			    (GNUTLS_DIG_SHA384, 80,
			     &_gnutls_sha_padlock_nano);
			if (ret < 0) {
				gnutls_assert();
			}

			ret =
			    gnutls_crypto_single_digest_register
			    (GNUTLS_DIG_SHA512, 80,
			     &_gnutls_sha_padlock_nano);
			if (ret < 0) {
				gnutls_assert();
			}

			ret =
			    gnutls_crypto_single_mac_register
			    (GNUTLS_MAC_SHA384, 80,
			     &_gnutls_hmac_sha_padlock_nano);
			if (ret < 0) {
				gnutls_assert();
			}

			ret =
			    gnutls_crypto_single_mac_register
			    (GNUTLS_MAC_SHA512, 80,
			     &_gnutls_hmac_sha_padlock_nano);
			if (ret < 0) {
				gnutls_assert();
			}
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA1,
							 80,
							 &_gnutls_sha_padlock_nano);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA224,
							 80,
							 &_gnutls_sha_padlock_nano);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA256,
							 80,
							 &_gnutls_sha_padlock_nano);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA1,
						      80,
						      &_gnutls_hmac_sha_padlock_nano);
		if (ret < 0) {
			gnutls_assert();
		}

		/* we don't register MAC_SHA224 because it is not used by TLS */

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA256,
						      80,
						      &_gnutls_hmac_sha_padlock_nano);
		if (ret < 0) {
			gnutls_assert();
		}
	} else if (phe) {
		/* Original padlock PHE. Does not support incremental operations.
		 */
		_gnutls_debug_log
		    ("Padlock SHA1 and SHA256 accelerator was detected\n");
		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA1,
							 80,
							 &_gnutls_sha_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_digest_register(GNUTLS_DIG_SHA256,
							 80,
							 &_gnutls_sha_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA1,
						      80,
						      &_gnutls_hmac_sha_padlock);
		if (ret < 0) {
			gnutls_assert();
		}

		ret =
		    gnutls_crypto_single_mac_register(GNUTLS_MAC_SHA256,
						      80,
						      &_gnutls_hmac_sha_padlock);
		if (ret < 0) {
			gnutls_assert();
		}
	}
#endif

	return;
}

void register_x86_crypto(void)
{
	register_x86_intel_crypto();
	register_x86_padlock_crypto();
}

