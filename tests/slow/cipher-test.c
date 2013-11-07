#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utils.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/* This does check the AES and SHA implementation against test vectors.
 * This should not run under valgrind in order to use the native
 * cpu instructions (AES-NI or padlock).
 */

static void
tls_log_func (int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}


int main(int argc, char **argv)
{
	gnutls_global_set_log_function(tls_log_func);
	if (argc > 1)
		gnutls_global_set_log_level(4711);

	global_init();

    /* ciphers */
    if (gnutls_cipher_self_test(GNUTLS_CIPHER_AES_128_CBC) < 0)
        return 1;

    if (gnutls_cipher_self_test(GNUTLS_CIPHER_AES_192_CBC) < 0)
        return 1;

    if (gnutls_cipher_self_test(GNUTLS_CIPHER_AES_256_CBC) < 0)
        return 1;

    if (gnutls_cipher_self_test(GNUTLS_CIPHER_AES_128_GCM) < 0)
        return 1;

    if (gnutls_cipher_self_test(GNUTLS_CIPHER_AES_256_GCM) < 0)
        return 1;

    if (gnutls_cipher_self_test(GNUTLS_CIPHER_3DES_CBC) < 0)
        return 1;

    /* message digests */        
    if (gnutls_digest_self_test(GNUTLS_DIG_MD5) < 0)
        return 1;

    if (gnutls_digest_self_test(GNUTLS_DIG_SHA1) < 0)
        return 1;

    if (gnutls_digest_self_test(GNUTLS_DIG_SHA224) < 0)
        return 1;

    if (gnutls_digest_self_test(GNUTLS_DIG_SHA256) < 0)
        return 1;

    if (gnutls_digest_self_test(GNUTLS_DIG_SHA384) < 0)
        return 1;

    if (gnutls_digest_self_test(GNUTLS_DIG_SHA512) < 0)
        return 1;

    /* MAC */
    if (gnutls_mac_self_test(GNUTLS_MAC_MD5) < 0)
        return 1;

    if (gnutls_mac_self_test(GNUTLS_MAC_SHA1) < 0)
        return 1;

    if (gnutls_mac_self_test(GNUTLS_MAC_SHA224) < 0)
        return 1;

    if (gnutls_mac_self_test(GNUTLS_MAC_SHA256) < 0)
        return 1;

    if (gnutls_mac_self_test(GNUTLS_MAC_SHA384) < 0)
        return 1;

    if (gnutls_mac_self_test(GNUTLS_MAC_SHA512) < 0)
        return 1;

	gnutls_global_deinit();
	return 0;
}
