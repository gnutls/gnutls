#include "testutils.h"
#include "hmac.h"

int
test_main(void)
{
  struct hmac_md5_ctx md5;
  struct hmac_sha1_ctx sha1;

  /* sha256's digests are longest */
  uint8_t digest[SHA256_DIGEST_SIZE];

  memset(digest, 0, sizeof(digest));
  
  /* Test vectors for md5, from RFC-2202 */

  /* md5 - 1 */
  hmac_md5_set_key(&md5, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b"));
  hmac_md5_update(&md5, LDATA("Hi There"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("9294727a3638bb1c 13f48ef8158bfc9d")))
    FAIL();

  /* md5 - 2 */
  hmac_md5_set_key(&md5, LDATA("Jefe"));
  hmac_md5_update(&md5, LDATA("what do ya want for nothing?"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("750c783e6ab0b503 eaa86e310a5db738")))
    FAIL();

  /* md5 - 3 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5, HL("dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56be34521d144c88 dbb8c733f0e8b3f6")))
    FAIL();
  
  /* md5 - 4 */
  hmac_md5_set_key(&md5, HL("0102030405060708 090a0b0c0d0e0f10" 
			    "1112131415161718 19"));
  hmac_md5_update(&md5, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("697eaf0aca3a3aea 3a75164746ffaa79")))
    FAIL();

  /* md5 - 5 */
  memset(digest, 0, MD5_DIGEST_SIZE);
  hmac_md5_set_key(&md5, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c" ));
  hmac_md5_update(&md5, LDATA("Test With Truncation"));
  hmac_md5_digest(&md5, 12, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56461ef2342edc00 f9bab99500000000")))
    FAIL();

  /* md5 - 6 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5,
		  LDATA("Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("6b1ab7fe4bd7bf8f 0b62e6ce61b9d0cd")))
    FAIL();

  /* md5 - 7 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5,
		  LDATA("Test Using Larger Than Block-Size Key and Larger "
			"Than One Block-Size Data"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("6f630fad67cda0ee 1fb1f562db3aa53e")))
    FAIL();

 
  /* Test vectors for sha1, from RFC-2202 */

  /* sha1 - 1 */
  hmac_sha1_set_key(&sha1, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b"));
  hmac_sha1_update(&sha1, LDATA("Hi There"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("b617318655057264 e28bc0b6fb378c8e f146be00")))
    FAIL();

  /* sha1 - 2 */
  hmac_sha1_set_key(&sha1, LDATA("Jefe"));
  hmac_sha1_update(&sha1, LDATA("what do ya want for nothing?"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("effcdf6ae5eb2fa2 d27416d5f184df9c 259a7c79")))
    FAIL();

  /* sha1 - 3 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaa"));
  hmac_sha1_update(&sha1, HL("dddddddddddddddd dddddddddddddddd"
			     "dddddddddddddddd dddddddddddddddd"
			     "dddddddddddddddd dddddddddddddddd"
			     "dddd"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("125d7342b9ac11cd 91a39af48aa17b4f 63f175d3")))
    FAIL();
  
  /* sha1 - 4 */
  hmac_sha1_set_key(&sha1, HL("0102030405060708 090a0b0c0d0e0f10" 
			      "1112131415161718 19"));
  hmac_sha1_update(&sha1, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcd"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("4c9007f4026250c6 bc8414f9bf50c86c 2d7235da")))
    FAIL();

  /* sha1 - 5 */
  memset(digest, 0, SHA1_DIGEST_SIZE);
  hmac_sha1_set_key(&sha1, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c"));
  hmac_sha1_update(&sha1, LDATA("Test With Truncation"));
  hmac_sha1_digest(&sha1, 12, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("4c1a03424b55e07f e7f27be100000000 00000000")))
    FAIL();

  /* sha1 - 6 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha1_update(&sha1,
		   LDATA("Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("aa4ae5e15272d00e 95705637ce8a3b55 ed402112")))
    FAIL();

  /* sha1 - 7 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha1_update(&sha1,
		  LDATA("Test Using Larger Than Block-Size Key and Larger "
			"Than One Block-Size Data"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("e8e99d0f45237d78 6d6bbaa7965c7808 bbff1a91")))
    FAIL();


  SUCCESS();
}
