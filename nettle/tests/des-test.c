#include "testutils.h"
#include "nettle-internal.h"
#include "des.h"

int
test_main(void)
{
  struct des_ctx ctx;
  
  /* From Applied Cryptography */
  test_cipher(&nettle_des,
	      HL("01234567 89ABCDEF"),
	      HL("01234567 89ABCDE7"),
	      H("C9574425 6A5ED31D"));

  test_cipher(&nettle_des,
	      HL("01 01 01 01 01 01 01 80"),
	      HL("00 00 00 00 00 00 00 00"),
	      H("9C C6 2D F4 3B 6E ED 74"));
  
  test_cipher(&nettle_des,
	      HL("80 01 01 01 01 01 01 01"),
	      HL("00 00 00 00 00 00 00 40"),
	      H("A3 80 E0 2A 6B E5 46 96"));

  test_cipher(&nettle_des,
	      HL("08 19 2A 3B 4C 5D 6E 7F"),
	      HL("00 00 00 00 00 00 00 00"),
	      H("25 DD AC 3E 96 17 64 67"));

  
  test_cipher(&nettle_des,
	      HL("01 23 45 67 89 AB CD EF"),
	      DES_BLOCK_SIZE, "Now is t",
	      H("3F A4 0E 8A 98 4D 48 15"));

  /* Parity check */
  if (des_set_key(&ctx, H("01 01 01 01 01 01 01 00"))
      || (ctx.status != DES_BAD_PARITY))
    FAIL();

  /* Weak key check */
  if (des_set_key(&ctx, H("01 01 01 01 01 01 01 01"))
      || (ctx.status != DES_WEAK_KEY))
    FAIL();

  if (des_set_key(&ctx, H("01 FE 01 FE 01 FE 01 FE"))
      || (ctx.status != DES_WEAK_KEY))
    FAIL();

  if (des_set_key(&ctx, H("FE E0 FE E0 FE F1 FE F1"))
      || (ctx.status != DES_WEAK_KEY))
    FAIL();

  SUCCESS();
}
