#include "testutils.h"
#include "arcfour.h"

int
test_main(void)
{
  test_cipher_stream(&nettle_arcfour128,
		     HL("01234567 89ABCDEF 00000000 00000000"),
		     HL("01234567 89ABCDEF"),
		     H("69723659 1B5242B1"));

  SUCCESS();
}
