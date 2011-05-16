#include "ecc.h"

unsigned long mp_unsigned_bin_size(mpz_t a)
{
  unsigned long t;
  assert(a != NULL);

  t = mpz_sizeinbase(a, 2);
  if (mpz_cmp_ui((a), 0) == 0) return 0;
    return (t>>3) + ((t&7)?1:0);
}

int mp_to_unsigned_bin(mpz_t a, unsigned char *b)
{
   assert(a != NULL);
   assert(b != NULL);
   mpz_export(b, NULL, 1, 1, 1, 0, a);

   return 0;
}

int mp_read_unsigned_bin(mpz_t a, unsigned char *b, unsigned long len)
{
   assert(a != NULL);
   assert(b != NULL);
   mpz_import(a, len, 1, 1, 1, 0, b);
   return 0;
}
