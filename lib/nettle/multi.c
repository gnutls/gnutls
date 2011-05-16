/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include <gmp.h>
#include <stdarg.h>
#include <ecc.h>

int mp_init_multi(mpz_t *a, ...)
{
   mpz_t    *cur = a;
   int       np  = 0;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       mpz_init(*cur);
       ++np;
       cur = va_arg(args, mpz_t*);
   }
   va_end(args);
   return 0;
}

void mp_clear_multi(mpz_t *a, ...)
{
   mpz_t    *cur = a;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       mpz_clear(*cur);
       cur = va_arg(args, mpz_t*);
   }
   va_end(args);
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
