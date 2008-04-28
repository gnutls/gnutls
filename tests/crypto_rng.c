
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>

#include "utils.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "../lib/random.h"

void mylogfn( int level, const char*ptr)
{
       printf ("Got Logs: ");
       if (ptr)
               printf ("%s", ptr);
}

int rng_init( void** ctx)
{
 return 0;
}

int rng_rnd ( void* ctx, int level, void* data, int datasize)
{
  memset(data, 1,datasize);
 return 0;
}

void rng_deinit( void* ctx)
{
}

void
doit (void)
{
 int rc;
 char buf1[32];
 char buf2[32];
 int failed = 0;
 gnutls_crypto_rnd_st rng = { rng_init, rng_rnd, rng_deinit };


 rc = gnutls_crypto_rnd_register (0, &rng);

 gnutls_global_init ();

 memset(buf2, 1, sizeof(buf2));
 
 _gnutls_rnd(GNUTLS_RND_KEY, buf1, sizeof(buf1));

 if (memcmp( buf1, buf2, sizeof(buf1))!=0)
    failed = 1;
 
 gnutls_global_deinit ();

 if (failed == 0) {
   success("rng registered ok\n");
 } else {
    fail ("rng register test failed: %d\n", rc);
 }
}
