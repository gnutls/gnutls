#include <accelerated.h>
#ifdef TRY_X86_OPTIMIZATIONS
# include <aes-x86.h>
#endif

void _gnutls_register_accel_crypto(void)
{

#ifdef TRY_X86_OPTIMIZATIONS
  register_x86_crypto ();
#endif

  return;
}
