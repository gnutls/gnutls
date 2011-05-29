#include <config.h>

#ifdef HAVE_CPUID_H
# include <cpuid.h>
# define cpuid __cpuid

#else
#define cpuid(func,ax,bx,cx,dx)\
  __asm__ __volatile__ ("cpuid":\
  "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#endif
