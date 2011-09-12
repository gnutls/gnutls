#include <config.h>

#ifdef HAVE_CPUID_H
# include <cpuid.h>
# define cpuid __cpuid

#else

# ifdef ASM_X86_64

#  define cpuid(func,ax,bx,cx,dx)\
  __asm__ __volatile__ ("cpuid":\
  "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

# else
/* some GCC versions complain on the version above */
#  define cpuid(func, a, b, c, d) g_cpuid(func, &a, &b, &c, &d)

inline static void g_cpuid(uint32_t func, unsigned int *ax, unsigned int *bx, unsigned int *cx, unsigned int* dx)
{
    asm volatile ("pushl %%ebx\n"
                  "cpuid\n" 
                  "movl %%ebx, %1\n"
                  "popl %%ebx\n"
                  :"=a" (*ax), "=r"(*bx), "=c"(*cx), "=d"(*dx)
                  :"a"(func)
                  :"cc");
}
# endif

#endif
