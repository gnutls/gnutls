#define cpuid(func,ax,bx,cx,dx)\
  __asm__ __volatile__ ("cpuid":\
  "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));
