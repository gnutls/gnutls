/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#ifdef ASM_X86_64

# ifdef HAVE_CPUID_H
#  include <cpuid.h>
#  define cpuid __cpuid
# else

#define cpuid(func,ax,bx,cx,dx)\
  __asm__ __volatile__ ("cpuid":\
  "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

# endif

# define have_cpuid() 1

#endif /* ASM_X86_64 */


#ifdef ASM_X86_32
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

inline static unsigned int have_cpuid(void)
{
  unsigned int have_id;
  asm volatile(
    "pushfl\t\n"
    "pop %0\t\n"
    "orl $0x200000, %0\t\n"
    "push %0\t\n"
    "popfl\t\n"
    "pushfl\t\n"
    "pop %0\t\n"
    "andl $0x200000, %0\t\n"
    :"=r" (have_id)
    ::
  );
  
  return have_id;
}
#endif /* ASM_X86_32 */
