#include <config.h>

#ifdef STDC_HEADERS
# include <string.h>
# include <stdlib.h>
# include <stdio.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include <time.h>
#include <ctype.h>

/* for open */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif


#if SIZEOF_UNSIGNED_LONG_INT == 8
 typedef unsigned long int uint64;
 typedef signed long int sint64;
#elif SIZEOF_UNSIGNED_LONG_LONG == 8
 typedef unsigned long long uint64;
 typedef signed long long sint64;
#else
# error "Cannot find a 64 bit integer in your system, sorry."
#endif


#if SIZEOF_UNSIGNED_LONG_INT == 4
 typedef unsigned long int uint32;
 typedef signed long int sint32;
#elif SIZEOF_UNSIGNED_INT == 4
 typedef unsigned int uint32;
 typedef signed int sint32;
#else
# error "Cannot find a 32 bit integer in your system, sorry."
#endif

#if SIZEOF_UNSIGNED_INT == 2
 typedef unsigned int uint16;
 typedef signed int sint16;
#elif SIZEOF_UNSIGNED_SHORT_INT == 2
 typedef unsigned short int uint16;
 typedef signed short int sint16;
#else 
# error "Cannot find a 16 bit integer in your system, sorry."
#endif

#if SIZEOF_UNSIGNED_CHAR == 1
 typedef unsigned char uint8; 
 typedef signed char int8; 
#else
# error "Cannot find an 8 bit char in your system, sorry."
#endif

#ifndef HAVE_MEMMOVE
# ifdef HAVE_BCOPY
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# else
#  error "Neither memmove nor bcopy exists on your system."
# endif
#endif
