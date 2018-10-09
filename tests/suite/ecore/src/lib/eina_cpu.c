/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef EFL_HAVE_THREADS
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined (__SUNPRO_C) || defined(__GNUC__)
#include <unistd.h>
#elif defined (__FreeBSD__) || defined (__OpenBSD__) || \
   defined (__NetBSD__) || defined (__DragonFly__) || defined (__MacOSX__) || \
   (defined (__MACH__) && defined (__APPLE__))
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#elif defined (__linux__) || defined(__GLIBC__)
#define _GNU_SOURCE
#include <sched.h>
#endif
#ifdef EFL_HAVE_POSIX_THREADS
#include <pthread.h>
#endif

#define TH_MAX 8
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "eina_cpu.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/* FIXME this ifdefs should be replaced */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/* FIXME the features checks should be called when this function is called?
 * or make it static by doing eina_cpu_init() and return a local var
 */
/**
 *
 * @return
 */
EAPI Eina_Cpu_Features eina_cpu_features_get(void)
{
	Eina_Cpu_Features ecf = 0;
	return ecf;
}

EAPI int eina_cpu_count(void)
{
#ifdef EFL_HAVE_THREADS

#if   defined (_WIN32)
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;

#elif defined (__SUNPRO_C) || defined(__GNUC__)
	/*
	 * _SC_NPROCESSORS_ONLN: number of processors that are online, that
	 is available when sysconf is called. The number
	 of cpu can change by admins.
	 * _SC_NPROCESSORS_CONF: maximum number of processors that are available
	 to the current OS instance. That number can be
	 change after a reboot.
	 * _SC_NPROCESSORS_MAX : maximum number of processors that are on the
	 motherboard.
	 */
	return sysconf(_SC_NPROCESSORS_ONLN);

#elif defined (__FreeBSD__) || defined (__OpenBSD__) || \
   defined (__NetBSD__) || defined (__DragonFly__) || defined (__MacOSX__) || \
   (defined (__MACH__) && defined (__APPLE__))

	int mib[4];
	int cpus;
	size_t len = sizeof(cpus);

	mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
	mib[1] = HW_AVAILCPU;
#else
	mib[1] = HW_NCPU;
#endif
	sysctl(mib, 2, &cpus, &len, NULL, 0);
	if (cpus < 1)
		cpus = 1;

	return cpus;

#elif defined (__linux__) || defined(__GLIBC__)
	cpu_set_t cpu;
	int i;
	static int cpus = 0;

	if (cpus != 0)
		return cpus;

	CPU_ZERO(&cpu);
	if (sched_getaffinity(0, sizeof(cpu), &cpu) != 0) {
		fprintf(stderr, "[Eina] could not get cpu affinity: %s\n",
			strerror(errno));
		return 1;
	}

	for (i = 0; i < TH_MAX; i++) {
		if (CPU_ISSET(i, &cpu))
			cpus = i + 1;
		else
			break;
	}
	return cpus;

#else
#error "eina_cpu_count() error: Platform not supported"
#endif
#else
	return 1;
#endif
}
