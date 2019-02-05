/* EINA - EFL data type library
 * Copyright (C) 2010 ProFUSION embedded systems
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
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef EFL_HAVE_POSIX_THREADS
#include <pthread.h>
#ifdef __linux__
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#endif
#endif

#include "eina_sched.h"
#include "eina_log.h"

#define RTNICENESS 5
#define NICENESS 5

/**
 * @brief Lower priority of current thread.
 *
 * It's used by worker threads so they use up background cpu and do not stall
 * the main thread If current thread is running with real-time priority, we
 * decrease our priority by @c RTNICENESS. This is done in a portable way.
 *
 * Otherwise (we are running with SCHED_OTHER policy) there's no portable way to
 * set the nice level on current thread. In Linux, it does work and it's the
 * only one that is implemented as of now. In this case the nice level is
 * incremented on this thread by @c NICENESS.
 */
EAPI void eina_sched_prio_drop(void)
{
#ifdef EFL_HAVE_POSIX_THREADS
	struct sched_param param;
	int pol, prio, ret;
	pthread_t pthread_id;

	pthread_id = pthread_self();
	ret = pthread_getschedparam(pthread_id, &pol, &param);
	if (ret) {
		EINA_LOG_ERR("Unable to query sched parameters");
		return;
	}

	if (EINA_UNLIKELY(pol == SCHED_RR || pol == SCHED_FIFO)) {
		prio = sched_get_priority_max(pol);
		param.sched_priority += RTNICENESS;
		if (prio > 0 && param.sched_priority > prio)
			param.sched_priority = prio;

		pthread_setschedparam(pthread_id, pol, &param);
	}
#ifdef __linux__
	else {
		errno = 0;
		prio = getpriority(PRIO_PROCESS, 0);
		if (errno == 0) {
			prio += NICENESS;
			if (prio > 19)
				prio = 19;

			setpriority(PRIO_PROCESS, 0, prio);
		}
	}
#endif
#else
	EINA_LOG_ERR("Eina does not have support for threads enabled"
		     "or it doesn't support setting scheduler priorities");
#endif
}
