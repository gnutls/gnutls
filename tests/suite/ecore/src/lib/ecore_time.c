#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "Ecore.h"
#include "ecore_private.h"

#include <time.h>

#ifdef HAVE_CLOCK_GETTIME
static clockid_t _ecore_time_clock_id = -1;
#endif
double _ecore_time_loop_time = -1.0;

/**
 * Retrieves the current system time as a floating point value in seconds.
 *
 * This uses a monotonic clock and thus never goes back in time while
 * machine is live (even if user changes time or timezone changes,
 * however it may be reset whenever the machine is restarted).
 *
 * @see ecore_loop_time_get().
 * @see ecore_time_unix_get().
 *
 * @return The number of seconds. Start time is not defined (it may be
 *         when the machine was booted, unix time, etc), all it is
 *         defined is that it never goes backwards (unless you got big critical
 *         messages when the application started).
 * @ingroup Ecore_Time_Group
 */
EAPI double ecore_time_get(void)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec t;

	if (EINA_UNLIKELY(_ecore_time_clock_id < 0))
		return ecore_time_unix_get();

	if (EINA_UNLIKELY(clock_gettime(_ecore_time_clock_id, &t))) {
		CRIT("Cannot get current time.");
		/* Try to at least return the latest value retrieved */
		return _ecore_time_loop_time;
	}

	return (double) t.tv_sec + (((double) t.tv_nsec) / 1000000000.0);
#else
	return ecore_time_unix_get();
#endif
}

/**
 * Retrieves the current UNIX time as a floating point value in seconds.
 *
 * @see ecore_time_get().
 * @see ecore_loop_time_get().
 *
 * @return  The number of seconds since 12.00AM 1st January 1970.
 * @ingroup Ecore_Time_Group
 */
EAPI double ecore_time_unix_get(void)
{
#ifdef HAVE_EVIL
	return evil_time_get();
#else
#ifdef HAVE_GETTIMEOFDAY
	struct timeval timev;

	gettimeofday(&timev, NULL);
	return (double) timev.tv_sec +
	    (((double) timev.tv_usec) / 1000000);
#else
#error "Your platform isn't supported yet"
#endif
#endif
}

/**
 * Retrieves the time at which the last loop stopped waiting for timeouts or
 * events.
 *
 * This gets the time that the main loop ceased waiting for timouts and/or
 * events to come in or for signals or any other interrupt source. This should
 * be considered a reference point for all time based activity that should
 * calculate its timepoint from the return of ecore_loop_time_get(). Use this
 * UNLESS you absolutely must get the current actual timepoint - then use
 * ecore_time_get(). Note that this time is meant to be used as relative to
 * other times obtained on this run. If you need absolute time references, use
 * ecore_time_unix_get() instead.
 *
 * This function can be called before any loop has ever been run, but either
 * ecore_init() or ecore_time_get() must have been called once.
 *
 * @return The number of seconds. Start time is not defined (it may be
 *         when the machine was booted, unix time, etc), all it is
 *         defined is that it never goes backwards (unless you got big critical
 *         messages when the application started).
 * @ingroup Ecore_Time_Group
 */
EAPI double ecore_loop_time_get(void)
{
	return _ecore_time_loop_time;
}


/**********************   Internal methods   ********************************/

/* TODO: Documentation says "All  implementations  support  the  system-wide
 * real-time clock, which is identified by CLOCK_REALTIME. Check if the fallback
 * to unix time (without specifying the resolution) might be removed
 */
void _ecore_time_init(void)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec t;

	if (_ecore_time_clock_id != -1)
		return;

	if (!clock_gettime(CLOCK_MONOTONIC, &t)) {
		_ecore_time_clock_id = CLOCK_MONOTONIC;
		DBG("using CLOCK_MONOTONIC.");
	} else if (!clock_gettime(CLOCK_REALTIME, &t)) {
		/* may go backwards */
		_ecore_time_clock_id = CLOCK_REALTIME;
		WRN("CLOCK_MONOTONIC not available. Fallback to CLOCK_REALTIME.");
	} else {
		_ecore_time_clock_id = -2;
		CRIT("Cannot get a valid clock_gettime() clock id! "
		     "Fallback to unix time.");
	}
#else
#warning "Your platform isn't supported yet"
	CRIT("Platform does not support clock_gettime. "
	     "Fallback to unix time.");
#endif

	_ecore_time_loop_time = ecore_time_get();
}
