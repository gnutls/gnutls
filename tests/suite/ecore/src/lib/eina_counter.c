/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric Bail, Vincent Torri
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
#include <time.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif				/* _WIN2 */

#include "eina_config.h"
#include "eina_private.h"
#include "eina_inlist.h"
#include "eina_error.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_counter.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#ifndef _WIN32
typedef struct timespec Eina_Nano_Time;
#else
typedef LARGE_INTEGER Eina_Nano_Time;
#endif

typedef struct _Eina_Clock Eina_Clock;

struct _Eina_Counter {
	EINA_INLIST;

	Eina_Inlist *clocks;
	const char *name;
};

struct _Eina_Clock {
	EINA_INLIST;

	Eina_Nano_Time start;
	Eina_Nano_Time end;
	int specimen;

	Eina_Bool valid;
};

#ifndef _WIN32
static inline int _eina_counter_time_get(Eina_Nano_Time * tp)
{
#if defined(CLOCK_PROCESS_CPUTIME_ID)
	return clock_gettime(CLOCK_PROCESS_CPUTIME_ID, tp);
#elif defined(CLOCK_PROF)
	return clock_gettime(CLOCK_PROF, tp);
#elif defined(CLOCK_REALTIME)
	return clock_gettime(CLOCK_REALTIME, tp);
#else
	return gettimeofday(tp, NULL);
#endif
}
#else
static const char EINA_ERROR_COUNTER_WINDOWS_STR[] =
    "Change your OS, you moron !";
static int EINA_ERROR_COUNTER_WINDOWS = 0;
static LARGE_INTEGER _eina_counter_frequency;

static inline int _eina_counter_time_get(Eina_Nano_Time * tp)
{
	return QueryPerformanceCounter(tp);
}
#endif				/* _WIN2 */

static char *_eina_counter_asiprintf(char *base, int *position,
				     const char *format, ...)
{
	char *tmp, *result;
	int size = 32;
	int n;
	va_list ap;

	tmp = realloc(base, sizeof(char) * (*position + size));
	if (!tmp)
		return base;

	result = tmp;

	while (1) {
		va_start(ap, format);
		n = vsnprintf(result + *position, size, format, ap);
		va_end(ap);

		if (n > -1 && n < size) {
			/* If we always have glibc > 2.2, we could just return *position += n. */
			*position += strlen(result + *position);
			return result;
		}

		if (n > -1)
			size = n + 1;
		else
			size <<= 1;

		tmp = realloc(result, sizeof(char) * (*position + size));
		if (!tmp)
			return result;

		result = tmp;
	}
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the eina counter internal structure.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the counter module set up by
 * eina_counter_init(). It is called by eina_init().
 *
 * This function sets up the error module of Eina and only on Windows,
 * it initializes the high precision timer. It also registers, only on
 * Windows, the error #EINA_ERROR_COUNTER_WINDOWS. It is also called
 * by eina_init(). It returns 0 on failure, otherwise it returns the
 * number of times it has already been called.
 *
 * @see eina_init()
 */
Eina_Bool eina_counter_init(void)
{
#ifdef _WIN32
	EINA_ERROR_COUNTER_WINDOWS =
	    eina_error_msg_static_register(EINA_ERROR_COUNTER_WINDOWS_STR);
	if (!QueryPerformanceFrequency(&_eina_counter_frequency)) {
		eina_error_set(EINA_ERROR_COUNTER_WINDOWS);
		return EINA_FALSE;
	}
#endif				/* _WIN2 */
	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the counter module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the counter module set up by
 * eina_counter_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_counter_shutdown(void)
{
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Counter_Group Counter
 *
 * @brief These functions allow you to get the time spent in a part of a code.
 *
 * Before using the counter system, Eina must be initialized with
 * eina_init() and later shut down with eina_shutdown(). The create a
 * counter, use eina_counter_new(). To free it, use
 * eina_counter_free().
 *
 * To time a part of a code, call eina_counter_start() just before it,
 * and eina_counter_stop() just after it. Each time you start to time
 * a code, a clock is added to a list. You can give a number of that
 * clock with the second argument of eina_counter_stop(). To send all
 * the registered clocks to a stream (like stdout, ofr a file), use
 * eina_counter_dump().
 *
 * Here is a straightforward example:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <eina_counter.h>
 *
 * void test_malloc(void)
 * {
 *    int i;
 *
 *    for (i = 0; i < 100000; ++i)
 *    {
 *       void *buf;
 *
 *       buf = malloc(100);
 *       free(buf);
 *    }
 * }
 *
 * int main(void)
 * {
 *    Eina_Counter *counter;
 *
 *    if (!eina_init())
 *    {
 *        printf("Error during the initialization of eina\n");
 *        return EXIT_FAILURE;
 *    }
 *
 *    counter = eina_counter_new("malloc");
 *
 *    eina_counter_start(counter);
 *    test_malloc();
 *    eina_counter_stop(counter, 1);
 *
 *    char* result = eina_counter_dump(counter);
 *    printf("%s", result);
 *    free(result);
 *
 *    eina_counter_free(counter);
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * Compile this code with the following commant:
 *
 * @verbatim
 * gcc -Wall -o test_eina_counter test_eina.c `pkg-config --cflags --libs eina`
 * @endverbatim
 *
 * The result should be something like that:
 *
 * @verbatim
 * \# specimen    experiment time    starting time    ending time
 * 1              9794125            783816           10577941
 * @endverbatim
 *
 * Note that the displayed time is in nanosecond.
 *
 * @{
 */

/**
 * @brief Return a counter.
 *
 * @param name The name of the counter.
 *
 * This function returns a new counter. It is characterized by @p
 * name. If @p name is @c NULL, the function returns @c NULL
 * immediately. If memory allocation fails, @c NULL is returned and the
 * error is set to #EINA_ERROR_OUT_OF_MEMORY.
 *
 * Whe the new counter is not needed anymore, use eina_counter_free() to
 * free the allocated memory.
 */
EAPI Eina_Counter *eina_counter_new(const char *name)
{
	Eina_Counter *counter;
	size_t length;

	EINA_SAFETY_ON_NULL_RETURN_VAL(name, NULL);

	length = strlen(name) + 1;

	eina_error_set(0);
	counter = calloc(1, sizeof(Eina_Counter) + length);
	if (!counter) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	counter->name = (char *) (counter + 1);
	memcpy((char *) counter->name, name, length);

	return counter;
}

/**
 * @brief Delete a counter.
 *
 * @param counter The counter to delete.
 *
 * This function remove the clock of @p counter from the used clocks
 * (see eina_counter_start()) and frees the memory allocated for
 * @p counter. If @p counter is @c NULL, the function returns
 * immediately.
 */
EAPI void eina_counter_free(Eina_Counter * counter)
{
	EINA_SAFETY_ON_NULL_RETURN(counter);

	while (counter->clocks) {
		Eina_Clock *clk = (Eina_Clock *) counter->clocks;

		counter->clocks =
		    eina_inlist_remove(counter->clocks, counter->clocks);
		free(clk);
	}

	free(counter);
}

/**
 * @brief Start the time count.
 *
 * @param counter The counter.
 *
 * This function specifies that the part of the code beginning just
 * after its call is being to be timed, using @p counter. If
 * @p counter is @c NULL, this function returns immediately.
 *
 * This function adds the clock associated to @p counter in a list. If
 * the memory needed by that clock can not be allocated, the function
 * returns and the error is set to #EINA_ERROR_OUT_OF_MEMORY.
 *
 * To stop the timing, eina_counter_stop() must be called with the
 * same counter.
 */
EAPI void eina_counter_start(Eina_Counter * counter)
{
	Eina_Clock *clk;
	Eina_Nano_Time tp;

	EINA_SAFETY_ON_NULL_RETURN(counter);
	if (_eina_counter_time_get(&tp) != 0)
		return;

	eina_error_set(0);
	clk = calloc(1, sizeof(Eina_Clock));
	if (!clk) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return;
	}

	counter->clocks =
	    eina_inlist_prepend(counter->clocks, EINA_INLIST_GET(clk));

	clk->valid = EINA_FALSE;
	clk->start = tp;
}

/**
 * @brief Stop the time count.
 *
 * @param counter The counter.
 * @param specimen The number of the test.
 *
 * This function stop the timing that has been started with
 * eina_counter_start(). @p counter must be the same than the one used
 * with eina_counter_start(). @p specimen is the number of the
 * test. If @p counter or its associated clock are  @c NULL, or if the
 * time can't be retrieved the function exits.
 */
EAPI void eina_counter_stop(Eina_Counter * counter, int specimen)
{
	Eina_Clock *clk;
	Eina_Nano_Time tp;

	EINA_SAFETY_ON_NULL_RETURN(counter);
	if (_eina_counter_time_get(&tp) != 0)
		return;

	clk = (Eina_Clock *) counter->clocks;

	if (!clk || clk->valid == EINA_TRUE)
		return;

	clk->end = tp;
	clk->specimen = specimen;
	clk->valid = EINA_TRUE;
}

/**
 * @brief Dump the result of all clocks of a counter to a stream.
 *
 * @return A string with a summary of the test.
 * @param counter The counter.
 *
 * This function returns an malloc'd string containing the dump of
 * all the valid clocks of @p counter.
 * If @p counter @c NULL, the functions exits
 * immediately. Otherwise, the output is formattted like that:
 *
 * @verbatim
 * \# specimen    experiment time    starting time    ending time
 * 1              208                120000           120208
 * @endverbatim
 *
 * The unit of time is the nanosecond.
 */
EAPI char *eina_counter_dump(Eina_Counter * counter)
{
	Eina_Clock *clk;
	char *result = NULL;
	int position = 0;

	EINA_SAFETY_ON_NULL_RETURN_VAL(counter, NULL);

	result = _eina_counter_asiprintf(result,
					 &position,
					 "# specimen\texperiment time\tstarting time\tending time\n");
	if (!result)
		return NULL;

	EINA_INLIST_REVERSE_FOREACH(counter->clocks, clk) {
		long int start;
		long int end;
		long int diff;

		if (clk->valid == EINA_FALSE)
			continue;

#ifndef _WIN32
		start =
		    clk->start.tv_sec * 1000000000 + clk->start.tv_nsec;
		end = clk->end.tv_sec * 1000000000 + clk->end.tv_nsec;
		diff =
		    (clk->end.tv_sec -
		     clk->start.tv_sec) * 1000000000 + clk->end.tv_nsec -
		    clk->start.tv_nsec;
#else
		start =
		    (long int) (((long long int) clk->start.QuadPart *
				 1000000000ll) /
				(long long int) _eina_counter_frequency.
				QuadPart);
		end =
		    (long
		     int) (((long long int) clk->end.QuadPart *
			    1000000000LL) /
			   (long long int) _eina_counter_frequency.
			   QuadPart);
		diff =
		    (long
		     int) (((long long int) (clk->end.QuadPart -
					     clk->start.QuadPart) *
			    1000000000LL) /
			   (long long int) _eina_counter_frequency.
			   QuadPart);
#endif				/* _WIN2 */

		result = _eina_counter_asiprintf(result, &position,
						 "%i\t%li\t%li\t%li\n",
						 clk->specimen,
						 diff, start, end);
	}

	return result;
}

/**
 * @}
 */
