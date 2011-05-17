#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "benchmark.h"

int benchmark_must_finish = 0;

#if !defined(_WIN32)
static void
alarm_handler (int signo)
{
  benchmark_must_finish = 1;
}
#else
#include <windows.h>
DWORD WINAPI
alarm_handler (LPVOID lpParameter)
{
  HANDLE wtimer = *((HANDLE *) lpParameter);
  WaitForSingleObject (wtimer, INFINITE);
  benchmark_must_finish = 1;
  return 0;
}

#define W32_ALARM_VARIABLES HANDLE wtimer = NULL, wthread = NULL; \
  LARGE_INTEGER alarm_timeout = { 0 , 0 }
#define W32_ALARM_TRIGGER(timeout, leave) { \
  wtimer = CreateWaitableTimer (NULL, TRUE, NULL); \
  if (wtimer == NULL) \
    { \
      fprintf (stderr, "error: CreateWaitableTimer %u\n", GetLastError ()); \
      leave; \
    } \
  wthread = CreateThread (NULL, 0, alarm_handler, &wtimer, 0, NULL); \
  if (wthread == NULL) \
    { \
      fprintf (stderr, "error: CreateThread %u\n", GetLastError ()); \
      leave; \
    } \
  alarm_timeout.QuadPart = timeout * 10000000; \
  if (SetWaitableTimer (wtimer, &alarm_timeout, 0, NULL, NULL, FALSE) == 0) \
    { \
      fprintf (stderr, "error: SetWaitableTimer %u\n", GetLastError ()); \
      leave; \
    } \
  }
#define W32_ALARM_CLEANUP { \
  if (wtimer != NULL) \
    CloseHandle (wtimer); \
  if (wthread != NULL) \
    CloseHandle (wthread);}
#endif

static void
value2human (unsigned long bytes, double time, double *data, double *speed,
             char *metric)
{
  if (bytes > 1000 && bytes < 1000 * 1000)
    {
      *data = ((double) bytes) / 1000;
      *speed = *data / time;
      strcpy (metric, "Kb");
      return;
    }
  else if (bytes >= 1000 * 1000 && bytes < 1000 * 1000 * 1000)
    {
      *data = ((double) bytes) / (1000 * 1000);
      *speed = *data / time;
      strcpy (metric, "Mb");
      return;
    }
  else if (bytes >= 1000 * 1000 * 1000)
    {
      *data = ((double) bytes) / (1000 * 1000 * 1000);
      *speed = *data / time;
      strcpy (metric, "Gb");
      return;
    }
  else
    {
      *data = (double) bytes;
      *speed = *data / time;
      strcpy (metric, "bytes");
      return;
    }
}

void start_benchmark(struct benchmark_st * st)
{
  st->old_handler = signal (SIGALRM, alarm_handler);

  benchmark_must_finish = 0;
  st->size = 0;

#if !defined(_WIN32)
  alarm (5);
#else
  W32_ALARM_TRIGGER(5, goto leave);
#endif
  gettime (&st->start);
  
}

/* returns the elapsed time */
double stop_benchmark(struct benchmark_st * st)
{
  double secs;
  struct timespec stop;
  double dspeed, ddata;
  char metric[16];

#if defined(_WIN32)
leave:
  W32_ALARM_CLEANUP;
#else
  signal(SIGALRM, st->old_handler);
#endif

  gettime (&stop);

  secs = (stop.tv_sec * 1000 + stop.tv_nsec / (1000 * 1000) -
          (st->start.tv_sec * 1000 + st->start.tv_nsec / (1000 * 1000)));
  secs /= 1000;

  value2human (st->size, secs, &ddata, &dspeed, metric);
  printf ("Processed %.2f %s in %.2f secs: ", ddata, metric, secs);
  printf ("%.2f %s/sec\n", dspeed, metric);

  return secs;
}
