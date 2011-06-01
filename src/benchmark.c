#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "benchmark.h"

int benchmark_must_finish = 0;

#if defined(_WIN32)
#include <windows.h>
DWORD WINAPI
alarm_handler (LPVOID lpParameter)
{
  HANDLE wtimer = *((HANDLE *) lpParameter);
  WaitForSingleObject (wtimer, INFINITE);
  benchmark_must_finish = 1;
  return 0;
}
#else
static void
alarm_handler (int signo)
{
  benchmark_must_finish = 1;
}
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
  memset(st, 0, sizeof(*st));
  st->old_handler = signal (SIGALRM, alarm_handler);
  gettime (&st->start);
  benchmark_must_finish = 0;

#if defined(_WIN32)
  st->wtimer = CreateWaitableTimer (NULL, TRUE, NULL);
  if (st->wtimer == NULL)
    {
      fprintf (stderr, "error: CreateWaitableTimer %u\n", GetLastError ());
      exit(1);
    }
  st->wthread = CreateThread (NULL, 0, alarm_handler, &st->wtimer, 0, NULL);
  if (st->wthread == NULL)
    {
      fprintf (stderr, "error: CreateThread %u\n", GetLastError ());
      exit(1);
    }
  alarm_timeout.QuadPart = (5) * 10000000;
  if (SetWaitableTimer (st->wtimer, &alarm_timeout, 0, NULL, NULL, FALSE) == 0)
    {
      fprintf (stderr, "error: SetWaitableTimer %u\n", GetLastError ());
      exit(1);
    }
  }
#else
  alarm (5);
#endif
  
}

/* returns the elapsed time */
double stop_benchmark(struct benchmark_st * st, const char* metric)
{
  double secs;
  struct timespec stop;
  double dspeed, ddata;
  char imetric[16];

#if defined(_WIN32)
  if (st->wtimer != NULL)
    CloseHandle (st->wtimer);
  if (st->wthread != NULL)
    CloseHandle (st->wthread);
#else
  signal(SIGALRM, st->old_handler);
#endif

  gettime (&stop);

  secs = (stop.tv_sec * 1000 + stop.tv_nsec / (1000 * 1000) -
          (st->start.tv_sec * 1000 + st->start.tv_nsec / (1000 * 1000)));
  secs /= 1000;

  if (metric == NULL)
    { /* assume bytes/sec */
      value2human (st->size, secs, &ddata, &dspeed, imetric);
      printf ("Processed %.2f %s in %.2f secs: ", ddata, imetric, secs);
      printf ("%.2f %s/sec\n", dspeed, imetric);
    }
  else
    {
      ddata = (double) st->size;
      dspeed = ddata / secs;
      printf ("Processed %.2f %s in %.2f secs: ", ddata, metric, secs);
      printf ("%.2f %s/sec\n", dspeed, metric);
    }

  return secs;
}
