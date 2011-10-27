#include <sys/time.h>
#include <time.h>
#include <signal.h>
#if defined(_WIN32)
# include <windows.h>
#endif
#include "timespec.h"           /* gnulib gettime */

typedef void (*sighandler_t)(int);

void benchmark_cipher (int init, int debug_level);
void benchmark_tls (int debug_level);

struct benchmark_st
{
  struct timespec start;
  unsigned long size;
  sighandler_t old_handler;
#if defined(_WIN32)
  HANDLE wtimer;
  HANDLE wthread;
  LARGE_INTEGER alarm_timeout;
#endif
};

extern int benchmark_must_finish;

void start_benchmark(struct benchmark_st * st);
double stop_benchmark(struct benchmark_st * st, const char* metric);

