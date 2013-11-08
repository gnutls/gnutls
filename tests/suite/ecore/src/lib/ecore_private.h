#ifndef _ECORE_PRIVATE_H
#define _ECORE_PRIVATE_H

extern int _ecore_log_dom;
#ifdef  _ECORE_DEFAULT_LOG_DOM
#undef _ECORE_DEFAULT_LOG_DOM
#endif
#define _ECORE_DEFAULT_LOG_DOM _ecore_log_dom

#ifdef ECORE_DEFAULT_LOG_COLOR
#undef ECORE_DEFAULT_LOG_COLOR
#endif
#define ECORE_DEFAULT_LOG_COLOR EINA_COLOR_BLUE

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_ECORE_DEFAULT_LOG_DOM, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_ECORE_DEFAULT_LOG_DOM, __VA_ARGS__)

#ifdef INF
#undef INF
#endif
#define INF(...) EINA_LOG_DOM_INFO(_ECORE_DEFAULT_LOG_DOM, __VA_ARGS__)

#ifdef WRN
#undef WRN
#endif
#define WRN(...) EINA_LOG_DOM_WARN(_ECORE_DEFAULT_LOG_DOM, __VA_ARGS__)

#ifdef CRIT
#undef CRIT
#endif
#define CRIT(...) EINA_LOG_DOM_CRIT(_ECORE_DEFAULT_LOG_DOM, __VA_ARGS__)

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef MIN
#define MIN(x, y) (((x) > (y)) ? (y) : (x))
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef ABS
#define ABS(x) ((x) < 0 ? -(x) : (x))
#endif

#ifndef CLAMP
#define CLAMP(x, min, max) (((x) > (max)) ? (max) : (((x) < (min)) ? (min) : (x)))
#endif

#define EVAS_FRAME_QUEUING 1	/* for test */

#define READBUFSIZ 65536

#define ECORE_MAGIC_NONE            0x1234fedc
#define ECORE_MAGIC_EXE             0xf7e812f5
#define ECORE_MAGIC_TIMER           0xf7d713f4
#define ECORE_MAGIC_IDLER           0xf7c614f3
#define ECORE_MAGIC_IDLE_ENTERER    0xf7b515f2
#define ECORE_MAGIC_IDLE_EXITER     0xf7601afd
#define ECORE_MAGIC_FD_HANDLER      0xf7a416f1
#define ECORE_MAGIC_EVENT_HANDLER   0xf79317f0
#define ECORE_MAGIC_EVENT_FILTER    0xf78218ff
#define ECORE_MAGIC_EVENT           0xf77119fe
#define ECORE_MAGIC_ANIMATOR        0xf7643ea5
#define ECORE_MAGIC_POLLER          0xf7568127
#define ECORE_MAGIC_PIPE            0xf7458226
#define ECORE_MAGIC_WIN32_HANDLER   0xf7e8f1a3
#define ECORE_MAGIC_JOB             0x76543210


#define ECORE_MAGIC                 Ecore_Magic  __magic

#define ECORE_MAGIC_SET(d, m)       (d)->__magic = (m)
#define ECORE_MAGIC_CHECK(d, m)     ((d) && ((d)->__magic == (m)))
#define ECORE_MAGIC_FAIL(d, m, fn)  _ecore_magic_fail((d), (d) ? (d)->__magic : 0, (m), (fn));

/* undef the following, we want our version */
#undef FREE
#define FREE(ptr) free(ptr); ptr = NULL;

#undef IF_FREE
#define IF_FREE(ptr) if (ptr) free(ptr); ptr = NULL;

#undef IF_FN_DEL
#define IF_FN_DEL(_fn, ptr) if (ptr) { _fn(ptr); ptr = NULL; }

EAPI void ecore_print_warning(const char *function, const char *sparam);

/* convenience macros for checking pointer parameters for non-NULL */
#undef CHECK_PARAM_POINTER_RETURN
#define CHECK_PARAM_POINTER_RETURN(sparam, param, ret) \
     if (!(param)) \
         { \
            ecore_print_warning(__FUNCTION__, sparam); \
            return ret; \
         }

#undef CHECK_PARAM_POINTER
#define CHECK_PARAM_POINTER(sparam, param) \
     if (!(param)) \
         { \
            ecore_print_warning(__FUNCTION__, sparam); \
            return; \
         }

typedef unsigned int Ecore_Magic;

EAPI void _ecore_magic_fail(const void *d, Ecore_Magic m,
			    Ecore_Magic req_m, const char *fname);

void _ecore_time_init(void);

void _ecore_timer_shutdown(void);
void _ecore_timer_cleanup(void);
void _ecore_timer_enable_new(void);
double _ecore_timer_next_get(void);
int _ecore_timers_exists(void);
int _ecore_timer_call(double when);

void _ecore_idler_shutdown(void);
int _ecore_idler_call(void);
int _ecore_idler_exist(void);

void _ecore_idle_enterer_shutdown(void);
void _ecore_idle_enterer_call(void);
int _ecore_idle_enterer_exist(void);

void _ecore_idle_exiter_shutdown(void);
void _ecore_idle_exiter_call(void);
int _ecore_idle_exiter_exist(void);

void _ecore_event_shutdown(void);
int _ecore_event_exist(void);
Ecore_Event *_ecore_event_add(int type, void *ev, Ecore_End_Cb func_free,
			      void *data);
void _ecore_event_call(void);

Ecore_Timer *_ecore_exe_doomsday_clock_get(Ecore_Exe * exe);
void _ecore_exe_doomsday_clock_set(Ecore_Exe * exe, Ecore_Timer * dc);

EAPI void *_ecore_event_signal_user_new(void);
void *_ecore_event_signal_hup_new(void);
void *_ecore_event_signal_exit_new(void);
void *_ecore_event_signal_power_new(void);
void *_ecore_event_signal_realtime_new(void);

void _ecore_main_shutdown(void);

#ifdef _WIN32
static inline void _ecore_signal_shutdown(void)
{
}

static inline void _ecore_signal_init(void)
{
}

static inline int _ecore_signal_count_get(void)
{
	return 0;
}

static inline void _ecore_signal_call(void)
{
}
#else
void _ecore_signal_shutdown(void);
void _ecore_signal_init(void);
int _ecore_signal_count_get(void);
void _ecore_signal_call(void);
#endif

void _ecore_exe_init(void);
void _ecore_exe_shutdown(void);
#ifndef _WIN32
Ecore_Exe *_ecore_exe_find(pid_t pid);
void *_ecore_exe_event_del_new(void);
void _ecore_exe_event_del_free(void *data, void *ev);
#endif

void _ecore_animator_shutdown(void);

void _ecore_poller_shutdown(void);

EAPI void *_ecore_list2_append(void *in_list, void *in_item);
EAPI void *_ecore_list2_prepend(void *in_list, void *in_item);
EAPI void *_ecore_list2_append_relative(void *in_list, void *in_item,
					void *in_relative);
EAPI void *_ecore_list2_prepend_relative(void *in_list, void *in_item,
					 void *in_relative);
EAPI void *_ecore_list2_remove(void *in_list, void *in_item);
EAPI void *_ecore_list2_find(void *in_list, void *in_item);

void _ecore_fps_debug_init(void);
void _ecore_fps_debug_shutdown(void);
void _ecore_fps_debug_runtime_add(double t);

void _ecore_thread_init(void);
void _ecore_thread_shutdown(void);

void _ecore_glib_init(void);
void _ecore_glib_shutdown(void);

void _ecore_job_init(void);
void _ecore_job_shutdown(void);

void _ecore_main_loop_init(void);
void _ecore_main_loop_shutdown(void);

extern int _ecore_fps_debug;
extern double _ecore_time_loop_time;
extern Eina_Bool _ecore_glib_always_integrate;

#endif
