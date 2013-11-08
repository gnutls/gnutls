#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#undef WIN32_LEAN_AND_MEAN
#ifndef USER_TIMER_MINIMUM
#define USER_TIMER_MINIMUM 0x0a
#endif
#endif

#ifdef __SUNPRO_C
#include <ieeefp.h>
#include <string.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#ifndef _MSC_VER
#include <sys/time.h>
#include <unistd.h>
#else
#include <float.h>
#endif

#define FIX_HZ 1

#ifdef FIX_HZ
#ifndef _MSC_VER
#include <sys/param.h>
#endif
#ifndef HZ
#define HZ 100
#endif
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "Ecore.h"
#include "ecore_private.h"

#ifdef HAVE_SYS_EPOLL_H
#define HAVE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef USE_G_MAIN_LOOP
#include <glib.h>
#endif

struct _Ecore_Fd_Handler {
	EINA_INLIST;
	ECORE_MAGIC;
	int fd;
	Ecore_Fd_Handler_Flags flags;
	Ecore_Fd_Cb func;
	void *data;
	Ecore_Fd_Cb buf_func;
	void *buf_data;
	Ecore_Fd_Prep_Cb prep_func;
	void *prep_data;
	int references;
	Eina_Bool read_active:1;
	Eina_Bool write_active:1;
	Eina_Bool error_active:1;
	Eina_Bool delete_me:1;
};

#ifdef _WIN32
struct _Ecore_Win32_Handler {
	EINA_INLIST;
	ECORE_MAGIC;
	HANDLE h;
	Ecore_Fd_Win32_Cb func;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};
#endif


static int _ecore_main_select(double timeout);
static void _ecore_main_prepare_handlers(void);
static void _ecore_main_fd_handlers_cleanup(void);
#ifndef _WIN32
static void _ecore_main_fd_handlers_bads_rem(void);
#endif
static void _ecore_main_fd_handlers_call(void);
static int _ecore_main_fd_handlers_buf_call(void);
#ifndef USE_G_MAIN_LOOP
static void _ecore_main_loop_iterate_internal(int once_only);
#endif

#ifdef _WIN32
static int _ecore_main_win32_select(int nfds, fd_set * readfds,
				    fd_set * writefds, fd_set * exceptfds,
				    struct timeval *timeout);
static void _ecore_main_win32_handlers_cleanup(void);
#endif

static int in_main_loop = 0;
static int do_quit = 0;
static Ecore_Fd_Handler *fd_handlers = NULL;
static Ecore_Fd_Handler *fd_handler_current = NULL;
static int fd_handlers_delete_me = 0;
#ifdef _WIN32
static Ecore_Win32_Handler *win32_handlers = NULL;
static Ecore_Win32_Handler *win32_handler_current = NULL;
static int win32_handlers_delete_me = 0;
#endif

#ifdef _WIN32
static Ecore_Select_Function main_loop_select = _ecore_main_win32_select;
#else
static Ecore_Select_Function main_loop_select = select;
#endif

static double t1 = 0.0;
static double t2 = 0.0;

#ifdef HAVE_EPOLL
static int epoll_fd = -1;
#endif

#ifdef USE_G_MAIN_LOOP
static GSource *ecore_epoll_source;
static GPollFD ecore_epoll_fd;
static guint ecore_epoll_id;
static GMainLoop *ecore_main_loop;
static gboolean ecore_idling;
static gboolean ecore_fds_ready;
#endif

#ifdef HAVE_EPOLL
static inline int _ecore_poll_events_from_fdh(Ecore_Fd_Handler * fdh)
{
	int events = 0;
	if (fdh->flags & ECORE_FD_READ)
		events |= EPOLLIN;
	if (fdh->flags & ECORE_FD_WRITE)
		events |= EPOLLOUT;
	if (fdh->flags & ECORE_FD_ERROR)
		events |= EPOLLERR;
	return events;
}
#else
static inline int _ecore_poll_events_from_fdh(Ecore_Fd_Handler *
					      fdh __UNUSED__)
{
	return 0;
}
#endif

#ifdef HAVE_EPOLL
static inline int _ecore_main_fdh_epoll_add(Ecore_Fd_Handler * fdh)
{
	int r = 0;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = _ecore_poll_events_from_fdh(fdh);
	ev.data.ptr = fdh;
	INF("adding poll on %d %08x", fdh->fd, ev.events);
	r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fdh->fd, &ev);
	return r;
}
#else
static inline int _ecore_main_fdh_epoll_add(Ecore_Fd_Handler *
					    fdh __UNUSED__)
{
	return 0;
}
#endif

#ifdef HAVE_EPOLL
static inline void _ecore_main_fdh_epoll_del(Ecore_Fd_Handler * fdh)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	INF("removing poll on %d", fdh->fd);
	/* could get an EBADF if somebody closed the FD before removing it */
	if ((epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fdh->fd, &ev) < 0) &&
	    (errno != EBADF)) {
		ERR("Failed to delete epoll fd %d! (errno=%d)", fdh->fd,
		    errno);
	}
}
#else
static inline void _ecore_main_fdh_epoll_del(Ecore_Fd_Handler *
					     fdh __UNUSED__)
{
}
#endif

#ifdef HAVE_EPOLL
static inline int _ecore_main_fdh_epoll_modify(Ecore_Fd_Handler * fdh)
{
	int r = 0;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = _ecore_poll_events_from_fdh(fdh);
	ev.data.ptr = fdh;
	INF("modifing epoll on %d to %08x", fdh->fd, ev.events);
	r = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fdh->fd, &ev);
	return r;
}
#else
static inline int _ecore_main_fdh_epoll_modify(Ecore_Fd_Handler *
					       fdh __UNUSED__)
{
	return 0;
}
#endif

#ifdef HAVE_EPOLL
static inline int _ecore_main_fdh_epoll_mark_active(void)
{
	struct epoll_event ev[32];
	int i, ret;

	memset(&ev, 0, sizeof(ev));
	ret =
	    epoll_wait(epoll_fd, ev,
		       sizeof(ev) / sizeof(struct epoll_event), 0);
	if (ret < 0) {
		if (errno == EINTR)
			return -1;
		ERR("epoll_wait failed %d", errno);
		return -1;
	}

	for (i = 0; i < ret; i++) {
		Ecore_Fd_Handler *fdh;

		fdh = ev[i].data.ptr;
		if (!ECORE_MAGIC_CHECK(fdh, ECORE_MAGIC_FD_HANDLER)) {
			ECORE_MAGIC_FAIL(fdh, ECORE_MAGIC_FD_HANDLER,
					 "_ecore_main_fdh_epoll_mark_active");
			continue;
		}
		if (fdh->delete_me) {
			ERR("deleted fd in epoll");
			continue;
		}
		if (ev->events & EPOLLIN)
			fdh->read_active = 1;
		if (ev->events & EPOLLOUT)
			fdh->write_active = 1;
		if (ev->events & EPOLLERR)
			fdh->error_active = 1;
	}

	return ret;
}
#endif

#ifdef USE_G_MAIN_LOOP

/* like we are about to enter main_loop_select in  _ecore_main_select */
static gboolean
_ecore_main_gsource_prepare(GSource * source, gint * next_time)
{
	double t = _ecore_timer_next_get();
	gboolean running;

	INF("enter, next timeout in %.1f", t);
	in_main_loop++;

	if (!ecore_idling) {
		while (_ecore_timer_call(_ecore_time_loop_time));
		_ecore_timer_cleanup();

		/* when idling, busy loop checking the fds only */
		if (!ecore_idling)
			_ecore_idle_enterer_call();
	}

	/* don't check fds if somebody quit */
	running = g_main_loop_is_running(ecore_main_loop);
	if (running) {
		/* only set idling state in dispatch */
		if (ecore_idling && !_ecore_idler_exist()) {
			if (_ecore_timers_exists()) {
				double t = _ecore_timer_next_get();
				*next_time = (t / 1000.0);
			} else
				*next_time = -1;
		} else
			*next_time = 0;

		_ecore_main_prepare_handlers();
	}

	in_main_loop--;
	INF("leave, timeout = %d", *next_time);

	/* ready if we're not running (about to quit) */
	return !running;
}

static gboolean _ecore_main_gsource_check(GSource * source)
{
	INF("enter");
	in_main_loop++;

	ecore_fds_ready = (_ecore_main_fdh_epoll_mark_active() > 0);
	_ecore_main_fd_handlers_cleanup();

	_ecore_time_loop_time = ecore_time_get();
	_ecore_timer_enable_new();

	in_main_loop--;
	INF("leave");

	return TRUE;		/* always dispatch */
}

/* like we just came out of main_loop_select in  _ecore_main_select */
static gboolean
_ecore_main_gsource_dispatch(GSource * source, GSourceFunc callback,
			     gpointer user_data)
{
	gboolean events_ready, timers_ready, idlers_ready, signals_ready;
	double next_time = _ecore_timer_next_get();

	events_ready = _ecore_event_exist();
	timers_ready = _ecore_timers_exists() && (0.0 <= next_time);
	idlers_ready = _ecore_idler_exist();
	signals_ready = (_ecore_signal_count_get() > 0);

	in_main_loop++;
	INF("enter idling=%d fds=%d events=%d signals=%d timers=%d (next=%.2f) idlers=%d", ecore_idling, ecore_fds_ready, events_ready, signals_ready, _ecore_timers_exists(), next_time, idlers_ready);

	if (ecore_idling && events_ready) {
		INF("calling idle exiters");
		_ecore_idle_exiter_call();
		ecore_idling = 0;
	} else if (!ecore_idling && !events_ready) {
		INF("start idling");
		ecore_idling = 1;
	}

	if (ecore_idling) {
		INF("calling idler");
		_ecore_idler_call();

		events_ready = _ecore_event_exist();
		timers_ready = _ecore_timers_exists()
		    && (0.0 <= next_time);
		idlers_ready = _ecore_idler_exist();

		if ((ecore_fds_ready || events_ready || timers_ready
		     || idlers_ready || signals_ready)) {
			INF("calling idle exiters");
			_ecore_idle_exiter_call();
			ecore_idling = 0;
		}
	}

	/* process events */
	if (!ecore_idling) {
		INF("work");
		_ecore_main_fd_handlers_call();
		_ecore_main_fd_handlers_buf_call();
		while (_ecore_signal_count_get())
			_ecore_signal_call();
		_ecore_event_call();
		_ecore_main_fd_handlers_cleanup();
	}

	in_main_loop--;

	INF("leave");

	return TRUE;		/* what should be returned here? */
}

static void _ecore_main_gsource_finalize(GSource * source)
{
	INF("finalize");
}

static GSourceFuncs ecore_gsource_funcs = {
	.prepare = _ecore_main_gsource_prepare,
	.check = _ecore_main_gsource_check,
	.dispatch = _ecore_main_gsource_dispatch,
	.finalize = _ecore_main_gsource_finalize,
};

#endif

void _ecore_main_loop_init(void)
{
	INF("enter");
#ifdef HAVE_EPOLL
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0)
		CRIT("Failed to create epoll fd!");
#endif

#ifdef USE_G_MAIN_LOOP
	ecore_epoll_source =
	    g_source_new(&ecore_gsource_funcs, sizeof(GSource));
	if (!ecore_epoll_source)
		CRIT("Failed to create glib source for epoll!");
	else {
		ecore_epoll_fd.fd = epoll_fd;
		ecore_epoll_fd.events = G_IO_IN;
		ecore_epoll_fd.revents = 0;
		g_source_add_poll(ecore_epoll_source, &ecore_epoll_fd);
		ecore_epoll_id = g_source_attach(ecore_epoll_source, NULL);
		if (ecore_epoll_id <= 0)
			CRIT("Failed to attach glib source to default context");
	}
#endif
	INF("leave");
}

void _ecore_main_loop_shutdown(void)
{
#ifdef USE_G_MAIN_LOOP
	if (ecore_epoll_source) {
		g_source_destroy(ecore_epoll_source);
		ecore_epoll_source = NULL;
	}
#endif

#ifdef HAVE_EPOLL
	if (epoll_fd >= 0) {
		close(epoll_fd);
		epoll_fd = -1;
	}
#endif
}


/**
 * @defgroup Ecore_Main_Loop_Group Main Loop Functions
 *
 * These functions control the Ecore event handling loop.  This loop is
 * designed to work on embedded systems all the way to large and
 * powerful mutli-cpu workstations.
 *
 * It serialises all system signals and events into a single event
 * queue, that can be easily processed without needing to worry about
 * concurrency.  A properly written, event-driven program using this
 * kind of programming does not need threads.  It makes the program very
 * robust and easy to follow.
 *
 * Here is an example of simple program and its basic event loop flow:
 * @image html prog_flow.png
 *
 * For examples of setting up and using a main loop, see
 * @ref event_handler_example.c and @ref timer_example.c.
 */

/**
 * Runs a single iteration of the main loop to process everything on the
 * queue.
 * @ingroup Ecore_Main_Loop_Group
 */
EAPI void ecore_main_loop_iterate(void)
{
#ifndef USE_G_MAIN_LOOP
	_ecore_main_loop_iterate_internal(1);
#else
	g_main_context_iteration(NULL, 1);
#endif
}

/**
 * Runs the application main loop.
 *
 * This function will not return until @ref ecore_main_loop_quit is called.
 *
 * @ingroup Ecore_Main_Loop_Group
 */
EAPI void ecore_main_loop_begin(void)
{
#ifndef USE_G_MAIN_LOOP
	in_main_loop++;
	while (do_quit == 0)
		_ecore_main_loop_iterate_internal(0);
	do_quit = 0;
	in_main_loop--;
#else
	ecore_main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(ecore_main_loop);
#endif
}

/**
 * Quits the main loop once all the events currently on the queue have
 * been processed.
 * @ingroup Ecore_Main_Loop_Group
 */
EAPI void ecore_main_loop_quit(void)
{
#ifndef USE_G_MAIN_LOOP
	do_quit = 1;
#else
	INF("enter");
	g_main_loop_quit(ecore_main_loop);
	INF("leave");
#endif
}

/**
 * Sets the function to use when monitoring multiple file descriptors,
 * and waiting until one of more of the file descriptors before ready
 * for some class of I/O operation.
 *
 * This function will be used instead of the system call select and
 * could possible be used to integrate the Ecore event loop with an
 * external event loop.
 *
 * @warning you don't know how to use, don't even try to use it.
 *
 * @ingroup Ecore_Main_Loop_Group
 */
EAPI void ecore_main_loop_select_func_set(Ecore_Select_Function func)
{
	main_loop_select = func;
}

/**
 * Gets the select function set by ecore_select_func_set(),
 * or the native select function if none was set.
 *
 * @ingroup Ecore_Main_Loop_Group
 */
EAPI void *ecore_main_loop_select_func_get(void)
{
	return main_loop_select;
}

/**
 * @defgroup Ecore_FD_Handler_Group File Event Handling Functions
 *
 * Functions that deal with file descriptor handlers.
 */

/**
 * Adds a callback for activity on the given file descriptor.
 *
 * @p func will be called during the execution of @ref ecore_main_loop_begin
 * when the file descriptor is available for reading, or writing, or both.
 *
 * Normally the return value from the @p func is "zero means this handler is
 * finished and can be deleted" as is usual for handler callbacks.  However,
 * if the @p buf_func is supplied, then the return value from the @p func is
 * "non zero means the handler should be called again in a tight loop".
 *
 * @p buf_func is called during event loop handling to check if data that has
 * been read from the file descriptor is in a buffer and is available to
 * read.  Some systems (notably xlib) handle their own buffering, and would
 * otherwise not work with select().  These systems should use a @p buf_func.
 * This is a most annoying hack, only ecore_x uses it, so refer to that for
 * an example.  NOTE - @p func should probably return "one" always if
 * @p buf_func is used, to avoid confusion with the other return value
 * semantics.
 *
 * @param   fd       The file descriptor to watch.
 * @param   flags    To watch it for read (@c ECORE_FD_READ) and/or
 *                   (@c ECORE_FD_WRITE) write ability.  @c ECORE_FD_ERROR
 *
 * @param   func     The callback function.
 * @param   data     The data to pass to the callback.
 * @param   buf_func The function to call to check if any data has been
 *                   buffered and already read from the fd.  Can be @c NULL.
 * @param   buf_data The data to pass to the @p buf_func function.
 * @return  A fd handler handle if successful.  @c NULL otherwise.
 * @ingroup Ecore_FD_Handler_Group
 */
EAPI Ecore_Fd_Handler *ecore_main_fd_handler_add(int fd,
						 Ecore_Fd_Handler_Flags
						 flags, Ecore_Fd_Cb func,
						 const void *data,
						 Ecore_Fd_Cb buf_func,
						 const void *buf_data)
{
	Ecore_Fd_Handler *fdh;

	if ((fd < 0) || (flags == 0) || (!func))
		return NULL;

	fdh = calloc(1, sizeof(Ecore_Fd_Handler));
	if (!fdh)
		return NULL;
	ECORE_MAGIC_SET(fdh, ECORE_MAGIC_FD_HANDLER);
	fdh->fd = fd;
	fdh->flags = flags;
	if (0 > _ecore_main_fdh_epoll_add(fdh)) {
		ERR("Failed to add epoll fd %d (errno = %d)!", fd, errno);
		free(fdh);
		return NULL;
	}
	fdh->read_active = 0;
	fdh->write_active = 0;
	fdh->error_active = 0;
	fdh->delete_me = 0;
	fdh->func = func;
	fdh->data = (void *) data;
	fdh->buf_func = buf_func;
	fdh->buf_data = (void *) buf_data;
	fd_handlers = (Ecore_Fd_Handler *)
	    eina_inlist_append(EINA_INLIST_GET(fd_handlers),
			       EINA_INLIST_GET(fdh));
	return fdh;
}

#ifdef _WIN32
EAPI Ecore_Win32_Handler *ecore_main_win32_handler_add(void *h,
						       Ecore_Fd_Win32_Cb
						       func,
						       const void *data)
{
	Ecore_Win32_Handler *wh;

	if (!h || !func)
		return NULL;

	wh = calloc(1, sizeof(Ecore_Win32_Handler));
	if (!wh)
		return NULL;
	ECORE_MAGIC_SET(wh, ECORE_MAGIC_WIN32_HANDLER);
	wh->h = (HANDLE) h;
	wh->delete_me = 0;
	wh->func = func;
	wh->data = (void *) data;
	win32_handlers = (Ecore_Win32_Handler *)
	    eina_inlist_append(EINA_INLIST_GET(win32_handlers),
			       EINA_INLIST_GET(wh));
	return wh;
}
#else
EAPI Ecore_Win32_Handler *ecore_main_win32_handler_add(void *h __UNUSED__,
						       Ecore_Fd_Win32_Cb
						       func __UNUSED__,
						       const void *data
						       __UNUSED__)
{
	return NULL;
}
#endif

/**
 * Deletes the given FD handler.
 * @param   fd_handler The given FD handler.
 * @return  The data pointer set using @ref ecore_main_fd_handler_add,
 *          for @p fd_handler on success.  @c NULL otherwise.
 * @ingroup Ecore_FD_Handler_Group
 *
 * Beware that if the fd is already closed, ecore may complain if it uses
 * epoll internally, and that in some rare cases this may be able to cause
 * crashes and instability. Remember to delete your fd handlers before the
 * fd's they listen to are closed.
 */
EAPI void *ecore_main_fd_handler_del(Ecore_Fd_Handler * fd_handler)
{
	if (!ECORE_MAGIC_CHECK(fd_handler, ECORE_MAGIC_FD_HANDLER)) {
		ECORE_MAGIC_FAIL(fd_handler, ECORE_MAGIC_FD_HANDLER,
				 "ecore_main_fd_handler_del");
		return NULL;
	}
	fd_handler->delete_me = 1;
	fd_handlers_delete_me = 1;
	_ecore_main_fdh_epoll_del(fd_handler);
	return fd_handler->data;
}

#ifdef _WIN32
EAPI void *ecore_main_win32_handler_del(Ecore_Win32_Handler *
					win32_handler)
{
	if (!ECORE_MAGIC_CHECK(win32_handler, ECORE_MAGIC_WIN32_HANDLER)) {
		ECORE_MAGIC_FAIL(win32_handler, ECORE_MAGIC_WIN32_HANDLER,
				 "ecore_main_win32_handler_del");
		return NULL;
	}
	win32_handler->delete_me = 1;
	win32_handlers_delete_me = 1;
	return win32_handler->data;
}
#else
EAPI void *ecore_main_win32_handler_del(Ecore_Win32_Handler *
					win32_handler __UNUSED__)
{
	return NULL;
}
#endif

EAPI void
ecore_main_fd_handler_prepare_callback_set(Ecore_Fd_Handler * fd_handler,
					   Ecore_Fd_Prep_Cb func,
					   const void *data)
{
	if (!ECORE_MAGIC_CHECK(fd_handler, ECORE_MAGIC_FD_HANDLER)) {
		ECORE_MAGIC_FAIL(fd_handler, ECORE_MAGIC_FD_HANDLER,
				 "ecore_main_fd_handler_prepare_callback_set");
		return;
	}
	fd_handler->prep_func = func;
	fd_handler->prep_data = (void *) data;
}

/**
 * Retrieves the file descriptor that the given handler is handling.
 * @param   fd_handler The given FD handler.
 * @return  The file descriptor the handler is watching.
 * @ingroup Ecore_FD_Handler_Group
 */
EAPI int ecore_main_fd_handler_fd_get(Ecore_Fd_Handler * fd_handler)
{
	if (!ECORE_MAGIC_CHECK(fd_handler, ECORE_MAGIC_FD_HANDLER)) {
		ECORE_MAGIC_FAIL(fd_handler, ECORE_MAGIC_FD_HANDLER,
				 "ecore_main_fd_handler_fd_get");
		return -1;
	}
	return fd_handler->fd;
}

/**
 * Return if read, write or error, or a combination thereof, is active on the
 * file descriptor of the given FD handler.
 * @param   fd_handler The given FD handler.
 * @param   flags      The flags, @c ECORE_FD_READ, @c ECORE_FD_WRITE or
 *                     @c ECORE_FD_ERROR to query.
 * @return  #EINA_TRUE if any of the given flags are active. #EINA_FALSE otherwise.
 * @ingroup Ecore_FD_Handler_Group
 */
EAPI Eina_Bool
ecore_main_fd_handler_active_get(Ecore_Fd_Handler * fd_handler,
				 Ecore_Fd_Handler_Flags flags)
{
	int ret = EINA_FALSE;

	if (!ECORE_MAGIC_CHECK(fd_handler, ECORE_MAGIC_FD_HANDLER)) {
		ECORE_MAGIC_FAIL(fd_handler, ECORE_MAGIC_FD_HANDLER,
				 "ecore_main_fd_handler_active_get");
		return EINA_FALSE;
	}
	if ((flags & ECORE_FD_READ) && (fd_handler->read_active))
		ret = EINA_TRUE;
	if ((flags & ECORE_FD_WRITE) && (fd_handler->write_active))
		ret = EINA_TRUE;
	if ((flags & ECORE_FD_ERROR) && (fd_handler->error_active))
		ret = EINA_TRUE;
	return ret;
}

/**
 * Set what active streams the given FD handler should be monitoring.
 * @param   fd_handler The given FD handler.
 * @param   flags      The flags to be watching.
 * @ingroup Ecore_FD_Handler_Group
 */
EAPI void
ecore_main_fd_handler_active_set(Ecore_Fd_Handler * fd_handler,
				 Ecore_Fd_Handler_Flags flags)
{
	if (!ECORE_MAGIC_CHECK(fd_handler, ECORE_MAGIC_FD_HANDLER)) {
		ECORE_MAGIC_FAIL(fd_handler, ECORE_MAGIC_FD_HANDLER,
				 "ecore_main_fd_handler_active_set");
		return;
	}
	fd_handler->flags = flags;
	if (0 > _ecore_main_fdh_epoll_modify(fd_handler)) {
		ERR("Failed to mod epoll fd %d!", fd_handler->fd);
	}
}

void _ecore_main_shutdown(void)
{
	if (in_main_loop) {
		ERR("\n"
		    "*** ECORE WARINING: Calling ecore_shutdown() while still in the main loop.\n"
		    "***                 Program may crash or behave strangely now.");
		return;
	}
	while (fd_handlers) {
		Ecore_Fd_Handler *fdh;

		fdh = fd_handlers;
		fd_handlers =
		    (Ecore_Fd_Handler *)
		    eina_inlist_remove(EINA_INLIST_GET(fd_handlers),
				       EINA_INLIST_GET(fdh));
		ECORE_MAGIC_SET(fdh, ECORE_MAGIC_NONE);
		free(fdh);
	}
	fd_handlers_delete_me = 0;
	fd_handler_current = NULL;

#ifdef _WIN32
	while (win32_handlers) {
		Ecore_Win32_Handler *wh;

		wh = win32_handlers;
		win32_handlers =
		    (Ecore_Win32_Handler *)
		    eina_inlist_remove(EINA_INLIST_GET(win32_handlers),
				       EINA_INLIST_GET(wh));
		ECORE_MAGIC_SET(wh, ECORE_MAGIC_NONE);
		free(wh);
	}
	win32_handlers_delete_me = 0;
	win32_handler_current = NULL;
#endif
}

static void _ecore_main_prepare_handlers(void)
{
	Ecore_Fd_Handler *fdh;

	/* call the prepare callback for all handlers */
	EINA_INLIST_FOREACH(fd_handlers, fdh) {
		if (!fdh->delete_me && fdh->prep_func) {
			fdh->references++;
			fdh->prep_func(fdh->prep_data, fdh);
			fdh->references--;
		}
	}
}

static int _ecore_main_select(double timeout)
{
	struct timeval tv, *t;
	fd_set rfds, wfds, exfds;
	int max_fd;
	int ret;

	t = NULL;
	if ((!finite(timeout)) || (timeout == 0.0)) {	/* finite() tests for NaN, too big, too small, and infinity.  */
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		t = &tv;
	} else if (timeout > 0.0) {
		int sec, usec;

#ifdef FIX_HZ
		timeout += (0.5 / HZ);
		sec = (int) timeout;
		usec = (int) ((timeout - (double) sec) * 1000000);
#else
		sec = (int) timeout;
		usec = (int) ((timeout - (double) sec) * 1000000);
#endif
		tv.tv_sec = sec;
		tv.tv_usec = usec;
		t = &tv;
	}
	max_fd = 0;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&exfds);

	/* call the prepare callback for all handlers */
	_ecore_main_prepare_handlers();
#ifndef HAVE_EPOLL
	Ecore_Fd_Handler *fdh;

	EINA_INLIST_FOREACH(fd_handlers, fdh) {
		if (!fdh->delete_me) {
			if (fdh->flags & ECORE_FD_READ) {
				FD_SET(fdh->fd, &rfds);
				if (fdh->fd > max_fd)
					max_fd = fdh->fd;
			}
			if (fdh->flags & ECORE_FD_WRITE) {
				FD_SET(fdh->fd, &wfds);
				if (fdh->fd > max_fd)
					max_fd = fdh->fd;
			}
			if (fdh->flags & ECORE_FD_ERROR) {
				FD_SET(fdh->fd, &exfds);
				if (fdh->fd > max_fd)
					max_fd = fdh->fd;
			}
		}
	}
#else				/* HAVE_EPOLL */
	/* polling on the epoll fd will wake when an fd in the epoll set is active */
	FD_SET(epoll_fd, &rfds);
	max_fd = epoll_fd;
#endif				/* HAVE_EPOLL */

	if (_ecore_signal_count_get())
		return -1;

	ret = main_loop_select(max_fd + 1, &rfds, &wfds, &exfds, t);

	_ecore_time_loop_time = ecore_time_get();
	if (ret < 0) {
#ifndef _WIN32
		if (errno == EINTR)
			return -1;
		else if (errno == EBADF)
			_ecore_main_fd_handlers_bads_rem();
#endif
	}
	if (ret > 0) {
#ifdef HAVE_EPOLL
		_ecore_main_fdh_epoll_mark_active();
#else				/* HAVE_EPOLL */
		Ecore_Fd_Handler *fdh;

		EINA_INLIST_FOREACH(fd_handlers, fdh) {
			if (!fdh->delete_me) {
				if (FD_ISSET(fdh->fd, &rfds))
					fdh->read_active = 1;
				if (FD_ISSET(fdh->fd, &wfds))
					fdh->write_active = 1;
				if (FD_ISSET(fdh->fd, &exfds))
					fdh->error_active = 1;
			}
		}
#endif				/* HAVE_EPOLL */
		_ecore_main_fd_handlers_cleanup();
#ifdef _WIN32
		_ecore_main_win32_handlers_cleanup();
#endif
		return 1;
	}
	return 0;
}

#ifndef _WIN32
static void _ecore_main_fd_handlers_bads_rem(void)
{
	Ecore_Fd_Handler *fdh;
	Eina_Inlist *l;
	int found = 0;

	ERR("Removing bad fds");
	for (l = EINA_INLIST_GET(fd_handlers); l;) {
		fdh = (Ecore_Fd_Handler *) l;
		l = l->next;
		errno = 0;

		if ((fcntl(fdh->fd, F_GETFD) < 0) && (errno == EBADF)) {
			ERR("Found bad fd at index %d", fdh->fd);
			if (fdh->flags & ECORE_FD_ERROR) {
				ERR("Fd set for error! calling user");
				fdh->references++;
				if (!fdh->func(fdh->data, fdh)) {
					ERR("Fd function err returned 0, remove it");
					fdh->delete_me = 1;
					fd_handlers_delete_me = 1;
					found++;
				}
				fdh->references--;
			} else {
				ERR("Problematic fd found at %d! setting it for delete", fdh->fd);
				fdh->delete_me = 1;
				fd_handlers_delete_me = 1;
				found++;
			}
		}
	}
	if (found == 0) {
#ifdef HAVE_GLIB
		ERR("No bad fd found. Maybe a foreign fd from glib?");
#else
		ERR("No bad fd found. EEEK!");
#endif
	}
	_ecore_main_fd_handlers_cleanup();
}
#endif

static void _ecore_main_fd_handlers_cleanup(void)
{
	Ecore_Fd_Handler *fdh;
	Eina_Inlist *l;
	int deleted_in_use = 0;

	if (!fd_handlers_delete_me)
		return;
	for (l = EINA_INLIST_GET(fd_handlers); l;) {
		fdh = (Ecore_Fd_Handler *) l;

		l = l->next;
		if (fdh->delete_me) {
			if (fdh->references) {
				deleted_in_use++;
				continue;
			}

			fd_handlers = (Ecore_Fd_Handler *)
			    eina_inlist_remove(EINA_INLIST_GET
					       (fd_handlers),
					       EINA_INLIST_GET(fdh));
			ECORE_MAGIC_SET(fdh, ECORE_MAGIC_NONE);
			free(fdh);
		}
	}
	if (!deleted_in_use)
		fd_handlers_delete_me = 0;
}

#ifdef _WIN32
static void _ecore_main_win32_handlers_cleanup(void)
{
	Ecore_Win32_Handler *wh;
	Eina_Inlist *l;
	int deleted_in_use = 0;

	if (!win32_handlers_delete_me)
		return;
	for (l = EINA_INLIST_GET(win32_handlers); l;) {
		wh = (Ecore_Win32_Handler *) l;

		l = l->next;
		if (wh->delete_me) {
			if (wh->references) {
				deleted_in_use++;
				continue;
			}

			win32_handlers = (Ecore_Win32_Handler *)
			    eina_inlist_remove(EINA_INLIST_GET
					       (win32_handlers),
					       EINA_INLIST_GET(wh));
			ECORE_MAGIC_SET(wh, ECORE_MAGIC_NONE);
			free(wh);
		}
	}
	if (!deleted_in_use)
		win32_handlers_delete_me = 0;
}
#endif

static void _ecore_main_fd_handlers_call(void)
{
	if (!fd_handler_current) {
		/* regular main loop, start from head */
		fd_handler_current = fd_handlers;
	} else {
		/* recursive main loop, continue from where we were */
		fd_handler_current =
		    (Ecore_Fd_Handler *)
		    EINA_INLIST_GET(fd_handler_current)->next;
	}

	while (fd_handler_current) {
		Ecore_Fd_Handler *fdh = fd_handler_current;

		if (!fdh->delete_me) {
			if ((fdh->read_active) ||
			    (fdh->write_active) || (fdh->error_active)) {
				fdh->references++;
				if (!fdh->func(fdh->data, fdh)) {
					fdh->delete_me = 1;
					fd_handlers_delete_me = 1;
				}
				fdh->references--;

				fdh->read_active = 0;
				fdh->write_active = 0;
				fdh->error_active = 0;
			}
		}

		if (fd_handler_current)	/* may have changed in recursive main loops */
			fd_handler_current =
			    (Ecore_Fd_Handler *)
			    EINA_INLIST_GET(fd_handler_current)->next;
	}
}

static int _ecore_main_fd_handlers_buf_call(void)
{
	Ecore_Fd_Handler *fdh;
	int ret;

	ret = 0;
	EINA_INLIST_FOREACH(fd_handlers, fdh) {
		if (!fdh->delete_me) {
			if (fdh->buf_func) {
				fdh->references++;
				if (fdh->buf_func(fdh->buf_data, fdh)) {
					ret |= fdh->func(fdh->data, fdh);
					fdh->read_active = 1;
				}
				fdh->references--;
			}
		}
	}
	return ret;
}

#ifndef USE_G_MAIN_LOOP
static void _ecore_main_loop_iterate_internal(int once_only)
{
	double next_time = -1.0;
	int have_event = 0;
	int have_signal;

	in_main_loop++;
	/* expire any timers */
	while (_ecore_timer_call(_ecore_time_loop_time));
	_ecore_timer_cleanup();

	/* process signals into events .... */
	while (_ecore_signal_count_get())
		_ecore_signal_call();
	if (_ecore_event_exist()) {
		_ecore_idle_enterer_call();
		have_event = 1;
		_ecore_main_select(0.0);
		_ecore_time_loop_time = ecore_time_get();
		_ecore_timer_enable_new();
		goto process_events;
	}
	/* call idle enterers ... */
	if (!once_only)
		_ecore_idle_enterer_call();
	else {
		have_event = have_signal = 0;

		if (_ecore_main_select(0.0) > 0)
			have_event = 1;
		if (_ecore_signal_count_get() > 0)
			have_signal = 1;
		if (have_signal || have_event) {
			_ecore_time_loop_time = ecore_time_get();
			_ecore_timer_enable_new();
			goto process_events;
		}
	}

	/* if these calls caused any buffered events to appear - deal with them */
	_ecore_main_fd_handlers_buf_call();

	/* if there are any - jump to processing them */
	if (_ecore_event_exist()) {
		have_event = 1;
		_ecore_main_select(0.0);
		_ecore_time_loop_time = ecore_time_get();
		_ecore_timer_enable_new();
		goto process_events;
	}
	if (once_only) {
		_ecore_idle_enterer_call();
		in_main_loop--;
		_ecore_time_loop_time = ecore_time_get();
		_ecore_timer_enable_new();
		return;
	}

	if (_ecore_fps_debug) {
		t2 = ecore_time_get();
		if ((t1 > 0.0) && (t2 > 0.0))
			_ecore_fps_debug_runtime_add(t2 - t1);
	}
      start_loop:
	/* any timers re-added as a result of these are allowed to go */
	_ecore_timer_enable_new();
	if (do_quit) {
		_ecore_time_loop_time = ecore_time_get();
		in_main_loop--;
		_ecore_timer_enable_new();
		return;
	}
	if (!_ecore_event_exist()) {
		/* init flags */
		have_event = have_signal = 0;
		next_time = _ecore_timer_next_get();
		/* no timers */
		if (next_time < 0) {
			/* no idlers */
			if (!_ecore_idler_exist()) {
				if (_ecore_main_select(-1.0) > 0)
					have_event = 1;
			}
			/* idlers */
			else {
				for (;;) {
					if (!_ecore_idler_call())
						goto start_loop;
					if (_ecore_event_exist())
						break;
					if (_ecore_main_select(0.0) > 0)
						have_event = 1;
					if (_ecore_signal_count_get() > 0)
						have_signal = 1;
					if (have_event || have_signal)
						break;
					if (_ecore_timers_exists())
						goto start_loop;
					if (do_quit)
						break;
				}
			}
		}
		/* timers */
		else {
			/* no idlers */
			if (!_ecore_idler_exist()) {
				if (_ecore_main_select(next_time) > 0)
					have_event = 1;
			}
			/* idlers */
			else {
				for (;;) {
					if (!_ecore_idler_call())
						goto start_loop;
					if (_ecore_event_exist())
						break;
					if (_ecore_main_select(0.0) > 0)
						have_event = 1;
					if (_ecore_signal_count_get() > 0)
						have_signal = 1;
					if (have_event || have_signal)
						break;
					next_time =
					    _ecore_timer_next_get();
					if (next_time <= 0)
						break;
					if (do_quit)
						break;
				}
			}
		}
		_ecore_time_loop_time = ecore_time_get();
	}
	if (_ecore_fps_debug)
		t1 = ecore_time_get();
	/* we came out of our "wait state" so idle has exited */
	if (!once_only)
		_ecore_idle_exiter_call();
	/* call the fd handler per fd that became alive... */
	/* this should read or write any data to the monitored fd and then */
	/* post events onto the ecore event pipe if necessary */
      process_events:
	_ecore_main_fd_handlers_call();
	_ecore_main_fd_handlers_buf_call();
	/* process signals into events .... */
	while (_ecore_signal_count_get())
		_ecore_signal_call();
	/* handle events ... */
	_ecore_event_call();
	_ecore_main_fd_handlers_cleanup();

	if (once_only)
		_ecore_idle_enterer_call();
	in_main_loop--;
}
#endif

#ifdef _WIN32
static int
_ecore_main_win32_select(int nfds __UNUSED__, fd_set * readfds,
			 fd_set * writefds, fd_set * exceptfds,
			 struct timeval *tv)
{
	HANDLE objects[MAXIMUM_WAIT_OBJECTS];
	int sockets[MAXIMUM_WAIT_OBJECTS];
	Ecore_Fd_Handler *fdh;
	Ecore_Win32_Handler *wh;
	unsigned int objects_nbr = 0;
	unsigned int handles_nbr = 0;
	unsigned int events_nbr = 0;
	DWORD result;
	DWORD timeout;
	MSG msg;
	unsigned int i;
	int res;

	/* Create an event object per socket */
	EINA_INLIST_FOREACH(fd_handlers, fdh) {
		WSAEVENT event;
		long network_event;

		network_event = 0;
		if (FD_ISSET(fdh->fd, readfds))
			network_event |= FD_READ;
		if (FD_ISSET(fdh->fd, writefds))
			network_event |= FD_WRITE;
		if (FD_ISSET(fdh->fd, exceptfds))
			network_event |= FD_OOB;

		if (network_event) {
			event = WSACreateEvent();
			WSAEventSelect(fdh->fd, event, network_event);
			objects[objects_nbr] = event;
			sockets[events_nbr] = fdh->fd;
			events_nbr++;
			objects_nbr++;
		}
	}

	/* store the HANDLEs in the objects to wait for */
	EINA_INLIST_FOREACH(win32_handlers, wh) {
		objects[objects_nbr] = wh->h;
		handles_nbr++;
		objects_nbr++;
	}

	/* Empty the queue before waiting */
	while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	/* Wait for any message sent or posted to this queue */
	/* or for one of the passed handles be set to signaled. */
	if (!tv)
		timeout = INFINITE;
	else
		timeout =
		    (DWORD) ((tv->tv_sec * 1000.0) +
			     (tv->tv_usec / 1000.0));

	if (timeout == 0)
		return 0;

	result =
	    MsgWaitForMultipleObjects(objects_nbr,
				      (const HANDLE *) objects, EINA_FALSE,
				      timeout, QS_ALLINPUT);

	FD_ZERO(readfds);
	FD_ZERO(writefds);
	FD_ZERO(exceptfds);

	/* The result tells us the type of event we have. */
	if (result == WAIT_FAILED) {
		char *msg;

		msg = evil_last_error_get();
		ERR(" * %s\n", msg);
		free(msg);
		res = -1;
	} else if (result == WAIT_TIMEOUT) {
		/* ERR("time out\n"); */
		res = 0;
	} else if (result == (WAIT_OBJECT_0 + objects_nbr)) {
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}

		res = 0;
	} else if ((result >= 0) && (result < WAIT_OBJECT_0 + events_nbr)) {
		WSANETWORKEVENTS network_event;

		WSAEnumNetworkEvents(sockets[result], objects[result],
				     &network_event);

		if (network_event.lNetworkEvents & FD_READ)
			FD_SET(sockets[result], readfds);
		if (network_event.lNetworkEvents & FD_WRITE)
			FD_SET(sockets[result], writefds);
		if (network_event.lNetworkEvents & FD_OOB)
			FD_SET(sockets[result], exceptfds);

		res = 1;
	} else if ((result >= (WAIT_OBJECT_0 + events_nbr)) &&
		   (result < (WAIT_OBJECT_0 + objects_nbr))) {
		if (!win32_handler_current) {
			/* regular main loop, start from head */
			win32_handler_current = win32_handlers;
		} else {
			/* recursive main loop, continue from where we were */
			win32_handler_current =
			    (Ecore_Win32_Handler *)
			    EINA_INLIST_GET(win32_handler_current)->next;
		}

		while (win32_handler_current) {
			wh = win32_handler_current;

			if (objects[result - WAIT_OBJECT_0] == wh->h) {
				if (!wh->delete_me) {
					wh->references++;
					if (!wh->func(wh->data, wh)) {
						wh->delete_me = 1;
						win32_handlers_delete_me =
						    1;
					}
					wh->references--;
				}
			}
			if (win32_handler_current)	/* may have changed in recursive main loops */
				win32_handler_current =
				    (Ecore_Win32_Handler *)
				    EINA_INLIST_GET
				    (win32_handler_current)->next;
		}
		res = 1;
	} else {
		ERR("unknown result...\n");
		res = -1;
	}

	/* Remove event objects again */
	for (i = 0; i < events_nbr; i++)
		WSACloseEvent(objects[i]);

	return res;
}
#endif
