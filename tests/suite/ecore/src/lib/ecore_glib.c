#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include "Ecore.h"
#include "ecore_private.h"

#ifdef HAVE_GLIB
#include <glib.h>

static Eina_Bool _ecore_glib_active = EINA_FALSE;
static Ecore_Select_Function _ecore_glib_select_original;
static GCond *_ecore_glib_cond = NULL;
static GPollFD *_ecore_glib_fds = NULL;
static size_t _ecore_glib_fds_size = 0;
static const size_t ECORE_GLIB_FDS_INITIAL = 128;
static const size_t ECORE_GLIB_FDS_STEP = 8;
static const size_t ECORE_GLIB_FDS_MAX_FREE = 256;

static Eina_Bool _ecore_glib_fds_resize(size_t size)
{
	void *tmp = realloc(_ecore_glib_fds, sizeof(GPollFD) * size);

	if (!tmp) {
		ERR("Could not realloc from %zu to %zu buckets.",
		    _ecore_glib_fds_size, size);
		return EINA_FALSE;
	}

	_ecore_glib_fds = tmp;
	_ecore_glib_fds_size = size;
	return EINA_TRUE;
}

static int
_ecore_glib_context_query(GMainContext * ctx, int priority, int *p_timer)
{
	int reqfds;

	if (_ecore_glib_fds_size == 0) {
		if (!_ecore_glib_fds_resize(ECORE_GLIB_FDS_INITIAL))
			return -1;
	}

	while (1) {
		size_t size;

		reqfds = g_main_context_query
		    (ctx, priority, p_timer, _ecore_glib_fds,
		     _ecore_glib_fds_size);
		if (reqfds <= (int) _ecore_glib_fds_size)
			break;

		size =
		    (1 +
		     reqfds / ECORE_GLIB_FDS_STEP) * ECORE_GLIB_FDS_STEP;
		if (!_ecore_glib_fds_resize(size))
			return -1;
	}

	if (reqfds + ECORE_GLIB_FDS_MAX_FREE < _ecore_glib_fds_size) {
		size_t size;

		size =
		    (1 +
		     reqfds / ECORE_GLIB_FDS_MAX_FREE) *
		    ECORE_GLIB_FDS_MAX_FREE;
		_ecore_glib_fds_resize(size);
	}

	return reqfds;
}

static int
_ecore_glib_context_poll_from(const GPollFD * pfds, int count,
			      fd_set * rfds, fd_set * wfds, fd_set * efds)
{
	const GPollFD *itr = pfds, *itr_end = pfds + count;
	int glib_fds = -1;

	for (; itr < itr_end; itr++) {
		if (glib_fds < itr->fd)
			glib_fds = itr->fd;

		if (itr->events & G_IO_IN)
			FD_SET(itr->fd, rfds);
		if (itr->events & G_IO_OUT)
			FD_SET(itr->fd, wfds);
		if (itr->events & (G_IO_HUP | G_IO_ERR))
			FD_SET(itr->fd, efds);
	}

	return glib_fds + 1;
}

static int
_ecore_glib_context_poll_to(GPollFD * pfds, int count, const fd_set * rfds,
			    const fd_set * wfds, const fd_set * efds,
			    int ready)
{
	GPollFD *itr = pfds, *itr_end = pfds + count;

	for (; itr < itr_end && ready > 0; itr++) {
		itr->revents = 0;
		if (FD_ISSET(itr->fd, rfds)) {
			itr->revents |= G_IO_IN;
			ready--;
		}
		if (FD_ISSET(itr->fd, wfds)) {
			itr->revents |= G_IO_OUT;
			ready--;
		}
		if (FD_ISSET(itr->fd, efds)) {
			itr->revents |= G_IO_ERR;
			ready--;
		}
	}
	return ready;
}

static int
_ecore_glib_select__locked(GMainContext * ctx, int ecore_fds,
			   fd_set * rfds, fd_set * wfds, fd_set * efds,
			   struct timeval *ecore_timeout)
{
	int priority, maxfds, glib_fds, reqfds, reqtimeout, ret;
	struct timeval *timeout, glib_timeout;

	g_main_context_prepare(ctx, &priority);
	reqfds = _ecore_glib_context_query(ctx, priority, &reqtimeout);
	if (reqfds < 0)
		goto error;

	glib_fds = _ecore_glib_context_poll_from
	    (_ecore_glib_fds, reqfds, rfds, wfds, efds);

	if (reqtimeout == -1)
		timeout = ecore_timeout;
	else {
		glib_timeout.tv_sec = reqtimeout / 1000;
		glib_timeout.tv_usec = (reqtimeout % 1000) * 1000;

		if (!ecore_timeout
		    || timercmp(ecore_timeout, &glib_timeout, >))
			timeout = &glib_timeout;
		else
			timeout = ecore_timeout;
	}

	maxfds = (ecore_fds >= glib_fds) ? ecore_fds : glib_fds;
	ret =
	    _ecore_glib_select_original(maxfds, rfds, wfds, efds, timeout);

	ret = _ecore_glib_context_poll_to
	    (_ecore_glib_fds, reqfds, rfds, wfds, efds, ret);

	if (g_main_context_check(ctx, priority, _ecore_glib_fds, reqfds))
		g_main_context_dispatch(ctx);

	return ret;

      error:
	return _ecore_glib_select_original
	    (ecore_fds, rfds, wfds, efds, ecore_timeout);
}

static int
_ecore_glib_select(int ecore_fds, fd_set * rfds, fd_set * wfds,
		   fd_set * efds, struct timeval *ecore_timeout)
{
	GStaticMutex lock = G_STATIC_MUTEX_INIT;
	GMutex *mutex = g_static_mutex_get_mutex(&lock);
	GMainContext *ctx = g_main_context_default();
	int ret;

	if (g_main_context_acquire(ctx))
		g_mutex_lock(mutex);
	else {
		if (!_ecore_glib_cond)
			_ecore_glib_cond = g_cond_new();

		while (!g_main_context_wait(ctx, _ecore_glib_cond, mutex))
			g_thread_yield();
	}

	ret = _ecore_glib_select__locked
	    (ctx, ecore_fds, rfds, wfds, efds, ecore_timeout);

	g_mutex_unlock(mutex);
	g_main_context_release(ctx);

	return ret;
}
#endif

void _ecore_glib_init(void)
{
}

void _ecore_glib_shutdown(void)
{
#ifdef HAVE_GLIB
	if (!_ecore_glib_active)
		return;
	_ecore_glib_active = EINA_FALSE;

	if (ecore_main_loop_select_func_get() == _ecore_glib_select)
		ecore_main_loop_select_func_set
		    (_ecore_glib_select_original);

	if (_ecore_glib_fds) {
		free(_ecore_glib_fds);
		_ecore_glib_fds = NULL;
	}
	_ecore_glib_fds_size = 0;

	if (_ecore_glib_cond) {
		g_cond_free(_ecore_glib_cond);
		_ecore_glib_cond = NULL;
	}
#endif
}

/**
 * Request ecore to integrate GLib's main loop.
 *
 * This will add a small overhead during every main loop interaction
 * by checking glib's default main context (used by its main loop). If
 * it have events to be checked (timers, file descriptors or idlers),
 * then these will be polled alongside with Ecore's own events, then
 * dispatched before Ecore's. This is done by calling
 * ecore_main_loop_select_func_set().
 *
 * This will cooperate with previously set
 * ecore_main_loop_select_func_set() by calling the old
 * function. Similarly, if you want to override
 * ecore_main_loop_select_func_set() after main loop is integrated,
 * call the new select function set by this call (get it by calling
 * ecore_main_loop_select_func_get() right after
 * ecore_main_loop_glib_integrate()).
 *
 * This is useful to use GMainLoop libraries, like GTK, GUPnP,
 * LibSoup, GConf and more. Adobe Flash plugin and other plugins
 * systems depend on this as well.
 *
 * Once initialized/integrated, it will be valid until Ecore is
 * completely shut down.
 *
 * @note this is only available if Ecore was compiled with GLib support.
 *
 * @return @c EINA_TRUE on success of @c EINA_FALSE if it failed,
 *         likely no GLib support in Ecore.
 */
EAPI Eina_Bool ecore_main_loop_glib_integrate(void)
{
#ifdef HAVE_GLIB
	void *func;

	if (_ecore_glib_active)
		return EINA_TRUE;
	func = ecore_main_loop_select_func_get();
	if (func == _ecore_glib_select)
		return EINA_TRUE;
	_ecore_glib_select_original = func;
	ecore_main_loop_select_func_set(_ecore_glib_select);
	_ecore_glib_active = EINA_TRUE;
	return EINA_TRUE;
#else
	fputs("ERROR: no glib support in ecore.\n", stderr);
	return EINA_FALSE;
#endif
}

Eina_Bool _ecore_glib_always_integrate = 1;

/**
 * Disable always integrating glib
 * 
 * If ecore is compiled with --enable-glib-integration-always (to always
 * call ecore_main_loop_glib_integrate() when ecore_init() is called), then
 * calling this before calling ecore_init() will disable the integration.
 * This is for apps that explicitly do not want this to happen for whatever
 * reasons they may have.
 */
EAPI void ecore_main_loop_glib_always_integrate_disable(void)
{
	_ecore_glib_always_integrate = 0;
}
