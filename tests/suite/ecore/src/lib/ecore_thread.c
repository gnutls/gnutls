#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#ifdef EFL_HAVE_PTHREAD
#include <pthread.h>
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#endif
#endif

#include "Ecore.h"
#include "ecore_private.h"

typedef struct _Ecore_Pthread_Worker Ecore_Pthread_Worker;
typedef struct _Ecore_Pthread Ecore_Pthread;
typedef struct _Ecore_Thread_Data Ecore_Thread_Data;

struct _Ecore_Thread_Data {
	void *data;
	Eina_Free_Cb cb;
};

struct _Ecore_Pthread_Worker {
	union {
		struct {
			Ecore_Cb func_blocking;
		} short_run;
		struct {
			Ecore_Thread_Heavy_Cb func_heavy;
			Ecore_Thread_Notify_Cb func_notify;
			Ecore_Pipe *notify;
		} feedback_run;
	} u;

	Ecore_Cb func_cancel;
	Ecore_Cb func_end;
#ifdef EFL_HAVE_PTHREAD
	pthread_t self;
	Eina_Hash *hash;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
#endif

	const void *data;

	Eina_Bool cancel:1;
	Eina_Bool feedback_run:1;
};

#ifdef EFL_HAVE_PTHREAD
typedef struct _Ecore_Pthread_Data Ecore_Pthread_Data;

struct _Ecore_Pthread_Data {
	Ecore_Pipe *p;
	void *data;
	pthread_t thread;
};
#endif

static int _ecore_thread_count_max = 0;
static int ECORE_THREAD_PIPE_DEL = 0;

#ifdef EFL_HAVE_PTHREAD
static int _ecore_thread_count = 0;

static Eina_List *_ecore_active_job_threads = NULL;
static Eina_List *_ecore_pending_job_threads = NULL;
static Eina_List *_ecore_pending_job_threads_feedback = NULL;
static Ecore_Event_Handler *del_handler = NULL;
static pthread_mutex_t _ecore_pending_job_threads_mutex =
    PTHREAD_MUTEX_INITIALIZER;

static Eina_Hash *_ecore_thread_global_hash = NULL;
static pthread_rwlock_t _ecore_thread_global_hash_lock =
    PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t _ecore_thread_global_hash_mutex =
    PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _ecore_thread_global_hash_cond =
    PTHREAD_COND_INITIALIZER;
static pthread_t main_loop_thread;
static Eina_Bool have_main_loop_thread = 0;
static void _ecore_thread_data_free(void *data)
{
	Ecore_Thread_Data *d = data;

	if (d->cb)
		d->cb(d->data);
	free(d);
}

static void _ecore_thread_pipe_free(void *data __UNUSED__, void *event)
{
	Ecore_Pipe *p = event;

	ecore_pipe_del(p);
}

static Eina_Bool
_ecore_thread_pipe_del(void *data __UNUSED__, int type __UNUSED__,
		       void *event __UNUSED__)
{
	/* This is a hack to delay pipe destruction until we are out of its internal loop. */
	return ECORE_CALLBACK_CANCEL;
}

static void _ecore_thread_end(Ecore_Pthread_Data * pth)
{
	Ecore_Pipe *p;

	if (pthread_join(pth->thread, (void **) &p) != 0)
		return;

	_ecore_active_job_threads =
	    eina_list_remove(_ecore_active_job_threads, pth);

	ecore_event_add(ECORE_THREAD_PIPE_DEL, pth->p,
			_ecore_thread_pipe_free, NULL);
	free(pth);
}

static void
_ecore_thread_handler(void *data __UNUSED__, void *buffer,
		      unsigned int nbyte)
{
	Ecore_Pthread_Worker *work;

	if (nbyte != sizeof(Ecore_Pthread_Worker *))
		return;

	work = *(Ecore_Pthread_Worker **) buffer;

	if (work->cancel) {
		if (work->func_cancel)
			work->func_cancel((void *) work->data);
	} else {
		if (work->func_end)
			work->func_end((void *) work->data);
	}

	if (work->feedback_run)
		ecore_pipe_del(work->u.feedback_run.notify);
	pthread_cond_destroy(&work->cond);
	pthread_mutex_destroy(&work->mutex);
	if (work->hash)
		eina_hash_free(work->hash);
	free(work);
}

static void
_ecore_notify_handler(void *data, void *buffer, unsigned int nbyte)
{
	Ecore_Pthread_Worker *work = data;
	void *user_data;

	if (nbyte != sizeof(Ecore_Pthread_Worker *))
		return;

	user_data = *(void **) buffer;

	if (work->u.feedback_run.func_notify)
		work->u.feedback_run.func_notify((Ecore_Thread *) work,
						 user_data,
						 (void *) work->data);
}

static void _ecore_short_job(Ecore_Pipe * end_pipe)
{
	Ecore_Pthread_Worker *work;

	while (_ecore_pending_job_threads) {
		pthread_mutex_lock(&_ecore_pending_job_threads_mutex);

		if (!_ecore_pending_job_threads) {
			pthread_mutex_unlock
			    (&_ecore_pending_job_threads_mutex);
			break;
		}

		work = eina_list_data_get(_ecore_pending_job_threads);
		_ecore_pending_job_threads =
		    eina_list_remove_list(_ecore_pending_job_threads,
					  _ecore_pending_job_threads);

		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

		if (!work->cancel)
			work->u.short_run.func_blocking((void *) work->
							data);

		ecore_pipe_write(end_pipe, &work,
				 sizeof(Ecore_Pthread_Worker *));
	}
}

static void _ecore_feedback_job(Ecore_Pipe * end_pipe, pthread_t thread)
{
	Ecore_Pthread_Worker *work;

	while (_ecore_pending_job_threads_feedback) {
		pthread_mutex_lock(&_ecore_pending_job_threads_mutex);

		if (!_ecore_pending_job_threads_feedback) {
			pthread_mutex_unlock
			    (&_ecore_pending_job_threads_mutex);
			break;
		}

		work =
		    eina_list_data_get
		    (_ecore_pending_job_threads_feedback);
		_ecore_pending_job_threads_feedback =
		    eina_list_remove_list
		    (_ecore_pending_job_threads_feedback,
		     _ecore_pending_job_threads_feedback);

		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

		work->self = thread;
		if (!work->cancel)
			work->u.feedback_run.
			    func_heavy((Ecore_Thread *) work,
				       (void *) work->data);

		ecore_pipe_write(end_pipe, &work,
				 sizeof(Ecore_Pthread_Worker *));
	}
}

static void *_ecore_direct_worker(Ecore_Pthread_Worker * work)
{
	Ecore_Pthread_Data *pth;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	eina_sched_prio_drop();

	pth = malloc(sizeof(Ecore_Pthread_Data));
	if (!pth)
		return NULL;

	pth->p = ecore_pipe_add(_ecore_thread_handler, NULL);
	if (!pth->p) {
		free(pth);
		return NULL;
	}
	pth->thread = pthread_self();

	work->self = pth->thread;
	work->u.feedback_run.func_heavy((Ecore_Thread *) work,
					(void *) work->data);

	ecore_pipe_write(pth->p, &work, sizeof(Ecore_Pthread_Worker *));

	work = malloc(sizeof(Ecore_Pthread_Worker));
	if (!work) {
		ecore_pipe_del(pth->p);
		free(pth);
		return NULL;
	}

	work->data = pth;
	work->u.short_run.func_blocking = NULL;
	work->func_end = (void *) _ecore_thread_end;
	work->func_cancel = NULL;
	work->cancel = EINA_FALSE;
	work->feedback_run = EINA_FALSE;
	work->hash = NULL;
	pthread_cond_init(&work->cond, NULL);
	pthread_mutex_init(&work->mutex, NULL);

	ecore_pipe_write(pth->p, &work, sizeof(Ecore_Pthread_Worker *));

	return pth->p;
}

static void *_ecore_thread_worker(Ecore_Pthread_Data * pth)
{
	Ecore_Pthread_Worker *work;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	eina_sched_prio_drop();

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	_ecore_thread_count++;
	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

      on_error:
	if (_ecore_pending_job_threads)
		_ecore_short_job(pth->p);
	if (_ecore_pending_job_threads_feedback)
		_ecore_feedback_job(pth->p, pth->thread);

	/* FIXME: Check if there is feedback running task todo, and switch to feedback run handler. */

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	if (_ecore_pending_job_threads) {
		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
		goto on_error;
	}
	if (_ecore_pending_job_threads_feedback) {
		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
		goto on_error;
	}

	_ecore_thread_count--;

	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

	work = malloc(sizeof(Ecore_Pthread_Worker));
	if (!work)
		return NULL;

	work->data = pth;
	work->u.short_run.func_blocking = NULL;
	work->func_end = (void *) _ecore_thread_end;
	work->func_cancel = NULL;
	work->cancel = EINA_FALSE;
	work->feedback_run = EINA_FALSE;
	work->hash = NULL;
	pthread_cond_init(&work->cond, NULL);
	pthread_mutex_init(&work->mutex, NULL);

	ecore_pipe_write(pth->p, &work, sizeof(Ecore_Pthread_Worker *));

	return pth->p;
}

#endif

void _ecore_thread_init(void)
{
	_ecore_thread_count_max = eina_cpu_count();
	if (_ecore_thread_count_max <= 0)
		_ecore_thread_count_max = 1;

	ECORE_THREAD_PIPE_DEL = ecore_event_type_new();
#ifdef EFL_HAVE_PTHREAD
	del_handler =
	    ecore_event_handler_add(ECORE_THREAD_PIPE_DEL,
				    _ecore_thread_pipe_del, NULL);
	main_loop_thread = pthread_self();
	have_main_loop_thread = 1;
#endif
}

void _ecore_thread_shutdown(void)
{
	/* FIXME: If function are still running in the background, should we kill them ? */
#ifdef EFL_HAVE_PTHREAD
	Ecore_Pthread_Worker *work;
	Ecore_Pthread_Data *pth;

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);

	EINA_LIST_FREE(_ecore_pending_job_threads, work) {
		if (work->func_cancel)
			work->func_cancel((void *) work->data);
		free(work);
	}

	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

	EINA_LIST_FREE(_ecore_active_job_threads, pth) {
		Ecore_Pipe *p;

		pthread_cancel(pth->thread);
		pthread_join(pth->thread, (void **) &p);

		ecore_pipe_del(pth->p);
	}
	if (_ecore_thread_global_hash)
		eina_hash_free(_ecore_thread_global_hash);
	ecore_event_handler_del(del_handler);
	have_main_loop_thread = 0;
	del_handler = NULL;
#endif
}

/**
 * @addtogroup Ecore_Thread Ecore Thread Functions
 * These functions allow for ecore-managed threads which integrate with ecore's main loop.
 * @{
 */

/**
 * @brief Run some blocking code in a parallel thread to avoid locking the main loop.
 * @param func_blocking The function that should run in another thread.
 * @param func_end The function that will be called in the main loop if the thread terminate correctly.
 * @param func_cancel The function that will be called in the main loop if the thread is cancelled.
 * @param data User context data to pass to all callback.
 * @return A reference to the newly created thread instance, or NULL if it failed.
 *
 * ecore_thread_run provide a facility for easily managing blocking task in a
 * parallel thread. You should provide three function. The first one, func_blocking,
 * that will do the blocking work in another thread (so you should not use the
 * EFL in it except Eina if you are careful). The second one, func_end,
 * that will be called in Ecore main loop when func_blocking is done. So you
 * can use all the EFL inside this function. The last one, func_cancel, will
 * be called in the main loop if the thread is cancelled or could not run at all.
 *
 * Be aware, that you can't make assumption on the result order of func_end
 * after many call to ecore_thread_run, as we start as much thread as the
 * host CPU can handle.
 */
EAPI Ecore_Thread *ecore_thread_run(Ecore_Cb func_blocking,
				    Ecore_Cb func_end,
				    Ecore_Cb func_cancel, const void *data)
{
#ifdef EFL_HAVE_PTHREAD
	Ecore_Pthread_Worker *work;
	Ecore_Pthread_Data *pth = NULL;

	if (!func_blocking)
		return NULL;

	work = malloc(sizeof(Ecore_Pthread_Worker));
	if (!work) {
		func_cancel((void *) data);
		return NULL;
	}

	work->u.short_run.func_blocking = func_blocking;
	work->hash = NULL;
	pthread_cond_init(&work->cond, NULL);
	pthread_mutex_init(&work->mutex, NULL);
	work->func_end = func_end;
	work->func_cancel = func_cancel;
	work->cancel = EINA_FALSE;
	work->feedback_run = EINA_FALSE;
	work->data = data;

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	_ecore_pending_job_threads =
	    eina_list_append(_ecore_pending_job_threads, work);

	if (_ecore_thread_count == _ecore_thread_count_max) {
		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
		return (Ecore_Thread *) work;
	}

	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

	/* One more thread could be created. */
	pth = malloc(sizeof(Ecore_Pthread_Data));
	if (!pth)
		goto on_error;

	pth->p = ecore_pipe_add(_ecore_thread_handler, NULL);
	if (!pth->p)
		goto on_error;

	if (pthread_create
	    (&pth->thread, NULL, (void *) _ecore_thread_worker, pth) == 0)
		return (Ecore_Thread *) work;

      on_error:
	if (pth) {
		if (pth->p)
			ecore_pipe_del(pth->p);
		free(pth);
	}

	if (_ecore_thread_count == 0) {
		if (work->func_cancel)
			work->func_cancel((void *) work->data);
		free(work);
		work = NULL;
	}
	return (Ecore_Thread *) work;
#else
	/*
	   If no thread and as we don't want to break app that rely on this
	   facility, we will lock the interface until we are done.
	 */
	func_blocking((void *) data);
	func_end((void *) data);

	return NULL;
#endif
}

/**
 * @brief Cancel a running thread.
 * @param thread The thread to cancel.
 * @return Will return EINA_TRUE if the thread has been cancelled,
 *         EINA_FALSE if it is pending.
 *
 * ecore_thread_cancel give the possibility to cancel a task still running. It
 * will return EINA_FALSE, if the destruction is delayed or EINA_TRUE if it is
 * cancelled after this call.
 *
 * You should use this function only in the main loop.
 *
 * func_end, func_cancel will destroy the handler, so don't use it after.
 * And if ecore_thread_cancel return EINA_TRUE, you should not use Ecore_Thread also.
 */
EAPI Eina_Bool ecore_thread_cancel(Ecore_Thread * thread)
{
#ifdef EFL_HAVE_PTHREAD
	Ecore_Pthread_Worker *work = (Ecore_Pthread_Worker *) thread;
	Eina_List *l;

	if (!work)
		return EINA_TRUE;

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);

	if ((have_main_loop_thread) &&
	    (pthread_equal(main_loop_thread, pthread_self()))) {
		EINA_LIST_FOREACH(_ecore_pending_job_threads, l, work) {
			if ((void *) work == (void *) thread) {
				_ecore_pending_job_threads =
				    eina_list_remove_list
				    (_ecore_pending_job_threads, l);

				pthread_mutex_unlock
				    (&_ecore_pending_job_threads_mutex);

				if (work->func_cancel)
					work->func_cancel((void *) work->
							  data);
				free(work);

				return EINA_TRUE;
			}
		}
	}

	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

	/* Delay the destruction */
	((Ecore_Pthread_Worker *) thread)->cancel = EINA_TRUE;
	return EINA_FALSE;
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Tell if a thread was canceled or not.
 * @param thread The thread to test.
 * @return EINA_TRUE if the thread is cancelled,
 *         EINA_FALSE if it is not.
 *
 * You can use this function in main loop and in the thread.
 */
EAPI Eina_Bool ecore_thread_check(Ecore_Thread * thread)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;

	if (!worker)
		return EINA_TRUE;
	return worker->cancel;
}

/**
 * @brief Run some heavy code in a parallel thread to avoid locking the main loop.
 * @param func_heavy The function that should run in another thread.
 * @param func_notify The function that will receive the data send by func_heavy in the main loop.
 * @param func_end The function that will be called in the main loop if the thread terminate correctly.
 * @param func_cancel The function that will be called in the main loop if the thread is cancelled.
 * @param data User context data to pass to all callback.
 * @param try_no_queue If you wan't to run outside of the thread pool.
 * @return A reference to the newly created thread instance, or NULL if it failed.
 *
 * ecore_thread_feedback_run provide a facility for easily managing heavy task in a
 * parallel thread. You should provide four functions. The first one, func_heavy,
 * that will do the heavy work in another thread (so you should not use the
 * EFL in it except Eina and Eet if you are careful). The second one, func_notify,
 * will receive the data send from the thread function (func_heavy) by ecore_thread_notify
 * in the main loop (and so, can use all the EFL). Tje third, func_end,
 * that will be called in Ecore main loop when func_heavy is done. So you
 * can use all the EFL inside this function. The last one, func_cancel, will
 * be called in the main loop also, if the thread is cancelled or could not run at all.
 *
 * Be aware, that you can't make assumption on the result order of func_end
 * after many call to ecore_feedback_run, as we start as much thread as the
 * host CPU can handle.
 *
 * If you set try_no_queue, it will try to run outside of the thread pool, this can bring
 * the CPU down, so be careful with that. Of course if it can't start a new thread, it will
 * try to use one from the pool.
 */
EAPI Ecore_Thread *ecore_thread_feedback_run(Ecore_Thread_Heavy_Cb
					     func_heavy,
					     Ecore_Thread_Notify_Cb
					     func_notify,
					     Ecore_Cb func_end,
					     Ecore_Cb func_cancel,
					     const void *data,
					     Eina_Bool try_no_queue)
{

#ifdef EFL_HAVE_PTHREAD
	Ecore_Pthread_Worker *worker;
	Ecore_Pthread_Data *pth = NULL;

	if (!func_heavy)
		return NULL;

	worker = malloc(sizeof(Ecore_Pthread_Worker));
	if (!worker)
		goto on_error;

	worker->u.feedback_run.func_heavy = func_heavy;
	worker->u.feedback_run.func_notify = func_notify;
	worker->hash = NULL;
	pthread_cond_init(&worker->cond, NULL);
	pthread_mutex_init(&worker->mutex, NULL);
	worker->func_cancel = func_cancel;
	worker->func_end = func_end;
	worker->data = data;
	worker->cancel = EINA_FALSE;
	worker->feedback_run = EINA_TRUE;

	worker->u.feedback_run.notify =
	    ecore_pipe_add(_ecore_notify_handler, worker);

	if (!try_no_queue) {
		pthread_t t;

		if (pthread_create
		    (&t, NULL, (void *) _ecore_direct_worker, worker) == 0)
			return (Ecore_Thread *) worker;
	}

	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	_ecore_pending_job_threads_feedback =
	    eina_list_append(_ecore_pending_job_threads_feedback, worker);

	if (_ecore_thread_count == _ecore_thread_count_max) {
		pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
		return (Ecore_Thread *) worker;
	}

	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);

	/* One more thread could be created. */
	pth = malloc(sizeof(Ecore_Pthread_Data));
	if (!pth)
		goto on_error;

	pth->p = ecore_pipe_add(_ecore_thread_handler, NULL);
	if (!pth->p)
		goto on_error;

	if (pthread_create
	    (&pth->thread, NULL, (void *) _ecore_thread_worker, pth) == 0)
		return (Ecore_Thread *) worker;

      on_error:
	if (pth) {
		if (pth->p)
			ecore_pipe_del(pth->p);
		free(pth);
	}

	if (_ecore_thread_count == 0) {
		if (func_cancel)
			func_cancel((void *) data);

		if (worker) {
			ecore_pipe_del(worker->u.feedback_run.notify);
			free(worker);
			worker = NULL;
		}
	}

	return (Ecore_Thread *) worker;
#else
	Ecore_Pthread_Worker worker;

	(void) try_no_queue;

	/*
	   If no thread and as we don't want to break app that rely on this
	   facility, we will lock the interface until we are done.
	 */
	worker.u.feedback_run.func_heavy = func_heavy;
	worker.u.feedback_run.func_notify = func_notify;
	worker.u.feedback_run.notify = NULL;
	worker.func_cancel = func_cancel;
	worker.func_end = func_end;
	worker.data = data;
	worker.cancel = EINA_FALSE;
	worker.feedback_run = EINA_TRUE;

	func_heavy((Ecore_Thread *) & worker, (void *) data);

	if (worker.cancel)
		func_cancel((void *) data);
	else
		func_end((void *) data);

	return NULL;
#endif
}

/**
 * @brief Send data to main loop from worker thread.
 * @param thread The current Ecore_Thread context to send data from
 * @param data Data to be transmitted to the main loop
 * @return EINA_TRUE if data was successfully send to main loop,
 *         EINA_FALSE if anything goes wrong.
 *
 * After a succesfull call, the data should be considered owned
 * by the main loop.
 *
 * You should use this function only in the func_heavy call.
 */
EAPI Eina_Bool
ecore_thread_feedback(Ecore_Thread * thread, const void *data)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;

	if (!worker)
		return EINA_FALSE;
	if (!worker->feedback_run)
		return EINA_FALSE;

#ifdef EFL_HAVE_PTHREAD
	if (!pthread_equal(worker->self, pthread_self()))
		return EINA_FALSE;

	ecore_pipe_write(worker->u.feedback_run.notify, &data,
			 sizeof(void *));

	return EINA_TRUE;
#else
	worker->u.feedback_run.func_notify(thread, (void *) data,
					   (void *) worker->data);

	return EINA_TRUE;
#endif
}

/**
 * @brief Get number of active thread jobs
 * @return Number of active threads running jobs
 * This returns the number of threads currently running jobs through the
 * ecore_thread api.
 */
EAPI int ecore_thread_active_get(void)
{
#ifdef EFL_HAVE_PTHREAD
	return _ecore_thread_count;
#else
	return 0;
#endif
}

/**
 * @brief Get number of pending (short) thread jobs
 * @return Number of pending threads running "short" jobs
 * This returns the number of threads currently running jobs through the
 * ecore_thread_run api call.
 */
EAPI int ecore_thread_pending_get(void)
{
	int ret;
#ifdef EFL_HAVE_PTHREAD
	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	ret = eina_list_count(_ecore_pending_job_threads);
	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
	return ret;
#else
	return 0;
#endif
}

/**
 * @brief Get number of pending feedback thread jobs
 * @return Number of pending threads running "feedback" jobs
 * This returns the number of threads currently running jobs through the
 * ecore_thread_feedback_run api call.
 */
EAPI int ecore_thread_pending_feedback_get(void)
{
	int ret;
#ifdef EFL_HAVE_PTHREAD
	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	ret = eina_list_count(_ecore_pending_job_threads_feedback);
	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
	return ret;
#else
	return 0;
#endif
}

/**
 * @brief Get number of pending thread jobs
 * @return Number of pending threads running jobs
 * This returns the number of threads currently running jobs through the
 * ecore_thread_run and ecore_thread_feedback_run api calls combined.
 */
EAPI int ecore_thread_pending_total_get(void)
{
	int ret;
#ifdef EFL_HAVE_PTHREAD
	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	ret =
	    eina_list_count(_ecore_pending_job_threads) +
	    eina_list_count(_ecore_pending_job_threads_feedback);
	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
	return ret;
#else
	return 0;
#endif
}

/**
 * @brief Get the max number of threads that can run simultaneously
 * @return Max number of threads ecore will run
 * This returns the total number of threads that ecore will attempt to run
 * simultaneously.
 */
EAPI int ecore_thread_max_get(void)
{
	return _ecore_thread_count_max;
}

/**
 * @brief Set the max number of threads that can run simultaneously
 * @param num The new maximum
 * This sets the maximum number of threads that ecore will try to run
 * simultaneously.  This number cannot be < 1 or >= 2x the number of active cpus.
 */
EAPI void ecore_thread_max_set(int num)
{
	if (num < 1)
		return;
	/* avoid doing something hilarious by blocking dumb users */
	if (num >= (2 * eina_cpu_count()))
		return;

	_ecore_thread_count_max = num;
}

/**
 * @brief Reset the max number of threads that can run simultaneously
 * This resets the maximum number of threads that ecore will try to run
 * simultaneously to the number of active cpus.
 */
EAPI void ecore_thread_max_reset(void)
{
	_ecore_thread_count_max = eina_cpu_count();
}

/**
 * @brief Get the number of threads which are available to be used
 * @return The number of available threads
 * This returns the number of threads slots that ecore has currently available.
 * Assuming that you haven't changed the max number of threads with @ref ecore_thread_max_set
 * this should be equal to (num_cpus - (active_running + active_feedback_running))
 */
EAPI int ecore_thread_available_get(void)
{
	int ret;
#ifdef EFL_HAVE_PTHREAD
	pthread_mutex_lock(&_ecore_pending_job_threads_mutex);
	ret = _ecore_thread_count_max - _ecore_thread_count;
	pthread_mutex_unlock(&_ecore_pending_job_threads_mutex);
	return ret;
#else
	return 0;
#endif
}

/**
 * @brief Add data to the thread for subsequent use
 * @param thread The thread context to add to
 * @param key The name string to add the data with
 * @param value The data to add
 * @param cb The callback to free the data with
 * @param direct If true, this will not copy the key string (like eina_hash_direct_add)
 * @return EINA_TRUE on success, EINA_FALSE on failure
 * This adds data to the thread context, allowing the thread
 * to retrieve and use it without complicated mutexing.  This function can only be called by a
 * *_run thread INSIDE the thread and will return EINA_FALSE in any case but success.
 * All data added to the thread will be freed with its associated callback (if present)
 * upon thread termination.  If no callback is specified, it is expected that the user will free the
 * data, but this is most likely not what you want.
 */
EAPI Eina_Bool
ecore_thread_local_data_add(Ecore_Thread * thread, const char *key,
			    void *value, Eina_Free_Cb cb, Eina_Bool direct)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;
	Ecore_Thread_Data *d;
	Eina_Bool ret;

	if ((!thread) || (!key) || (!value))
		return EINA_FALSE;
#ifdef EFL_HAVE_PTHREAD
	if (!pthread_equal(worker->self, pthread_self()))
		return EINA_FALSE;

	if (!worker->hash)
		worker->hash =
		    eina_hash_string_small_new(_ecore_thread_data_free);

	if (!worker->hash)
		return EINA_FALSE;

	if (!(d = malloc(sizeof(Ecore_Thread_Data))))
		return EINA_FALSE;

	d->data = value;
	d->cb = cb;

	if (direct)
		ret = eina_hash_direct_add(worker->hash, key, d);
	else
		ret = eina_hash_add(worker->hash, key, d);
	pthread_cond_broadcast(&worker->cond);
	return ret;
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Modify data in the thread, or add if not found
 * @param thread The thread context
 * @param key The name string to add the data with
 * @param value The data to add
 * @param cb The callback to free the data with
 * @return The old data associated with @p key on success if modified, NULL if added
 * This adds/modifies data in the thread context, adding only if modify fails.
 * This function can only be called by a *_run thread INSIDE the thread.
 * All data added to the thread pool will be freed with its associated callback (if present)
 * upon thread termination.  If no callback is specified, it is expected that the user will free the
 * data, but this is most likely not what you want.
 */
EAPI void *ecore_thread_local_data_set(Ecore_Thread * thread,
				       const char *key, void *value,
				       Eina_Free_Cb cb)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;
	Ecore_Thread_Data *d, *r;
	void *ret;
	if ((!thread) || (!key) || (!value))
		return NULL;
#ifdef EFL_HAVE_PTHREAD
	if (!pthread_equal(worker->self, pthread_self()))
		return NULL;

	if (!worker->hash)
		worker->hash =
		    eina_hash_string_small_new(_ecore_thread_data_free);

	if (!worker->hash)
		return NULL;

	if (!(d = malloc(sizeof(Ecore_Thread_Data))))
		return NULL;

	d->data = value;
	d->cb = cb;

	r = eina_hash_set(worker->hash, key, d);
	pthread_cond_broadcast(&worker->cond);
	ret = r->data;
	free(r);
	return ret;
#else
	return NULL;
#endif
}

/**
 * @brief Find data in the thread's data
 * @param thread The thread context
 * @param key The name string the data is associated with
 * @return The value, or NULL on error
 * This finds data in the thread context that has been previously added with @ref ecore_thread_local_data_add
 * This function can only be called by a *_run thread INSIDE the thread, and will return NULL
 * in any case but success.
 */

EAPI void *ecore_thread_local_data_find(Ecore_Thread * thread,
					const char *key)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;
	Ecore_Thread_Data *d;

	if ((!thread) || (!key))
		return NULL;
#ifdef EFL_HAVE_PTHREAD
	if (!pthread_equal(worker->self, pthread_self()))
		return NULL;

	if (!worker->hash)
		return NULL;

	d = eina_hash_find(worker->hash, key);
	return d->data;
#else
	return NULL;
#endif
}

/**
 * @brief Delete data from the thread's data
 * @param thread The thread context
 * @param key The name string the data is associated with
 * @return EINA_TRUE on success, EINA_FALSE on failure
 * This deletes the data pointer from the thread context which was previously added with @ref ecore_thread_local_data_add
 * This function can only be called by a *_run thread INSIDE the thread, and will return EINA_FALSE
 * in any case but success.  Note that this WILL free the data if a callback was specified.
 */
EAPI Eina_Bool
ecore_thread_local_data_del(Ecore_Thread * thread, const char *key)
{
	Ecore_Pthread_Worker *worker = (Ecore_Pthread_Worker *) thread;
	Ecore_Thread_Data *d;
	if ((!thread) || (!key))
		return EINA_FALSE;
#ifdef EFL_HAVE_PTHREAD
	if (!pthread_equal(worker->self, pthread_self()))
		return EINA_FALSE;

	if (!worker->hash)
		return EINA_FALSE;
	if ((d = eina_hash_find(worker->hash, key)))
		_ecore_thread_data_free(d);
	return eina_hash_del_by_key(worker->hash, key);
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Add data to the global data
 * @param key The name string to add the data with
 * @param value The data to add
 * @param cb The optional callback to free the data with once ecore is shut down
 * @param direct If true, this will not copy the key string (like eina_hash_direct_add)
 * @return EINA_TRUE on success, EINA_FALSE on failure
 * This adds data to the global thread data, and will return EINA_FALSE in any case but success.
 * All data added to global can be manually freed, or a callback can be provided with @p cb which will
 * be called upon ecore_thread shutting down.  Note that if you have manually freed data that a callback
 * was specified for, you will most likely encounter a segv later on.
 */
EAPI Eina_Bool
ecore_thread_global_data_add(const char *key, void *value, Eina_Free_Cb cb,
			     Eina_Bool direct)
{
	Eina_Bool ret;
	Ecore_Thread_Data *d;

	if ((!key) || (!value))
		return EINA_FALSE;
#ifdef EFL_HAVE_PTHREAD
	pthread_rwlock_wrlock(&_ecore_thread_global_hash_lock);
	if (!_ecore_thread_global_hash)
		_ecore_thread_global_hash =
		    eina_hash_string_small_new(_ecore_thread_data_free);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);

	if (!(d = malloc(sizeof(Ecore_Thread_Data))))
		return EINA_FALSE;

	d->data = value;
	d->cb = cb;

	if (!_ecore_thread_global_hash)
		return EINA_FALSE;
	pthread_rwlock_wrlock(&_ecore_thread_global_hash_lock);
	if (direct)
		ret =
		    eina_hash_direct_add(_ecore_thread_global_hash, key,
					 d);
	else
		ret = eina_hash_add(_ecore_thread_global_hash, key, d);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);
	pthread_cond_broadcast(&_ecore_thread_global_hash_cond);
	return ret;
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Add data to the global data
 * @param key The name string to add the data with
 * @param value The data to add
 * @param cb The optional callback to free the data with once ecore is shut down
 * @return An Ecore_Thread_Data on success, NULL on failure
 * This adds data to the global thread data and returns NULL, or replaces the previous data
 * associated with @p key and returning the previous data if it existed.  To see if an error occurred,
 * one must use eina_error_get.
 * All data added to global can be manually freed, or a callback can be provided with @p cb which will
 * be called upon ecore_thread shutting down.  Note that if you have manually freed data that a callback
 * was specified for, you will most likely encounter a segv later on.
 */
EAPI void *ecore_thread_global_data_set(const char *key, void *value,
					Eina_Free_Cb cb)
{
	Ecore_Thread_Data *d, *r;
	void *ret;

	if ((!key) || (!value))
		return NULL;
#ifdef EFL_HAVE_PTHREAD
	pthread_rwlock_wrlock(&_ecore_thread_global_hash_lock);
	if (!_ecore_thread_global_hash)
		_ecore_thread_global_hash =
		    eina_hash_string_small_new(_ecore_thread_data_free);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);

	if (!_ecore_thread_global_hash)
		return NULL;

	if (!(d = malloc(sizeof(Ecore_Thread_Data))))
		return NULL;

	d->data = value;
	d->cb = cb;

	pthread_rwlock_wrlock(&_ecore_thread_global_hash_lock);
	r = eina_hash_set(_ecore_thread_global_hash, key, d);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);
	pthread_cond_broadcast(&_ecore_thread_global_hash_cond);

	ret = r->data;
	free(r);
	return ret;
#else
	return NULL;
#endif
}

/**
 * @brief Find data in the global data
 * @param key The name string the data is associated with
 * @return The value, or NULL on error
 * This finds data in the global data that has been previously added with @ref ecore_thread_global_data_add
 * This function will return NULL in any case but success.
 * All data added to global can be manually freed, or a callback can be provided with @p cb which will
 * be called upon ecore_thread shutting down.  Note that if you have manually freed data that a callback
 * was specified for, you will most likely encounter a segv later on.
 * @note Keep in mind that the data returned can be used by multiple threads at a time, so you will most likely want to mutex
 * if you will be doing anything with it.
 */

EAPI void *ecore_thread_global_data_find(const char *key)
{
	Ecore_Thread_Data *ret;
	if (!key)
		return NULL;
#ifdef EFL_HAVE_PTHREAD
	if (!_ecore_thread_global_hash)
		return NULL;

	pthread_rwlock_rdlock(&_ecore_thread_global_hash_lock);
	ret = eina_hash_find(_ecore_thread_global_hash, key);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);
	return ret->data;
#else
	return NULL;
#endif
}

/**
 * @brief Delete data from the global data
 * @param key The name string the data is associated with
 * @return EINA_TRUE on success, EINA_FALSE on failure
 * This deletes the data pointer from the global data which was previously added with @ref ecore_thread_global_data_add
 * This function will return EINA_FALSE in any case but success.
 * Note that this WILL free the data if an @c Eina_Free_Cb was specified when the data was added.
 */
EAPI Eina_Bool ecore_thread_global_data_del(const char *key)
{
	Eina_Bool ret;
	Ecore_Thread_Data *d;

	if (!key)
		return EINA_FALSE;
#ifdef EFL_HAVE_PTHREAD
	if (!_ecore_thread_global_hash)
		return EINA_FALSE;

	pthread_rwlock_wrlock(&_ecore_thread_global_hash_lock);
	if ((d = eina_hash_find(_ecore_thread_global_hash, key)))
		_ecore_thread_data_free(d);
	ret = eina_hash_del_by_key(_ecore_thread_global_hash, key);
	pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);
	return ret;
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Find data in the global data and optionally wait for the data if not found
 * @param key The name string the data is associated with
 * @param seconds The amount of time in seconds to wait for the data.  If 0, the call will be async and not wait for data.
 * If < 0 the call will wait indefinitely for the data.
 * @return The value, or NULL on failure
 * This finds data in the global data that has been previously added with @ref ecore_thread_global_data_add
 * This function will return NULL in any case but success.
 * Use @p seconds to specify the amount of time to wait.  Use > 0 for an actual wait time, 0 to not wait, and < 0 to wait indefinitely.
 * @note Keep in mind that the data returned can be used by multiple threads at a time, so you will most likely want to mutex
 * if you will be doing anything with it.
 */
EAPI void *ecore_thread_global_data_wait(const char *key, double seconds)
{
	double time = 0;
	Ecore_Thread_Data *ret = NULL;
	if (!key)
		return NULL;
#ifdef EFL_HAVE_PTHREAD
	if (!_ecore_thread_global_hash)
		return NULL;
	if (seconds > 0)
		time = ecore_time_get() + seconds;

	while (1) {
		struct timespec t = { 0, 0 };

		t.tv_sec = (long int) time;
		t.tv_nsec =
		    (long int) ((time - (double) t.tv_sec) * 1000000000);
		pthread_rwlock_rdlock(&_ecore_thread_global_hash_lock);
		ret = eina_hash_find(_ecore_thread_global_hash, key);
		pthread_rwlock_unlock(&_ecore_thread_global_hash_lock);
		if ((ret) || (!seconds)
		    || ((seconds > 0) && (time <= ecore_time_get())))
			break;
		pthread_mutex_lock(&_ecore_thread_global_hash_mutex);
		pthread_cond_timedwait(&_ecore_thread_global_hash_cond,
				       &_ecore_thread_global_hash_mutex,
				       &t);
		pthread_mutex_unlock(&_ecore_thread_global_hash_mutex);
	}
	if (ret)
		return ret->data;
	return NULL;
#else
	return NULL;
#endif
}

/**
 * @}
 */
