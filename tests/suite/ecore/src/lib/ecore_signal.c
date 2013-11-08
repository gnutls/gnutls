#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

#include "Ecore.h"
#include "ecore_private.h"

/* make mono happy - this is evil though... */
#undef SIGPWR
/* valgrind in some versions/setups uses SIGRT's... hmmm */
#undef SIGRTMIN

typedef void (*Signal_Handler) (int sig, siginfo_t * si, void *foo);

static void _ecore_signal_callback_set(int sig, Signal_Handler func);
static void _ecore_signal_callback_ignore(int sig, siginfo_t * si,
					  void *foo);
static void _ecore_signal_callback_sigchld(int sig, siginfo_t * si,
					   void *foo);
static void _ecore_signal_callback_sigusr1(int sig, siginfo_t * si,
					   void *foo);
static void _ecore_signal_callback_sigusr2(int sig, siginfo_t * si,
					   void *foo);
static void _ecore_signal_callback_sighup(int sig, siginfo_t * si,
					  void *foo);
static void _ecore_signal_callback_sigquit(int sig, siginfo_t * si,
					   void *foo);
static void _ecore_signal_callback_sigint(int sig, siginfo_t * si,
					  void *foo);
static void _ecore_signal_callback_sigterm(int sig, siginfo_t * si,
					   void *foo);
#ifdef SIGPWR
static void _ecore_signal_callback_sigpwr(int sig, siginfo_t * si,
					  void *foo);
#endif

#ifdef SIGRTMIN
static void _ecore_signal_callback_sigrt(int sig, siginfo_t * si,
					 void *foo);
#endif

static Eina_Bool _ecore_signal_exe_exit_delay(void *data);

//#define MAXSIGQ 256 // 32k
#define MAXSIGQ 64		// 8k

static volatile sig_atomic_t sig_count = 0;
static volatile sig_atomic_t sigchld_count = 0;
static volatile sig_atomic_t sigusr1_count = 0;
static volatile sig_atomic_t sigusr2_count = 0;
static volatile sig_atomic_t sighup_count = 0;
static volatile sig_atomic_t sigquit_count = 0;
static volatile sig_atomic_t sigint_count = 0;
static volatile sig_atomic_t sigterm_count = 0;
#ifdef SIGPWR
static volatile sig_atomic_t sigpwr_count = 0;
#endif
#ifdef SIGRTMIN
static volatile sig_atomic_t *sigrt_count = NULL;
#endif

static volatile siginfo_t sigchld_info[MAXSIGQ];
static volatile siginfo_t sigusr1_info[MAXSIGQ];
static volatile siginfo_t sigusr2_info[MAXSIGQ];
static volatile siginfo_t sighup_info[MAXSIGQ];
static volatile siginfo_t sigquit_info[MAXSIGQ];
static volatile siginfo_t sigint_info[MAXSIGQ];
static volatile siginfo_t sigterm_info[MAXSIGQ];
#ifdef SIGPWR
static volatile siginfo_t sigpwr_info[MAXSIGQ];
#endif
#ifdef SIGRTMIN
static volatile siginfo_t *sigrt_info[MAXSIGQ];
#endif

void _ecore_signal_shutdown(void)
{
#ifdef SIGRTMIN
	int i, num = SIGRTMAX - SIGRTMIN;
#endif

	_ecore_signal_callback_set(SIGPIPE, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGALRM, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGCHLD, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGUSR1, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGUSR2, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGHUP, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGQUIT, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGINT, (Signal_Handler) SIG_DFL);
	_ecore_signal_callback_set(SIGTERM, (Signal_Handler) SIG_DFL);
#ifdef SIGPWR
	_ecore_signal_callback_set(SIGPWR, (Signal_Handler) SIG_DFL);
	sigpwr_count = 0;
#endif
	sigchld_count = 0;
	sigusr1_count = 0;
	sigusr2_count = 0;
	sighup_count = 0;
	sigquit_count = 0;
	sigint_count = 0;
	sigterm_count = 0;
	sig_count = 0;

#ifdef SIGRTMIN
	for (i = 0; i < num; i++) {
		_ecore_signal_callback_set(SIGRTMIN + i,
					   (Signal_Handler) SIG_DFL);
		sigrt_count[i] = 0;
	}

	if (sigrt_count) {
		free((sig_atomic_t *) sigrt_count);
		sigrt_count = NULL;
	}

	for (i = 0; i < MAXSIGQ; i++) {
		if (sigrt_info[i]) {
			free((siginfo_t *) sigrt_info[i]);
			sigrt_info[i] = NULL;
		}
	}
#endif
}

void _ecore_signal_init(void)
{
#ifdef SIGRTMIN
	int i, num = SIGRTMAX - SIGRTMIN;
#endif

	_ecore_signal_callback_set(SIGPIPE, _ecore_signal_callback_ignore);
	_ecore_signal_callback_set(SIGALRM, _ecore_signal_callback_ignore);
	_ecore_signal_callback_set(SIGCHLD,
				   _ecore_signal_callback_sigchld);
	_ecore_signal_callback_set(SIGUSR1,
				   _ecore_signal_callback_sigusr1);
	_ecore_signal_callback_set(SIGUSR2,
				   _ecore_signal_callback_sigusr2);
	_ecore_signal_callback_set(SIGHUP, _ecore_signal_callback_sighup);
	_ecore_signal_callback_set(SIGQUIT,
				   _ecore_signal_callback_sigquit);
	_ecore_signal_callback_set(SIGINT, _ecore_signal_callback_sigint);
	_ecore_signal_callback_set(SIGTERM,
				   _ecore_signal_callback_sigterm);
#ifdef SIGPWR
	_ecore_signal_callback_set(SIGPWR, _ecore_signal_callback_sigpwr);
#endif

#ifdef SIGRTMIN
	sigrt_count = calloc(1, sizeof(sig_atomic_t) * num);
	assert(sigrt_count);

	for (i = 0; i < MAXSIGQ; i++) {
		sigrt_info[i] = calloc(1, sizeof(siginfo_t) * num);
		assert(sigrt_info[i]);
	}

	for (i = 0; i < num; i++)
		_ecore_signal_callback_set(SIGRTMIN + i,
					   _ecore_signal_callback_sigrt);
#endif
}

int _ecore_signal_count_get(void)
{
	return sig_count;
}

void _ecore_signal_call(void)
{
#ifdef SIGRTMIN
	int i, num = SIGRTMAX - SIGRTMIN;
#endif
	volatile sig_atomic_t n;
	sigset_t oldset, newset;

	if (sig_count == 0)
		return;
	sigemptyset(&newset);
	sigaddset(&newset, SIGPIPE);
	sigaddset(&newset, SIGALRM);
	sigaddset(&newset, SIGCHLD);
	sigaddset(&newset, SIGUSR1);
	sigaddset(&newset, SIGUSR2);
	sigaddset(&newset, SIGHUP);
	sigaddset(&newset, SIGQUIT);
	sigaddset(&newset, SIGINT);
	sigaddset(&newset, SIGTERM);
#ifdef SIGPWR
	sigaddset(&newset, SIGPWR);
#endif
#ifdef SIGRTMIN
	for (i = 0; i < num; i++)
		sigaddset(&newset, SIGRTMIN + i);
#endif
	sigprocmask(SIG_BLOCK, &newset, &oldset);
	if (sigchld_count > MAXSIGQ)
		WRN("%i SIGCHLD in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigchld_count, MAXSIGQ);
	for (n = 0; n < sigchld_count; n++) {
		pid_t pid;
		int status;

		while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
			Ecore_Exe_Event_Del *e;

			/* FIXME: If this process is set respawn, respawn with a suitable backoff
			 * period for those that need too much respawning.
			 */
			e = _ecore_exe_event_del_new();
			if (e) {
				if (WIFEXITED(status)) {
					e->exit_code = WEXITSTATUS(status);
					e->exited = 1;
				} else if (WIFSIGNALED(status)) {
					e->exit_signal = WTERMSIG(status);
					e->signalled = 1;
				}
				e->pid = pid;
				e->exe = _ecore_exe_find(pid);

				if ((n < MAXSIGQ)
				    && (sigchld_info[n].si_signo))
					e->data = sigchld_info[n];	/* No need to clone this. */

				if ((e->exe)
				    && (ecore_exe_flags_get(e->exe) &
					(ECORE_EXE_PIPE_READ |
					 ECORE_EXE_PIPE_ERROR))) {
					/* We want to report the Last Words of the exe, so delay this event.
					 * This is twice as relevant for stderr.
					 * There are three possibilities here -
					 *  1 There are no Last Words.
					 *  2 There are Last Words, they are not ready to be read.
					 *  3 There are Last Words, they are ready to be read.
					 *
					 * For 1 we don't want to delay, for 3 we want to delay.
					 * 2 is the problem.  If we check for data now and there
					 * is none, then there is no way to differentiate 1 and 2.
					 * If we don't delay, we may loose data, but if we do delay,
					 * there may not be data and the exit event never gets sent.
					 *
					 * Any way you look at it, there has to be some time passed
					 * before the exit event gets sent.  So the strategy here is
					 * to setup a timer event that will send the exit event after
					 * an arbitrary, but brief, time.
					 *
					 * This is probably paranoid, for the less paraniod, we could
					 * check to see for Last Words, and only delay if there are any.
					 * This has it's own set of problems.
					 */
					Ecore_Timer *doomsday_clock;

					doomsday_clock =
					    _ecore_exe_doomsday_clock_get
					    (e->exe);
					IF_FN_DEL(ecore_timer_del,
						  doomsday_clock);
					_ecore_exe_doomsday_clock_set(e->
								      exe,
								      ecore_timer_add
								      (0.1,
								       _ecore_signal_exe_exit_delay,
								       e));
				} else {
					_ecore_event_add
					    (ECORE_EXE_EVENT_DEL, e,
					     _ecore_exe_event_del_free,
					     NULL);
				}
			}
		}
		sig_count--;
	}
	sigchld_count = 0;

	if (sigusr1_count > MAXSIGQ)
		WRN("%i SIGUSR1 in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigusr1_count, MAXSIGQ);
	for (n = 0; n < sigusr1_count; n++) {
		Ecore_Event_Signal_User *e;

		e = _ecore_event_signal_user_new();
		if (e) {
			e->number = 1;

			if ((n < MAXSIGQ) && (sigusr1_info[n].si_signo))
				e->data = sigusr1_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_USER, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigusr1_count = 0;

	if (sigusr2_count > MAXSIGQ)
		WRN("%i SIGUSR2 in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigusr2_count, MAXSIGQ);
	for (n = 0; n < sigusr2_count; n++) {
		Ecore_Event_Signal_User *e;

		e = _ecore_event_signal_user_new();
		if (e) {
			e->number = 2;

			if ((n < MAXSIGQ) && (sigusr2_info[n].si_signo))
				e->data = sigusr2_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_USER, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigusr2_count = 0;

	if (sighup_count > MAXSIGQ)
		WRN("%i SIGHUP in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sighup_count, MAXSIGQ);
	for (n = 0; n < sighup_count; n++) {
		Ecore_Event_Signal_Hup *e;

		e = _ecore_event_signal_hup_new();
		if (e) {
			if ((n < MAXSIGQ) && (sighup_info[n].si_signo))
				e->data = sighup_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_HUP, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sighup_count = 0;

	if (sigquit_count > MAXSIGQ)
		WRN("%i SIGQUIT in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigquit_count, MAXSIGQ);
	for (n = 0; n < sigquit_count; n++) {
		Ecore_Event_Signal_Exit *e;

		e = _ecore_event_signal_exit_new();
		if (e) {
			e->quit = 1;

			if ((n < MAXSIGQ) && (sigquit_info[n].si_signo))
				e->data = sigquit_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_EXIT, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigquit_count = 0;

	if (sigint_count > MAXSIGQ)
		WRN("%i SIGINT in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigint_count, MAXSIGQ);
	for (n = 0; n < sigint_count; n++) {
		Ecore_Event_Signal_Exit *e;

		e = _ecore_event_signal_exit_new();
		if (e) {
			e->interrupt = 1;

			if ((n < MAXSIGQ) && (sigint_info[n].si_signo))
				e->data = sigint_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_EXIT, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigint_count = 0;

	if (sigterm_count > MAXSIGQ)
		WRN("%i SIGTERM in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigterm_count, MAXSIGQ);
	for (n = 0; n < sigterm_count; n++) {
		Ecore_Event_Signal_Exit *e;

		e = _ecore_event_signal_exit_new();
		if (e) {
			e->terminate = 1;

			if ((n < MAXSIGQ) && (sigterm_info[n].si_signo))
				e->data = sigterm_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_EXIT, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigterm_count = 0;

#ifdef SIGPWR
	if (sigpwr_count > MAXSIGQ)
		WRN("%i SIGPWR in queue. max queue size %i. losing "
		    "siginfo for extra signals.", sigpwr_count, MAXSIGQ);
	for (n = 0; n < sigpwr_count; n++) {
		Ecore_Event_Signal_Power *e;

		e = _ecore_event_signal_power_new();
		if (e) {
			if ((n < MAXSIGQ) && (sigpwr_info[n].si_signo))
				e->data = sigpwr_info[n];

			ecore_event_add(ECORE_EVENT_SIGNAL_POWER, e, NULL,
					NULL);
		}
		sig_count--;
	}
	sigpwr_count = 0;
#endif

#ifdef SIGRTMIN
	for (i = 0; i < num; i++) {
		if (sigrt_count[i] > MAXSIGQ)
			WRN("%i SIGRT%i in queue. max queue size %i. losing " "siginfo for extra signals.", i + 1, sigrt_count[i], MAXSIGQ);
		for (n = 0; n < sigrt_count[i]; n++) {
			Ecore_Event_Signal_Realtime *e;

			if ((e = _ecore_event_signal_realtime_new())) {
				e->num = i;

				if ((n < MAXSIGQ)
				    && (sigrt_info[n][i].si_signo))
					e->data = sigrt_info[n][i];

				ecore_event_add
				    (ECORE_EVENT_SIGNAL_REALTIME, e, NULL,
				     NULL);
			}
			sig_count--;
		}
		sigrt_count[i] = 0;
	}
#endif
	sigprocmask(SIG_SETMASK, &oldset, NULL);
}

static void _ecore_signal_callback_set(int sig, Signal_Handler func)
{
	struct sigaction sa;

	sa.sa_sigaction = func;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(sig, &sa, NULL);
}

static void
_ecore_signal_callback_ignore(int sig __UNUSED__,
			      siginfo_t * si __UNUSED__,
			      void *foo __UNUSED__)
{
}

static void
_ecore_signal_callback_sigchld(int sig __UNUSED__, siginfo_t * si,
			       void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigchld_info[n] = *si;
		else
			sigchld_info[n].si_signo = 0;
	}

	sigchld_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sigusr1(int sig __UNUSED__, siginfo_t * si,
			       void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigusr1_info[n] = *si;
		else
			sigusr1_info[n].si_signo = 0;
	}
	sigusr1_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sigusr2(int sig __UNUSED__, siginfo_t * si,
			       void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigusr2_info[n] = *si;
		else
			sigusr2_info[n].si_signo = 0;
	}
	sigusr2_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sighup(int sig __UNUSED__, siginfo_t * si,
			      void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sighup_info[n] = *si;
		else
			sighup_info[n].si_signo = 0;
	}
	sighup_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sigquit(int sig __UNUSED__, siginfo_t * si,
			       void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigquit_info[n] = *si;
		else
			sigquit_info[n].si_signo = 0;
	}
	sigquit_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sigint(int sig __UNUSED__, siginfo_t * si,
			      void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigint_info[n] = *si;
		else
			sigint_info[n].si_signo = 0;
	}
	sigint_count++;
	sig_count++;
}

static void
_ecore_signal_callback_sigterm(int sig __UNUSED__, siginfo_t * si,
			       void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigterm_info[n] = *si;
		else
			sigterm_info[n].si_signo = 0;
	}
	sigterm_count++;
	sig_count++;
}

#ifdef SIGPWR
static void
_ecore_signal_callback_sigpwr(int sig __UNUSED__, siginfo_t * si,
			      void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigpwr_info[n] = *si;
		else
			sigpwr_info[n].si_signo = 0;
	}
	sigpwr_count++;
	sig_count++;
}
#endif

#ifdef SIGRTMIN
static void
_ecore_signal_callback_sigrt(int sig, siginfo_t * si, void *foo __UNUSED__)
{
	volatile sig_atomic_t n;
	n = sigchld_count;
	if (n < MAXSIGQ) {
		if (si)
			sigrt_info[n][sig - SIGRTMIN] = *si;
		else
			sigrt_info[n][sig - SIGRTMIN].si_signo = 0;
	}
	sigrt_count[sig - SIGRTMIN]++;
	sig_count++;
}
#endif

static Eina_Bool _ecore_signal_exe_exit_delay(void *data)
{
	Ecore_Exe_Event_Del *e;

	e = data;
	if (e) {
		_ecore_exe_doomsday_clock_set(e->exe, NULL);
		_ecore_event_add(ECORE_EXE_EVENT_DEL, e,
				 _ecore_exe_event_del_free, NULL);
	}
	return ECORE_CALLBACK_CANCEL;
}
