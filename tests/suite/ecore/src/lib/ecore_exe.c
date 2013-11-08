#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "Ecore.h"
#include "ecore_private.h"


   /* FIXME: Getting respawn to work
    *
    * There is no way that we can do anything about the internal state info of
    * an external exe.  The same can be said about the state of user code.  User
    * code in this context means the code that is using ecore_exe to manage exe's
    * for it.
    *
    * Document that the exe must be respawnable, in other words, there is no
    * state that it cannot regenerate by just killing it and starting it again.
    * This includes state that the user code knows about, as the respawn is
    * transparent to that code.  On the other hand, maybe a respawn event might
    * be useful, or maybe resend the currently non existent add event.  For
    * consistancy with ecore_con, an add event is good anyway.
    *
    * The Ecore_exe structure is reused for respawning, so that the (opaque)
    * pointer held by the user remains valid.  This means that the Ecore_Exe
    * init and del functions may need to be split into two parts each to avoid
    * duplicating code - common code part, and the rest.  This implies that
    * the unchanging members mentioned next should NEVER change.
    *
    * These structure members don't need to change -
    *   __list_data       - we stay on the list
    *   ECORE_MAGIC       - this is a constant
    *   data              - passed in originally
    *   cmd               - passed in originally
    *   flags             - passed in originally
    *
    * These structure members need to change -
    *   tag               - state that must be regenerated, zap it
    *   pid               - it will be different
    *   child_fd_write    - it will be different
    *   child_fd_read     - it will be different
    *   child_fd_error    - it will be different
    *   write_fd_handler  - we cannot change the fd used by a handler, this changes coz the fd changes.
    *   read_fd_handler   - we cannot change the fd used by a handler, this changes coz the fd changes.
    *   error_fd_handler  - we cannot change the fd used by a handler, this changes coz the fd changes.
    *
    * Hmm, the read, write, and error buffers could be tricky.
    * They are not atomic, and could be in a semi complete state.
    * They fall into the "state must be regenerated" mentioned above.
    * A respawn/add event should take care of it.
    *
    * These structure members need to change -
    *   write_data_buf    - state that must be regenerated, zap it
    *   write_data_size   - state that must be regenerated, zap it
    *   write_data_offset - state that must be regenerated, zap it
    *   read_data_buf     - state that must be regenerated, zap it
    *   read_data_size    - state that must be regenerated, zap it
    *   error_data_buf    - state that must be regenerated, zap it
    *   error_data_size   - state that must be regenerated, zap it
    *   close_write       - state that must be regenerated, zap it
    *
    * There is the problem that an exe that fell over and needs respawning
    * might keep falling over, keep needing to be respawned, and tie up system
    * resources with the constant respawning.  An exponentially increasing
    * timeout (with maximum timeout) between respawns should take care of that.
    * Although this is not a "contention for a resource" problem, the exe falling
    * over may be, so a random element added to the timeout may help, and won't
    * hurt.  The user code may need to be informed that a timeout is in progress.
    */

struct _Ecore_Exe {
	EINA_INLIST;
	ECORE_MAGIC;
	pid_t pid;
	void *data;
	char *tag, *cmd;
	Ecore_Exe_Flags flags;
	Ecore_Fd_Handler *write_fd_handler;	/* the fd_handler to handle write to child - if this was used, or NULL if not */
	Ecore_Fd_Handler *read_fd_handler;	/* the fd_handler to handle read from child - if this was used, or NULL if not */
	Ecore_Fd_Handler *error_fd_handler;	/* the fd_handler to handle errors from child - if this was used, or NULL if not */
	void *write_data_buf;	/* a data buffer for data to write to the child -
				 * realloced as needed for more data and flushed when the fd handler says writes are possible
				 */
	int write_data_size;	/* the size in bytes of the data buffer */
	int write_data_offset;	/* the offset in bytes in the data buffer */
	void *read_data_buf;	/* data read from the child awating delivery to an event */
	int read_data_size;	/* data read from child in bytes */
	void *error_data_buf;	/* errors read from the child awating delivery to an event */
	int error_data_size;	/* errors read from child in bytes */
	int child_fd_write;	/* fd to write TO to send data to the child */
	int child_fd_read;	/* fd to read FROM when child has sent us (the parent) data */
	int child_fd_error;	/* fd to read FROM when child has sent us (the parent) errors */
	int child_fd_write_x;	/* fd to write TO to send data to the child */
	int child_fd_read_x;	/* fd to read FROM when child has sent us (the parent) data */
	int child_fd_error_x;	/* fd to read FROM when child has sent us (the parent) errors */
	Eina_Bool close_stdin:1;

	int start_bytes, end_bytes, start_lines, end_lines;	/* Number of bytes/lines to auto pipe at start/end of stdout/stderr. */

	Ecore_Timer *doomsday_clock;	/* The Timer of Death.  Muahahahaha. */
	void *doomsday_clock_dead;	/* data for the doomsday clock */

	Ecore_Exe_Cb pre_free_cb;
};


/* TODO: Something to let people build a command line and does auto escaping -
 *
 * ecore_exe_snprintf()
 *
 *   OR
 *
 * cmd = ecore_exe_comand_parameter_append(cmd, "firefox");
 * cmd = ecore_exe_comand_parameter_append(cmd, "http://www.foo.com/bar.html?baz=yes");
 * each parameter appended is one argument, and it gets escaped, quoted, and
 * appended with a preceding space.  The first is the command off course.
 */

struct _ecore_exe_dead_exe {
	pid_t pid;
	char *cmd;
};

static inline void _ecore_exe_exec_it(const char *exe_cmd,
				      Ecore_Exe_Flags flags);
static Eina_Bool _ecore_exe_data_generic_handler(void *data,
						 Ecore_Fd_Handler *
						 fd_handler,
						 Ecore_Exe_Flags flags);
static Eina_Bool _ecore_exe_data_error_handler(void *data,
					       Ecore_Fd_Handler *
					       fd_handler);
static Eina_Bool _ecore_exe_data_read_handler(void *data,
					      Ecore_Fd_Handler *
					      fd_handler);
static Eina_Bool _ecore_exe_data_write_handler(void *data,
					       Ecore_Fd_Handler *
					       fd_handler);
static void _ecore_exe_flush(Ecore_Exe * exe);
static void _ecore_exe_event_exe_data_free(void *data __UNUSED__,
					   void *ev);
static Ecore_Exe *_ecore_exe_is_it_alive(pid_t pid);
static Eina_Bool _ecore_exe_make_sure_its_dead(void *data);
static Eina_Bool _ecore_exe_make_sure_its_really_dead(void *data);
static Ecore_Exe_Event_Add *_ecore_exe_event_add_new(void);
static void _ecore_exe_event_add_free(void *data, void *ev);
static void _ecore_exe_dead_attach(Ecore_Exe * exe);

EAPI int ECORE_EXE_EVENT_ADD = 0;
EAPI int ECORE_EXE_EVENT_DEL = 0;
EAPI int ECORE_EXE_EVENT_DATA = 0;
EAPI int ECORE_EXE_EVENT_ERROR = 0;

static Ecore_Exe *exes = NULL;
static const char *shell = NULL;

/* FIXME: This errno checking stuff should be put elsewhere for everybody to use.
 * For now it lives here though, just to make testing easier.
 */
static int _ecore_exe_check_errno(int result, const char *file, int line);

#define E_IF_NO_ERRNO(result, foo, ok) \
  while (((ok) = _ecore_exe_check_errno( (result) = (foo), __FILE__, __LINE__)) == -1)   sleep(1); \
  if (ok)

#define E_NO_ERRNO(result, foo, ok) \
  while (((ok) = _ecore_exe_check_errno( (result) = (foo), __FILE__, __LINE__)) == -1)   sleep(1)

#define E_IF_NO_ERRNO_NOLOOP(result, foo, ok) \
  if (((ok) = _ecore_exe_check_errno( (result) = (foo), __FILE__, __LINE__)))

static int _ecore_exe_check_errno(int result, const char *file, int line)
{
	int saved_errno = errno;

	if (result == -1) {
		perror("*** errno reports ");
/* What is currently supported -
 *
 *   pipe
 *     EFAULT  Argument is not valid.
 *     EMFILE  Too many file descriptors used by process.
 *     ENFILE  Too many open files by system.
 *   read
 *     EAGAIN  No data now, try again.
 *     EBADF   This is not an fd that can be read.
 *     EFAULT  This is not a valid buffer.
 *     EINTR   Interupted by signal, try again.
 *     EINVAL  This is not an fd that can be read.
 *     EIO     I/O error.
 *     EISDIR  This is a directory, and cannot be read.
 *     others  Depending on what sort of thing we are reading from.
 *   close
 *     EBADF   This is not an fd that can be closed.
 *     EINTR   Interupted by signal, try again.
 *     EIO     I/O error.
 *   dup2
 *     EBADF   This is not an fd that can be dup2'ed.
 *     EBUSY   Race condition between open() and dup()
 *     EINTR   Interupted by signal, try again.
 *     EMFILE  Too many file descriptors used by process.
 *   fcntl
 *     EACCES, EAGAIN  Locked or mapped by something else, try again later.
 *     EBADF   This is not an fd that can be fcntl'ed.
 *     EDEADLK This will cause a deadlock.
 *     EFAULT  This is not a valid lock.
 *     EINTR   Interupted by signal, try again.
 *     EINVAL  This is not a valid arg.
 *     EMFILE  Too many file descriptors used by process.
 *     ENOLCK  Problem getting a lock.
 *     EPERM   Not allowed to do that.
 *   fsync
 *     EBADF   This is not an fd that is open for writing.
 *     EINVAL, EROFS  This is not an fd that can be fsynced.
 *     EIO     I/O error.
 *
 * How to use it -
 *    int ok = 0;
 *    int result;
 *
 *    E_IF_NO_ERRNO(result, foo(bar), ok)
 *      {
 *         E_IF_NO_ERRNO_NOLOOP(result, foo(bar), ok)
 *            {
 *            }
 *      }
 *
 *   if (!ok)
 *     {
 *        // Something failed, cleanup.
 *     }
 */
		switch (saved_errno) {
		case EACCES:
		case EAGAIN:
		case EINTR:
			{	/* Not now, try later. */
				ERR("*** Must try again in %s @%u.", file,
				    line);
				result = -1;
				break;
			}
		case EMFILE:
		case ENFILE:
		case ENOLCK:
			{	/* Low on resources. */
				ERR("*** Low on resources in %s @%u.",
				    file, line);
				result = 0;
				break;
			}
		case EIO:
			{	/* I/O error. */
				ERR("*** I/O error in %s @%u.", file,
				    line);
				result = 0;
				break;
			}
		case EFAULT:
		case EBADF:
		case EINVAL:
		case EROFS:
		case EISDIR:
		case EDEADLK:
		case EPERM:
		case EBUSY:
			{	/* Programmer fucked up. */
				ERR("*** NAUGHTY PROGRAMMER!!!\n"
				    "*** SPANK SPANK SPANK!!!\n"
				    "*** Now go fix your code in %s @%u. Tut tut tut!",
				    file, line);
				result = 0;
				break;
			}
		default:
			{	/* Unsupported errno code, please add this one. */
				ERR("*** NAUGHTY PROGRAMMER!!!\n"
				    "*** SPANK SPANK SPANK!!!\n"
				    "*** Unsupported errno code %d, please add this one.\n"
				    "*** Now go fix your code in %s @%u, from %s @%u. Tut tut tut!",
				    saved_errno, __FILE__, __LINE__, file,
				    line);
				result = 0;
				break;
			}
		}
	} else			/* Everything is fine. */
		result = 1;

	errno = saved_errno;
	return result;
}

/**
 * @defgroup Ecore_Exe_Basic_Group Process Spawning Functions
 *
 * Functions that deal with spawned processes.
 */

static int run_pri = ECORE_EXE_PRIORITY_INHERIT;

/**
 * Sets the priority at which to launch processes
 *
 * This sets the priority of processes run by ecore_exe_run() and
 * ecore_exe_pipe_run().
 * @li On Windows, the child process is created by default with the
 * #ECORE_EXE_WIN32_PRIORITY_NORMAL priority, unless the calling
 * process is in #ECORE_EXE_WIN32_PRIORITY_IDLE or
 * #ECORE_EXE_WIN32_PRIORITY_BELOW_NORMAL priority. In that case, the
 * child process inherits this priority.
 * @li On other platforms, if set to #ECORE_EXE_PRIORITY_INHERIT child
 * processes inherits the priority of their parent. This is the default.
 *
 * @param   pri value a Ecore_Exe_Win32_Priority value on Windows, -20
 * to 19 or ECORE_EXE_PRIORITY_INHERIT on other OS.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void ecore_exe_run_priority_set(int pri)
{
	run_pri = pri;
}

/**
 * Gets the priority at which to launch processes
 *
 * This gets ths priority of launched processes. See
 * ecore_exe_run_priority_set() for details. This just returns the value set
 * by this call.
 *
 * @return the value set by ecore_exe_run_priority_set()
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI int ecore_exe_run_priority_get(void)
{
	return run_pri;
}

/**
 * Spawns a child process.
 *
 * This is now just a thin wrapper around ecore_exe_pipe_run()
 *
 * @param   exe_cmd The command to run with @c /bin/sh.
 * @param   data    Data to attach to the returned process handle.
 * @return  A process handle to the spawned process.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI Ecore_Exe *ecore_exe_run(const char *exe_cmd, const void *data)
{
/* I'm just being paranoid again, leaving in the original code in case there is a problem. */
#if 0
	Ecore_Exe *exe;
	pid_t pid;

	if (!exe_cmd)
		return NULL;
	pid = fork();
	if (pid) {
		exe = calloc(1, sizeof(Ecore_Exe));
		if (!exe) {
			kill(pid, SIGKILL);
			return NULL;
		}
		ECORE_MAGIC_SET(exe, ECORE_MAGIC_EXE);
		exe->pid = pid;
		exe->data = (void *) data;
		exe->cmd = strdup(exe_cmd);
		exes = _ecore_list2_append(exes, exe);
		return exe;
	}
	_ecore_exe_exec_it(exe_cmd, 0);
	exit(127);
	return NULL;
#else
	return ecore_exe_pipe_run(exe_cmd, 0, data);
#endif
}

/**
 * Spawns a child process with its stdin/out available for communication.
 *
 * This function forks and runs the given command using @c /bin/sh.
 *
 * Note that the process handle is only valid until a child process
 * terminated event is received.  After all handlers for the child process
 * terminated event have been called, the handle will be freed by Ecore.
 *
 * This function does the same thing as ecore_exe_run(), but also makes the
 * standard in and/or out as well as stderr from the child process available
 * for reading or writing.  To write use ecore_exe_send().  To read listen to
 * ECORE_EXE_EVENT_DATA or ECORE_EXE_EVENT_ERROR events (set up handlers).
 * Ecore may buffer read and error data until a newline character if asked
 * for with the @p flags.  All data will be included in the events (newlines
 * will be replaced with NULLS if line buffered).  ECORE_EXE_EVENT_DATA events
 * will only happen if the process is run with ECORE_EXE_PIPE_READ enabled
 * in the flags.  The same with the error version.  Writing will only be
 * allowed with ECORE_EXE_PIPE_WRITE enabled in the flags.
 *
 * @param   exe_cmd The command to run with @c /bin/sh.
 * @param   flags   The flag parameters for how to deal with inter-process I/O
 * @param   data    Data to attach to the returned process handle.
 * @return  A process handle to the spawned process.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI Ecore_Exe *ecore_exe_pipe_run(const char *exe_cmd,
				   Ecore_Exe_Flags flags, const void *data)
{
	Ecore_Exe *exe = NULL;
	int statusPipe[2] = { -1, -1 };
	int errorPipe[2] = { -1, -1 };
	int readPipe[2] = { -1, -1 };
	int writePipe[2] = { -1, -1 };
	int n = 0;
	int ok = 1;
	int result;

	if (!exe_cmd)
		return NULL;
	exe = calloc(1, sizeof(Ecore_Exe));
	if (!exe)
		return NULL;

	if ((flags & ECORE_EXE_PIPE_AUTO)
	    && (!(flags & ECORE_EXE_PIPE_ERROR))
	    && (!(flags & ECORE_EXE_PIPE_READ)))
		/* We need something to auto pipe. */
		flags |= ECORE_EXE_PIPE_READ | ECORE_EXE_PIPE_ERROR;

	exe->child_fd_error = -1;
	exe->child_fd_read = -1;
	exe->child_fd_write = -1;
	exe->child_fd_error_x = -1;
	exe->child_fd_read_x = -1;
	exe->child_fd_write_x = -1;

	/*  Create some pipes. */
	if (ok) {
		E_IF_NO_ERRNO_NOLOOP(result, pipe(statusPipe), ok) {
		}
	}
	if (ok && (flags & ECORE_EXE_PIPE_ERROR)) {
		E_IF_NO_ERRNO_NOLOOP(result, pipe(errorPipe), ok) {
			exe->child_fd_error = errorPipe[0];
			exe->child_fd_error_x = errorPipe[1];
		}
	}
	if (ok && (flags & ECORE_EXE_PIPE_READ)) {
		E_IF_NO_ERRNO_NOLOOP(result, pipe(readPipe), ok) {
			exe->child_fd_read = readPipe[0];
			exe->child_fd_read_x = readPipe[1];
		}
	}
	if (ok && (flags & ECORE_EXE_PIPE_WRITE)) {
		E_IF_NO_ERRNO_NOLOOP(result, pipe(writePipe), ok) {
			exe->child_fd_write = writePipe[1];
			exe->child_fd_write_x = writePipe[0];
		}
	}
	if (ok) {
		pid_t pid = 0;
		volatile int vfork_exec_errno = 0;

		/* FIXME: I should double check this.  After a quick look around, this is already done, but via a more modern method. */
		/* signal(SIGPIPE, SIG_IGN);    We only want EPIPE on errors */
		pid = fork();

		if (pid == -1) {
			ERR("Failed to fork process");
			pid = 0;
		} else if (pid == 0) {	/* child */
			if (run_pri != ECORE_EXE_PRIORITY_INHERIT) {
				if ((run_pri >= -20) && (run_pri <= 19))
					setpriority(PRIO_PROCESS, 0,
						    run_pri);
			}
			/* dup2 STDERR, STDIN, and STDOUT.  dup2() allegedly closes the
			 * second pipe if it's open. On the other hand, there was the
			 * Great FD Leak Scare of '06, so let's be paranoid. */
			if (ok && (flags & ECORE_EXE_PIPE_ERROR)) {
				E_NO_ERRNO(result, close(STDERR_FILENO),
					   ok);
				E_NO_ERRNO(result,
					   dup2(errorPipe[1],
						STDERR_FILENO), ok);
			}
			if (ok && (flags & ECORE_EXE_PIPE_READ)) {
				E_NO_ERRNO(result, close(STDOUT_FILENO),
					   ok);
				E_NO_ERRNO(result,
					   dup2(readPipe[1],
						STDOUT_FILENO), ok);
			}
			if (ok && (flags & ECORE_EXE_PIPE_WRITE)) {
				E_NO_ERRNO(result, close(STDIN_FILENO),
					   ok);
				E_NO_ERRNO(result,
					   dup2(writePipe[0],
						STDIN_FILENO), ok);
			}

			if (ok) {
				/* Setup the status pipe. */
				E_NO_ERRNO(result, close(statusPipe[0]),
					   ok);
				E_IF_NO_ERRNO(result, fcntl(statusPipe[1], F_SETFD, FD_CLOEXEC), ok) {	/* close on exec shows success */
					/* Run the actual command. */
					_ecore_exe_exec_it(exe_cmd, flags);	/* no return */
				}
			}

			/* Something went 'orribly wrong. */
			vfork_exec_errno = errno;

			/* Close the pipes. */
			if (flags & ECORE_EXE_PIPE_ERROR)
				E_NO_ERRNO(result, close(errorPipe[1]),
					   ok);
			if (flags & ECORE_EXE_PIPE_READ)
				E_NO_ERRNO(result, close(readPipe[1]), ok);
			if (flags & ECORE_EXE_PIPE_WRITE)
				E_NO_ERRNO(result, close(writePipe[0]),
					   ok);
			E_NO_ERRNO(result, close(statusPipe[1]), ok);

			_exit(-1);
		} else {	/* parent */

			/* Close the unused pipes. */
			E_NO_ERRNO(result, close(statusPipe[1]), ok);

			/* FIXME: after having a good look at the current e fd
			 * handling, investigate fcntl(dataPipe[x], F_SETSIG, ...) */
			/* FIXME: above F_SETSIG etc. - this is async SIGIO based IO
			 * which is also linux specific so we probably don't want to
			 * do this as long as select() is working fine. the only time
			 * we really want to think of SIGIO async IO is when it all
			 * actually works basically everywhere and we can turn all
			 * IO into DMA async activities (i.e. you do a read() then
			 * the read is complete not on return but when you get a
			 * SIGIO - the read() just starts the transfer and it is
			 * completed in the background by DMA (or whatever mechanism
			 * the kernel choses)) */

			/* Wait for it to start executing. */
			/* FIXME: this doesn't seem very nice - we sit and block
			 * waiting on a child process... even though it's just
			 * the segment between the fork() and the exec) it just feels
			 * wrong */
			for (;;) {
				char buf;

				E_NO_ERRNO(result,
					   read(statusPipe[0], &buf, 1),
					   ok);
				if (result == 0) {
					if (vfork_exec_errno != 0) {
						n = vfork_exec_errno;
						ERR("Could not start \"%s\"", exe_cmd);
						pid = 0;
					}
					break;
				}
			}

			/* Close the status pipe. */
			E_NO_ERRNO(result, close(statusPipe[0]), ok);
		}

		if (pid) {
			/* Setup the exe structure. */
			ECORE_MAGIC_SET(exe, ECORE_MAGIC_EXE);
			exe->start_bytes = -1;
			exe->end_bytes = -1;
			exe->start_lines = -1;
			exe->end_lines = -1;
			exe->pid = pid;
			exe->flags = flags;
			exe->data = (void *) data;
			if ((exe->cmd = strdup(exe_cmd))) {
				if (flags & ECORE_EXE_PIPE_ERROR) {	/* Setup the error stuff. */
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_error,
							    F_SETFL,
							    O_NONBLOCK),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_error,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_error_x,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					{
						exe->error_fd_handler =
						    ecore_main_fd_handler_add
						    (exe->child_fd_error,
						     ECORE_FD_READ,
						     _ecore_exe_data_error_handler,
						     exe, NULL, NULL);
						if (!exe->error_fd_handler)
							ok = 0;
					}
				}
				if (ok && (flags & ECORE_EXE_PIPE_READ)) {	/* Setup the read stuff. */
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_read,
							    F_SETFL,
							    O_NONBLOCK),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_read,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_read_x,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					{
						exe->read_fd_handler =
						    ecore_main_fd_handler_add
						    (exe->child_fd_read,
						     ECORE_FD_READ,
						     _ecore_exe_data_read_handler,
						     exe, NULL, NULL);
						if (!exe->read_fd_handler)
							ok = 0;
					}
				}
				if (ok && (flags & ECORE_EXE_PIPE_WRITE)) {	/* Setup the write stuff. */
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_write,
							    F_SETFL,
							    O_NONBLOCK),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_write,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					E_IF_NO_ERRNO(result,
						      fcntl(exe->
							    child_fd_write_x,
							    F_SETFD,
							    FD_CLOEXEC),
						      ok) {
					}
					{
						exe->write_fd_handler =
						    ecore_main_fd_handler_add
						    (exe->child_fd_write,
						     ECORE_FD_WRITE,
						     _ecore_exe_data_write_handler,
						     exe, NULL, NULL);
						if (exe->write_fd_handler)
							ecore_main_fd_handler_active_set(exe->write_fd_handler, 0);	/* Nothing to write to start with. */
						else
							ok = 0;
					}
				}

				exes =
				    (Ecore_Exe *)
				    eina_inlist_append(EINA_INLIST_GET
						       (exes),
						       EINA_INLIST_GET
						       (exe));
				n = 0;
			} else
				ok = 0;
		} else
			ok = 0;
	}

	if (!ok) {		/* Something went wrong, so pull down everything. */
		if (exe->pid)
			ecore_exe_terminate(exe);
		IF_FN_DEL(ecore_exe_free, exe);
	} else {
		Ecore_Exe_Event_Add *e;

		e = _ecore_exe_event_add_new();
		e->exe = exe;
		if (e)		/* Send the event. */
			ecore_event_add(ECORE_EXE_EVENT_ADD, e,
					_ecore_exe_event_add_free, NULL);
		/* INF("Running as %d for %s.\n", exe->pid, exe->cmd); */
	}

	errno = n;
	return exe;
}

/**
 * Defines a function to be called before really freeing the handle data.
 *
 * This might be useful for language bindings such as Python and Perl
 * that need to deallocate wrappers associated with this handle.
 *
 * This handle should never be modified by this call. It should be
 * considered informative only. All getters are valid when the given
 * function is called back.
 *
 * @param exe The child process to attach the pre_free function.
 * @param func The function to call before @a exe is freed.
 */
EAPI void
ecore_exe_callback_pre_free_set(Ecore_Exe * exe, Ecore_Exe_Cb func)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_callback_pre_free_set");
		return;
	}
	exe->pre_free_cb = func;
}

/**
 * Sends data to the given child process which it receives on stdin.
 *
 * This function writes to a child processes standard in, with unlimited
 * buffering. This call will never block. It may fail if the system runs out
 * of memory.
 *
 * @param exe  The child process to send to
 * @param data The data to send
 * @param size The size of the data to send, in bytes
 * @return EINA_TRUE if successful, EINA_FALSE on failure.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI Eina_Bool ecore_exe_send(Ecore_Exe * exe, const void *data, int size)
{
	void *buf;

	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_send");
		return EINA_FALSE;
	}

	if (exe->close_stdin) {
		ERR("Ecore_Exe %p stdin is closed! Cannot send %d bytes from %p", exe, size, data);
		return EINA_FALSE;
	}

	if (exe->child_fd_write == -1) {
		ERR("Ecore_Exe %p created without ECORE_EXE_PIPE_WRITE! "
		    "Cannot send %d bytes from %p", exe, size, data);
		return EINA_FALSE;
	}

	buf = realloc(exe->write_data_buf, exe->write_data_size + size);
	if (!buf)
		return EINA_FALSE;

	exe->write_data_buf = buf;
	memcpy((char *) exe->write_data_buf + exe->write_data_size, data,
	       size);
	exe->write_data_size += size;

	if (exe->write_fd_handler)
		ecore_main_fd_handler_active_set(exe->write_fd_handler,
						 ECORE_FD_WRITE);

	return EINA_TRUE;
}

/**
 * The stdin of the given child process will close when the write buffer is empty.
 *
 * @param exe  The child process
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void ecore_exe_close_stdin(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_close_stdin");
		return;
	}
	exe->close_stdin = 1;
}

/**
 * Sets the auto pipe limits for the given process handle. On Windows
 * this function does nothing.
 *
 * @param   exe The given process handle.
 * @param   start_bytes limit of bytes at start of output to buffer.
 * @param   end_bytes limit of bytes at end of output to buffer.
 * @param   start_lines limit of lines at start of output to buffer.
 * @param   end_lines limit of lines at end of output to buffer.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void
ecore_exe_auto_limits_set(Ecore_Exe * exe, int start_bytes, int end_bytes,
			  int start_lines, int end_lines)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_auto_limits_set");
		return;
	}
	/* FIXME: sanitize the input. */
	exe->start_bytes = start_bytes;
	exe->end_bytes = end_bytes;
	exe->start_lines = start_lines;
	exe->end_lines = end_lines;

	/* FIXME: get this can of worms working.
	 *
	 * capture stderr & stdout internally
	 *
	 * raster and onefang keep moving the goal posts on this one.  It started out as
	 * "show users the error output if an exe fails" and is rapidly approaching
	 * "alternative method of getting the data, poll vs event driven".  Some serious
	 * thinking needs to be applied to this.  Do we really want to go that far?  If
	 * so, we should change the names.  The basic design will probably remain the
	 * same which ever way we go.  The constant goal post moving is probably due to
	 * generic design methods leading to feature creep as we inspired each other to
	 * more generic designs.  It does seem like the closer we get to poll driven,
	 * the more issues and corner cases there are.
	 *
	 * Instead of doing the usual register an event handler thing, we are ecore_exe,
	 * we can take some short cuts.  Don't send the events, just leave the exe buffers
	 * as is until the user asks for them, then return the event.
	 *
	 * start = 0,  end = 0;   clogged arteries get flushed, everything is ignored.
	 * start = -1, end = -1;  clogged arteries get transferred to internal buffers.  Actually, either == -1 means buffer everything.
	 * start = X,  end = 0;   buffer first X out of clogged arteries, flush and ignore rest.
	 * start = 0,  end = X;   circular buffer X
	 * start = X,  end = Y;   buffer first X out of clogged arteries, circular buffer Y from beginning.
	 *
	 * bytes vs lines, which ever one reaches the limit first.
	 * Before we go beyond the start+end limit, leave the end buffer empty, and store both in the start buffer, coz they overlap.
	 * After we pass the the start+end limit, insert "\n...\n" at the end of the start buffer, copy the rest to the end buffer, then store in the end buffer.
	 *
	 * Other issues -
	 * Spank programmer for polling data if polling is not turned on.
	 * Spank programmer for setting up event callbacks if polling is turned on.
	 * Spank programmer for freeing the event data if it came from the event system, as that autofrees.
	 * Spank the programmer if they try to set the limits bigger than what has been gathered & ignored already, coz they just lost data.
	 * Spank onefang and raster for opening this can of worms.
	 * Should we have separate out/err limits?
	 * Should we remove from the internal buffer the data that was delivered already?
	 * If so, what to do about limits, start, and end?  They could loose their meaning.
	 */
}

/**
 * Gets the auto pipe data for the given process handle
 *
 * @param   exe The given process handle.
 * @param   flags   Is this a ECORE_EXE_PIPE_READ or ECORE_EXE_PIPE_ERROR?
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI Ecore_Exe_Event_Data *ecore_exe_event_data_get(Ecore_Exe * exe,
						    Ecore_Exe_Flags flags)
{
	Ecore_Exe_Event_Data *e = NULL;
	int is_buffered = 0;
	unsigned char *inbuf;
	int inbuf_num;

	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_event_data_get");
		return NULL;
	}

	/* Sort out what sort of event we are. */
	if (flags & ECORE_EXE_PIPE_READ) {
		flags = ECORE_EXE_PIPE_READ;
		if (exe->flags & ECORE_EXE_PIPE_READ_LINE_BUFFERED)
			is_buffered = 1;
	} else {
		flags = ECORE_EXE_PIPE_ERROR;
		if (exe->flags & ECORE_EXE_PIPE_ERROR_LINE_BUFFERED)
			is_buffered = 1;
	}

	/* Get the data. */
	if (flags & ECORE_EXE_PIPE_READ) {
		inbuf = exe->read_data_buf;
		inbuf_num = exe->read_data_size;
		exe->read_data_buf = NULL;
		exe->read_data_size = 0;
	} else {
		inbuf = exe->error_data_buf;
		inbuf_num = exe->error_data_size;
		exe->error_data_buf = NULL;
		exe->error_data_size = 0;
	}

	e = calloc(1, sizeof(Ecore_Exe_Event_Data));
	if (e) {
		e->exe = exe;
		e->data = inbuf;
		e->size = inbuf_num;

		if (is_buffered) {	/* Deal with line buffering. */
			int max = 0;
			int count = 0;
			int i;
			int last = 0;
			char *c;

			c = (char *) inbuf;
			for (i = 0; i < inbuf_num; i++) {	/* Find the lines. */
				if (inbuf[i] == '\n') {
					if (count >= max) {
						/* In testing, the lines seem to arrive in batches of 500 to 1000 lines at most, roughly speaking. */
						max += 10;	/* FIXME: Maybe keep track of the largest number of lines ever sent, and add half that many instead of 10. */
						e->lines = realloc(e->lines, sizeof(Ecore_Exe_Event_Data_Line) * (max + 1));	/* Allow room for the NULL termination. */
					}
					/* raster said to leave the line endings as line endings, however -
					 * This is line buffered mode, we are not dealing with binary here, but lines.
					 * If we are not dealing with binary, we must be dealing with ASCII, unicode, or some other text format.
					 * Thus the user is most likely gonna deal with this text as strings.
					 * Thus the user is most likely gonna pass this data to str functions.
					 * rasters way - the endings are always gonna be '\n';  onefangs way - they will always be '\0'
					 * We are handing them the string length as a convenience.
					 * Thus if they really want it in raw format, they can e->lines[i].line[e->lines[i].size - 1] = '\n'; easily enough.
					 * In the default case, we can do this conversion quicker than the user can, as we already have the index and pointer.
					 * Let's make it easy on them to use these as standard C strings.
					 *
					 * onefang is proud to announce that he has just set a new personal record for the
					 * most over documentation of a simple assignment statement.  B-)
					 */
					inbuf[i] = '\0';
					e->lines[count].line = c;
					e->lines[count].size = i - last;
					last = i + 1;
					c = (char *) &inbuf[last];
					count++;
				}
			}
			if (count == 0) {	/* No lines to send, cancel the event. */
				_ecore_exe_event_exe_data_free(NULL, e);
				e = NULL;
			} else {	/* NULL terminate the array, so that people know where the end is. */

				e->lines[count].line = NULL;
				e->lines[count].size = 0;
			}
			if (i > last) {	/* Partial line left over, save it for next time. */
				if (e)
					e->size = last;
				if (flags & ECORE_EXE_PIPE_READ) {
					exe->read_data_size = i - last;
					exe->read_data_buf =
					    malloc(exe->read_data_size);
					memcpy(exe->read_data_buf, c,
					       exe->read_data_size);
				} else {
					exe->error_data_size = i - last;
					exe->error_data_buf =
					    malloc(exe->error_data_size);
					memcpy(exe->error_data_buf, c,
					       exe->error_data_size);
				}
			}
		}
	}

	return e;
}

/**
 * Sets the string tag for the given process handle
 *
 * @param   exe The given process handle.
 * @param   tag The string tag to set on the process handle.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void ecore_exe_tag_set(Ecore_Exe * exe, const char *tag)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_tag_set");
		return;
	}
	IF_FREE(exe->tag);
	if (tag)
		exe->tag = strdup(tag);
	else
		exe->tag = NULL;
}

/**
 * Retrieves the tag attached to the given process handle. There is no need to
 * free it as it just returns the internal pointer value. This value is only
 * valid as long as the @p exe is valid or until the tag is set to something
 * else on this @p exe.
 *
 * @param   exe The given process handle.
 * @return The string attached to @p exe. It is a handle to existing
 *         internal string and should not be modified, use
 *         ecore_exe_tag_set() to change it. It might be @c NULL.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI const char *ecore_exe_tag_get(const Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_tag_get");
		return NULL;
	}
	return exe->tag;
}

/**
 * Frees the given process handle.
 *
 * Note that the process that the handle represents is unaffected by this
 * function.
 *
 * @param   exe The given process handle.
 * @return  The data attached to the handle when @ref ecore_exe_run was
 *          called.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void *ecore_exe_free(Ecore_Exe * exe)
{
	void *data;
	int ok = 0;
	int result;

	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_free");
		return NULL;
	}

	data = exe->data;

	if (exe->pre_free_cb)
		exe->pre_free_cb(data, exe);

	if (exe->doomsday_clock) {
		struct _ecore_exe_dead_exe *dead;

		ecore_timer_del(exe->doomsday_clock);
		exe->doomsday_clock = NULL;
		dead = exe->doomsday_clock_dead;
		if (dead) {
			IF_FREE(dead->cmd);
			free(dead);
			exe->doomsday_clock_dead = NULL;
		}
	}
	IF_FN_DEL(ecore_main_fd_handler_del, exe->write_fd_handler);
	IF_FN_DEL(ecore_main_fd_handler_del, exe->read_fd_handler);
	IF_FN_DEL(ecore_main_fd_handler_del, exe->error_fd_handler);
	if (exe->child_fd_write_x != -1)
		E_NO_ERRNO(result, close(exe->child_fd_write_x), ok);
	if (exe->child_fd_read_x != -1)
		E_NO_ERRNO(result, close(exe->child_fd_read_x), ok);
	if (exe->child_fd_error_x != -1)
		E_NO_ERRNO(result, close(exe->child_fd_error_x), ok);
	if (exe->child_fd_write != -1)
		E_NO_ERRNO(result, close(exe->child_fd_write), ok);
	if (exe->child_fd_read != -1)
		E_NO_ERRNO(result, close(exe->child_fd_read), ok);
	if (exe->child_fd_error != -1)
		E_NO_ERRNO(result, close(exe->child_fd_error), ok);
	IF_FREE(exe->write_data_buf);
	IF_FREE(exe->read_data_buf);
	IF_FREE(exe->error_data_buf);
	IF_FREE(exe->cmd);

	exes =
	    (Ecore_Exe *) eina_inlist_remove(EINA_INLIST_GET(exes),
					     EINA_INLIST_GET(exe));
	ECORE_MAGIC_SET(exe, ECORE_MAGIC_NONE);
	IF_FREE(exe->tag);
	free(exe);
	return data;
}

/**
 * Frees the given event data.
 *
 * @param   e The given event data.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void ecore_exe_event_data_free(Ecore_Exe_Event_Data * e)
{
	if (!e)
		return;
	IF_FREE(e->lines);
	IF_FREE(e->data);
	free(e);
}

/**
 * Retrieves the process ID of the given spawned process.
 * @param   exe Handle to the given spawned process.
 * @return  The process ID on success.  @c -1 otherwise.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI pid_t ecore_exe_pid_get(const Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_pid_get");
		return -1;
	}
	return exe->pid;
}

/**
 * Retrieves the command of the given spawned process.
 * @param   exe Handle to the given spawned process.
 * @return The command on success.  NULL otherwise. This string is the
 *         pointer to the internal value and must not be modified in
 *         any way.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI const char *ecore_exe_cmd_get(const Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_cmd_get");
		return NULL;
	}
	return exe->cmd;
}

/**
 * Retrieves the data attached to the given process handle.
 * @param   exe The given process handle.
 * @return The data pointer attached to @p exe Given to
 *         ecore_exe_run() or ecore_exe_pipe_run()
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI void *ecore_exe_data_get(const Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_data_get");
		return NULL;
	}
	return exe->data;
}

/**
 * Retrieves the flags attached to the given process handle.
 * @param   exe The given process handle.
 * @return  The flags attached to @p exe.
 * @ingroup Ecore_Exe_Basic_Group
 */
EAPI Ecore_Exe_Flags ecore_exe_flags_get(const Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_data_get");
		return 0;
	}
	return exe->flags;
}

/**
 * @defgroup Ecore_Exe_Signal_Group Spawned Process Signal Functions
 *
 * Functions that send signals to spawned processes.
 */

/**
 * Pauses the given process by sending it a @c SIGSTOP signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_pause(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_pause");
		return;
	}
	kill(exe->pid, SIGSTOP);
}

/**
 * Continues the given paused process by sending it a @c SIGCONT signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_continue(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_continue");
		return;
	}
	kill(exe->pid, SIGCONT);
}

/**
 * Sends the given spawned process a interrupt (@c SIGINT) signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_interrupt(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_interrupt");
		return;
	}
	_ecore_exe_dead_attach(exe);
	kill(exe->pid, SIGINT);
}

/**
 * Sends the given spawned process a quit (@c SIGQUIT) signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_quit(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_quit");
		return;
	}
	_ecore_exe_dead_attach(exe);
	kill(exe->pid, SIGQUIT);
}

/**
 * Sends the given spawned process a terminate (@c SIGTERM) signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_terminate(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE,
				 "ecore_exe_terminate");
		return;
	}
	_ecore_exe_dead_attach(exe);
	INF("Sending TERM signal to %s (%d).", exe->cmd, exe->pid);
	kill(exe->pid, SIGTERM);
}

/**
 * Kills the given spawned process by sending it a @c SIGKILL signal.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_kill(Ecore_Exe * exe)
{
	struct _ecore_exe_dead_exe *dead;

	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_kill");
		return;
	}

	dead = calloc(1, sizeof(struct _ecore_exe_dead_exe));
	if (dead) {
		dead->pid = exe->pid;
		dead->cmd = strdup(exe->cmd);
		IF_FN_DEL(ecore_timer_del, exe->doomsday_clock);
		exe->doomsday_clock =
		    ecore_timer_add(10.0,
				    _ecore_exe_make_sure_its_really_dead,
				    dead);
	}

	INF("Sending KILL signal to %s (%d).", exe->cmd, exe->pid);
	kill(exe->pid, SIGKILL);
}

/**
 * Sends a @c SIGUSR signal to the given spawned process.
 * @param   exe Process handle to the given process.
 * @param   num The number user signal to send.  Must be either 1 or 2, or
 *              the signal will be ignored.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_signal(Ecore_Exe * exe, int num)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_signal");
		return;
	}
	if (num == 1)
		kill(exe->pid, SIGUSR1);
	else if (num == 2)
		kill(exe->pid, SIGUSR2);
}

/**
 * Sends a @c SIGHUP signal to the given spawned process.
 * @param   exe Process handle to the given process.
 * @ingroup Ecore_Exe_Signal_Group
 */
EAPI void ecore_exe_hup(Ecore_Exe * exe)
{
	if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE)) {
		ECORE_MAGIC_FAIL(exe, ECORE_MAGIC_EXE, "ecore_exe_hup");
		return;
	}
	kill(exe->pid, SIGHUP);
}

static Ecore_Exe *_ecore_exe_is_it_alive(pid_t pid)
{
	Ecore_Exe *exe = NULL;

	/* FIXME: There is no nice, safe, OS independent way to tell if a
	 * particular PID is still alive.  I have written code to do so
	 * for my urunlevel busybox applet (http://urunlevel.sourceforge.net/),
	 * but it's for linux only, and still not guaranteed.
	 *
	 * So for now, we just check that a valid Ecore_Exe structure
	 * exists for it.  Even that is not a guarantee, as the structure
	 * can be freed without killing the process.
	 *
	 * I think we can safely put exe's into two categories, those users
	 * that care about the life of the exe, and the run and forget type.
	 * The run and forget type starts up the exe, then free's the
	 * Ecore_Exe structure straight away.  They can never call any of
	 * the functions that can call this, so we don't worry about them.
	 *
	 * Those user's that care about the life of exe's will keep the
	 * Ecore_Exe structure around, terminate them eventually, or
	 * register for exit events.  For these ones the assumption
	 * that valid Ecore_Exe struct == live exe is almost valid.
	 *
	 * I will probably copy my urunlevel code into here someday.
	 */
	exe = _ecore_exe_find(pid);
	if (exe) {
		if (!ECORE_MAGIC_CHECK(exe, ECORE_MAGIC_EXE))
			exe = NULL;
	}

	return exe;
}

static Eina_Bool _ecore_exe_make_sure_its_dead(void *data)
{
	struct _ecore_exe_dead_exe *dead;

	dead = data;
	if (dead) {
		Ecore_Exe *exe = NULL;

		if ((exe = _ecore_exe_is_it_alive(dead->pid))) {
			if (dead->cmd)
				INF("Sending KILL signal to allegedly dead %s (%d).", dead->cmd, dead->pid);
			else
				INF("Sending KILL signal to allegedly dead PID %d.", dead->pid);
			exe->doomsday_clock =
			    ecore_timer_add(10.0,
					    _ecore_exe_make_sure_its_really_dead,
					    dead);
			kill(dead->pid, SIGKILL);
		} else {
			IF_FREE(dead->cmd);
			free(dead);
		}
	}
	return ECORE_CALLBACK_CANCEL;
}

static Eina_Bool _ecore_exe_make_sure_its_really_dead(void *data)
{
	struct _ecore_exe_dead_exe *dead;

	dead = data;
	if (dead) {
		Ecore_Exe *exe = NULL;

		if ((exe = _ecore_exe_is_it_alive(dead->pid))) {
			ERR("RUN!  The zombie wants to eat your brains!  And your CPU!");
			if (dead->cmd)
				INF("%s (%d) is not really dead.",
				    dead->cmd, dead->pid);
			else
				INF("PID %d is not really dead.",
				    dead->pid);
			exe->doomsday_clock = NULL;
		}
		IF_FREE(dead->cmd);
		free(dead);
	}
	return ECORE_CALLBACK_CANCEL;
}

void _ecore_exe_init(void)
{
	ECORE_EXE_EVENT_ADD = ecore_event_type_new();
	ECORE_EXE_EVENT_DEL = ecore_event_type_new();
	ECORE_EXE_EVENT_DATA = ecore_event_type_new();
	ECORE_EXE_EVENT_ERROR = ecore_event_type_new();
}

void _ecore_exe_shutdown(void)
{
	while (exes)
		ecore_exe_free(exes);
}

Ecore_Exe *_ecore_exe_find(pid_t pid)
{
	Ecore_Exe *exe;

	EINA_INLIST_FOREACH(exes, exe) {
		if (exe->pid == pid)
			return exe;
	}
	return NULL;
}

Ecore_Timer *_ecore_exe_doomsday_clock_get(Ecore_Exe * exe)
{
	return exe->doomsday_clock;
}

void _ecore_exe_doomsday_clock_set(Ecore_Exe * exe, Ecore_Timer * dc)
{
	exe->doomsday_clock = dc;
}

static inline void
_ecore_exe_exec_it(const char *exe_cmd, Ecore_Exe_Flags flags)
{
	char use_sh = 1;
	char *buf = NULL;
	char **args = NULL;
	int save_errno = 0;

	/* So what is this doing?
	 *
	 * We are trying to avoid wrapping the exe call with /bin/sh -c.
	 * We conservatively search for certain shell meta characters,
	 * If we don't find them, we can call the exe directly.
	 */
	if (!strpbrk(exe_cmd, "|&;<>()$`\\\"'*?#")) {
		char *token;
		char pre_command = 1;
		int num_tokens = 0;

		if (!(buf = strdup(exe_cmd)))
			return;

		token = strtok(buf, " \t\n\v");
		while (token) {
			if (token[0] == '~')
				break;
			if (pre_command) {
				if (token[0] == '[')
					break;
				if (strchr(token, '='))
					break;
				else
					pre_command = 0;
			}
			num_tokens++;
			token = strtok(NULL, " \t\n\v");
		}
		IF_FREE(buf);
		if ((!token) && (num_tokens)) {
			int i = 0;

			if (!(buf = strdup(exe_cmd)))
				return;

			token = strtok(buf, " \t\n\v");
			use_sh = 0;
			if (!
			    (args =
			     (char **) calloc(num_tokens + 1,
					      sizeof(char *)))) {
				IF_FREE(buf);
				return;
			}
			for (i = 0; i < num_tokens; i++) {
				if (token)
					args[i] = token;
				token = strtok(NULL, " \t\n\v");
			}
			args[num_tokens] = NULL;
		}
	}

	if (!(flags & ECORE_EXE_NOT_LEADER))
		setsid();
	if ((flags & ECORE_EXE_USE_SH)) {
		errno = 0;
		execl("/bin/sh", "/bin/sh", "-c", exe_cmd, (char *) NULL);
	} else if (use_sh) {	/* We have to use a shell to run this. */
		if (!shell) {	/* Find users preferred shell. */
			shell = getenv("SHELL");
			if (!shell)
				shell = "/bin/sh";
		}
		errno = 0;
		execl(shell, shell, "-c", exe_cmd, (char *) NULL);
	} else {		/* We can run this directly. */
		errno = 0;
		execvp(args[0], args);
	}

	save_errno = errno;
	IF_FREE(buf);
	IF_FREE(args);
	errno = save_errno;
	return;
}

static Eina_Bool
_ecore_exe_data_generic_handler(void *data, Ecore_Fd_Handler * fd_handler,
				Ecore_Exe_Flags flags)
{
	Ecore_Exe *exe;
	int child_fd;
	int event_type;

	exe = data;

	/* Sort out what sort of handler we are. */
	if (flags & ECORE_EXE_PIPE_READ) {
		flags = ECORE_EXE_PIPE_READ;
		event_type = ECORE_EXE_EVENT_DATA;
		child_fd = exe->child_fd_read;
	} else {
		flags = ECORE_EXE_PIPE_ERROR;
		event_type = ECORE_EXE_EVENT_ERROR;
		child_fd = exe->child_fd_error;
	}

	if ((fd_handler)
	    &&
	    (ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)))
	{
		unsigned char *inbuf;
		int inbuf_num;

		/* Get any left over data from last time. */
		if (flags & ECORE_EXE_PIPE_READ) {
			inbuf = exe->read_data_buf;
			inbuf_num = exe->read_data_size;
			exe->read_data_buf = NULL;
			exe->read_data_size = 0;
		} else {
			inbuf = exe->error_data_buf;
			inbuf_num = exe->error_data_size;
			exe->error_data_buf = NULL;
			exe->error_data_size = 0;
		}

		for (;;) {
			int num, lost_exe;
			char buf[READBUFSIZ];

			lost_exe = 0;
			errno = 0;
			if ((num = read(child_fd, buf, READBUFSIZ)) < 1)
				/* FIXME: SPEED/SIZE TRADE OFF - add a smaller READBUFSIZE
				 * (currently 64k) to inbuf, use that instead of buf, and
				 * save ourselves a memcpy(). */
			{
				lost_exe = ((errno == EIO) ||
					    (errno == EBADF) ||
					    (errno == EPIPE) ||
					    (errno == EINVAL)
					    || (errno == ENOSPC));
				if ((errno != EAGAIN) && (errno != EINTR))
					perror
					    ("_ecore_exe_generic_handler() read problem ");
			}
			if (num > 0) {	/* data got read. */
				inbuf = realloc(inbuf, inbuf_num + num);
				memcpy(inbuf + inbuf_num, buf, num);
				inbuf_num += num;
			} else {	/* No more data to read. */
				if (inbuf) {
					Ecore_Exe_Event_Data *e;

					/* Stash the data away for later. */
					if (flags & ECORE_EXE_PIPE_READ) {
						exe->read_data_buf = inbuf;
						exe->read_data_size =
						    inbuf_num;
					} else {
						exe->error_data_buf =
						    inbuf;
						exe->error_data_size =
						    inbuf_num;
					}

					if (!
					    (exe->
					     flags & ECORE_EXE_PIPE_AUTO))
					{
						e = ecore_exe_event_data_get(exe, flags);
						if (e)	/* Send the event. */
							ecore_event_add
							    (event_type, e,
							     _ecore_exe_event_exe_data_free,
							     NULL);
					}
				}
				if (lost_exe) {
					if (flags & ECORE_EXE_PIPE_READ) {
						if (exe->read_data_size)
							INF("There are %d bytes left unsent from the dead exe %s.", exe->read_data_size, exe->cmd);
					} else {
						if (exe->error_data_size)
							INF("There are %d bytes left unsent from the dead exe %s.", exe->error_data_size, exe->cmd);
					}
					/* Thought about this a bit.  If the exe has actually
					 * died, this won't do any harm as it must have died
					 * recently and the pid has not had a chance to recycle.
					 * It is also a paranoid catchall, coz the usual ecore_signal
					 * mechenism should kick in.  But let's give it a good
					 * kick in the head anyway.
					 */
					ecore_exe_terminate(exe);
				}
				break;
			}
		}
	}

	return ECORE_CALLBACK_RENEW;
}

static Eina_Bool
_ecore_exe_data_error_handler(void *data, Ecore_Fd_Handler * fd_handler)
{
	return _ecore_exe_data_generic_handler(data, fd_handler,
					       ECORE_EXE_PIPE_ERROR);
}

static Eina_Bool
_ecore_exe_data_read_handler(void *data, Ecore_Fd_Handler * fd_handler)
{
	return _ecore_exe_data_generic_handler(data, fd_handler,
					       ECORE_EXE_PIPE_READ);
}

static Eina_Bool
_ecore_exe_data_write_handler(void *data,
			      Ecore_Fd_Handler * fd_handler __UNUSED__)
{
	Ecore_Exe *exe;

	exe = data;
	if ((exe->write_fd_handler) &&
	    (ecore_main_fd_handler_active_get
	     (exe->write_fd_handler, ECORE_FD_WRITE)))
		_ecore_exe_flush(exe);

	/* If we have sent all there is to send, and we need to close the pipe, then close it. */
	if ((exe->close_stdin == 1)
	    && (exe->write_data_size == exe->write_data_offset)) {
		int ok = 0;
		int result;

		INF("Closing stdin for %s", exe->cmd);
		/* if (exe->child_fd_write != -1)  E_NO_ERRNO(result, fsync(exe->child_fd_write), ok);   This a) doesn't work, and b) isn't needed. */
		IF_FN_DEL(ecore_main_fd_handler_del,
			  exe->write_fd_handler);
		if (exe->child_fd_write != -1)
			E_NO_ERRNO(result, close(exe->child_fd_write), ok);
		exe->child_fd_write = -1;
		IF_FREE(exe->write_data_buf);
	}

	return ECORE_CALLBACK_RENEW;
}

static void _ecore_exe_flush(Ecore_Exe * exe)
{
	int count;

	/* check whether we need to write anything at all. */
	if ((exe->child_fd_write == -1) || (!exe->write_data_buf))
		return;
	if (exe->write_data_size == exe->write_data_offset)
		return;

	count = write(exe->child_fd_write,
		      (char *) exe->write_data_buf +
		      exe->write_data_offset,
		      exe->write_data_size - exe->write_data_offset);
	if (count < 1) {
		if (errno == EIO || errno == EBADF || errno == EPIPE || errno == EINVAL || errno == ENOSPC) {	/* we lost our exe! */
			ecore_exe_terminate(exe);
			if (exe->write_fd_handler)
				ecore_main_fd_handler_active_set(exe->
								 write_fd_handler,
								 0);
		}
	} else {
		exe->write_data_offset += count;
		if (exe->write_data_offset >= exe->write_data_size) {	/* Nothing left to write, clean up. */
			exe->write_data_size = 0;
			exe->write_data_offset = 0;
			IF_FREE(exe->write_data_buf);
			if (exe->write_fd_handler)
				ecore_main_fd_handler_active_set(exe->
								 write_fd_handler,
								 0);
		}
	}
}

static void _ecore_exe_event_exe_data_free(void *data __UNUSED__, void *ev)
{
	Ecore_Exe_Event_Data *e;

	e = ev;
	ecore_exe_event_data_free(e);
}

static Ecore_Exe_Event_Add *_ecore_exe_event_add_new(void)
{
	Ecore_Exe_Event_Add *e;

	e = calloc(1, sizeof(Ecore_Exe_Event_Add));
	return e;
}

static void _ecore_exe_event_add_free(void *data __UNUSED__, void *ev)
{
	Ecore_Exe_Event_Add *e;

	e = ev;
	free(e);
}

void *_ecore_exe_event_del_new(void)
{
	Ecore_Exe_Event_Del *e;

	e = calloc(1, sizeof(Ecore_Exe_Event_Del));
	return e;
}

void _ecore_exe_event_del_free(void *data __UNUSED__, void *ev)
{
	Ecore_Exe_Event_Del *e;

	e = ev;
	if (e->exe)
		ecore_exe_free(e->exe);
	free(e);
}

static void _ecore_exe_dead_attach(Ecore_Exe * exe)
{
	struct _ecore_exe_dead_exe *dead;

	if (exe->doomsday_clock_dead)
		return;
	dead = calloc(1, sizeof(struct _ecore_exe_dead_exe));
	if (dead) {
		dead->pid = exe->pid;
		dead->cmd = strdup(exe->cmd);
		IF_FN_DEL(ecore_timer_del, exe->doomsday_clock);
		exe->doomsday_clock =
		    ecore_timer_add(10.0, _ecore_exe_make_sure_its_dead,
				    dead);
		exe->doomsday_clock_dead = dead;
	}
}
