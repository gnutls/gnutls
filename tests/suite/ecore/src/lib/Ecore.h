#ifndef _ECORE_H
#define _ECORE_H

#ifdef _MSC_VER
#include <Evil.h>
#endif

#include <Eina.h>

#ifdef EAPI
#undef EAPI
#endif

#ifdef _WIN32
#ifdef EFL_ECORE_BUILD
#ifdef DLL_EXPORT
#define EAPI __declspec(dllexport)
#else
#define EAPI
#endif				/* ! DLL_EXPORT */
#else
#define EAPI __declspec(dllimport)
#endif				/* ! EFL_ECORE_BUILD */
#else
#ifdef __GNUC__
#if __GNUC__ >= 4
#define EAPI __attribute__ ((visibility("default")))
#else
#define EAPI
#endif
#else
#define EAPI
#endif
#endif				/* ! _WIN32 */

/**
 * @file Ecore.h
 * @brief The file that provides the program utility, main loop and timer
 *        functions.
 *
 * This header provides the Ecore event handling loop.  For more
 * details, see @ref Ecore_Main_Loop_Group.
 *
 * For the main loop to be of any use, you need to be able to add events
 * and event handlers.  Events for file descriptor events are covered in
 * @ref Ecore_FD_Handler_Group.
 *
 * Time functions are covered in @ref Ecore_Time_Group.
 *
 * There is also provision for callbacks for when the loop enters or
 * exits an idle state. See @ref Idle_Group for more information.
 *
 * Functions are also provided for spawning child processes using fork.
 * See @ref Ecore_Exe_Basic_Group and @ref Ecore_Exe_Signal_Group for
 * more details.
 */

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#include <signal.h>
#endif

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECORE_VERSION_MAJOR 1
#define ECORE_VERSION_MINOR 0

	typedef struct _Ecore_Version {
		int major;
		int minor;
		int micro;
		int revision;
	} Ecore_Version;

	EAPI extern Ecore_Version *ecore_version;

#define ECORE_CALLBACK_CANCEL EINA_FALSE /**< Return value to remove a callback */
#define ECORE_CALLBACK_RENEW EINA_TRUE	/**< Return value to keep a callback */

#define ECORE_CALLBACK_PASS_ON EINA_TRUE /**< Return value to pass event to next handler */
#define ECORE_CALLBACK_DONE EINA_FALSE /**< Return value to stop event handling */

#define ECORE_EVENT_NONE            0
#define ECORE_EVENT_SIGNAL_USER     1 /**< User signal event */
#define ECORE_EVENT_SIGNAL_HUP      2 /**< Hup signal event */
#define ECORE_EVENT_SIGNAL_EXIT     3 /**< Exit signal event */
#define ECORE_EVENT_SIGNAL_POWER    4 /**< Power signal event */
#define ECORE_EVENT_SIGNAL_REALTIME 5 /**< Realtime signal event */
#define ECORE_EVENT_COUNT           6

#define ECORE_EXE_PRIORITY_INHERIT 9999

	EAPI extern int ECORE_EXE_EVENT_ADD;
					/**< A child process has been added */
	EAPI extern int ECORE_EXE_EVENT_DEL;
					/**< A child process has been deleted (it exited, naming consistent with the rest of ecore). */
	EAPI extern int ECORE_EXE_EVENT_DATA;
					 /**< Data from a child process. */
	EAPI extern int ECORE_EXE_EVENT_ERROR;
					  /**< Errors from a child process. */

	enum _Ecore_Fd_Handler_Flags {
		ECORE_FD_READ = 1,
			   /**< Fd Read mask */
		ECORE_FD_WRITE = 2,
			    /**< Fd Write mask */
		ECORE_FD_ERROR = 4
			   /**< Fd Error mask */
	};
	typedef enum _Ecore_Fd_Handler_Flags Ecore_Fd_Handler_Flags;

	enum _Ecore_Exe_Flags {	/* flags for executing a child with its stdin and/or stdout piped back */
		    ECORE_EXE_PIPE_READ = 1,
				 /**< Exe Pipe Read mask */
		ECORE_EXE_PIPE_WRITE = 2,
				  /**< Exe Pipe Write mask */
		ECORE_EXE_PIPE_ERROR = 4,
				  /**< Exe Pipe error mask */
		ECORE_EXE_PIPE_READ_LINE_BUFFERED = 8,
					       /**< Reads are buffered until a newline and delivered 1 event per line */
		ECORE_EXE_PIPE_ERROR_LINE_BUFFERED = 16,
						 /**< Errors are buffered until a newline and delivered 1 event per line */
		ECORE_EXE_PIPE_AUTO = 32,
				  /**< stdout and stderr are buffered automatically */
		ECORE_EXE_RESPAWN = 64,
				/**< FIXME: Exe is restarted if it dies */
		ECORE_EXE_USE_SH = 128,
				/**< Use /bin/sh to run the command. */
		ECORE_EXE_NOT_LEADER = 256
				   /**< Do not use setsid() to have the executed process be its own session leader */
	};
	typedef enum _Ecore_Exe_Flags Ecore_Exe_Flags;

	enum _Ecore_Exe_Win32_Priority {
		ECORE_EXE_WIN32_PRIORITY_IDLE,
				      /**< Idle priority, for monitoring the system */
		ECORE_EXE_WIN32_PRIORITY_BELOW_NORMAL,
					      /**< Below default priority */
		ECORE_EXE_WIN32_PRIORITY_NORMAL,
					/**< Default priority */
		ECORE_EXE_WIN32_PRIORITY_ABOVE_NORMAL,
					      /**< Above default priority */
		ECORE_EXE_WIN32_PRIORITY_HIGH,
				      /**< High priority, use with care as other threads in the system will not get processor time */
		ECORE_EXE_WIN32_PRIORITY_REALTIME
					 /**< Realtime priority, should be almost never used as it can interrupt system threads that manage mouse input, keyboard input, and background disk flushing */
	};
	typedef enum _Ecore_Exe_Win32_Priority Ecore_Exe_Win32_Priority;

	enum _Ecore_Poller_Type {	/* Poller types */
		    ECORE_POLLER_CORE = 0
			      /**< The core poller interval */
	};
	typedef enum _Ecore_Poller_Type Ecore_Poller_Type;

	typedef struct _Ecore_Exe Ecore_Exe;		  /**< A handle for spawned processes */
	typedef struct _Ecore_Timer Ecore_Timer;	    /**< A handle for timers */
	typedef struct _Ecore_Idler Ecore_Idler;	    /**< A handle for idlers */
	typedef struct _Ecore_Idle_Enterer Ecore_Idle_Enterer;	   /**< A handle for idle enterers */
	typedef struct _Ecore_Idle_Exiter Ecore_Idle_Exiter;	  /**< A handle for idle exiters */
	typedef struct _Ecore_Fd_Handler Ecore_Fd_Handler;	 /**< A handle for Fd handlers */
	typedef struct _Ecore_Win32_Handler Ecore_Win32_Handler;    /**< A handle for HANDLE handlers on Windows */
	typedef struct _Ecore_Event_Handler Ecore_Event_Handler;    /**< A handle for an event handler */
	typedef struct _Ecore_Event_Filter Ecore_Event_Filter;	   /**< A handle for an event filter */
	typedef struct _Ecore_Event Ecore_Event;	    /**< A handle for an event */
	typedef struct _Ecore_Animator Ecore_Animator;	       /**< A handle for animators */
	typedef struct _Ecore_Pipe Ecore_Pipe;		   /**< A handle for pipes */
	typedef struct _Ecore_Poller Ecore_Poller;	     /**< A handle for pollers */
	typedef struct _Ecore_Event_Signal_User Ecore_Event_Signal_User;/**< User signal event */
	typedef struct _Ecore_Event_Signal_Hup Ecore_Event_Signal_Hup; /**< Hup signal event */
	typedef struct _Ecore_Event_Signal_Exit Ecore_Event_Signal_Exit;/**< Exit signal event */
	typedef struct _Ecore_Event_Signal_Power Ecore_Event_Signal_Power;
									 /**< Power signal event */
	typedef struct _Ecore_Event_Signal_Realtime Ecore_Event_Signal_Realtime;
									    /**< Realtime signal event */
	typedef struct _Ecore_Exe_Event_Add Ecore_Exe_Event_Add;    /**< Spawned Exe add event */
	typedef struct _Ecore_Exe_Event_Del Ecore_Exe_Event_Del;    /**< Spawned Exe exit event */
	typedef struct _Ecore_Exe_Event_Data_Line Ecore_Exe_Event_Data_Line;
									  /**< Lines from a child process */
	typedef struct _Ecore_Exe_Event_Data Ecore_Exe_Event_Data;   /**< Data from a child process */
	typedef struct _Ecore_Thread Ecore_Thread;

   /**
    * @typedef Ecore_Data_Cb Ecore_Data_Cb
    * A callback which is used to return data to the main function
    */
	typedef void *(*Ecore_Data_Cb) (void *data);
   /**
    * @typedef Ecore_Filter_Cb
    * A callback used for filtering events from the main loop.
    */
	typedef Eina_Bool(*Ecore_Filter_Cb) (void *data, void *loop_data,
					     int type, void *event);
   /**
    * @typedef Ecore_Eselect_Function Ecore_Eselect_Function
    * A function which can be used to replace select() in the main loop
    */
	typedef int (*Ecore_Select_Function) (int nfds, fd_set * readfds,
					      fd_set * writefds,
					      fd_set * exceptfds,
					      struct timeval * timeout);
   /**
    * @typedef Ecore_End_Cb Ecore_End_Cb
    * This is the callback which is called at the end of a function, usually for cleanup purposes.
    */
	typedef void (*Ecore_End_Cb) (void *user_data, void *func_data);
   /**
    * @typedef Ecore_Pipe_Cb Ecore_Pipe_Cb
    * The callback that data written to the pipe is sent to.
    */
	typedef void (*Ecore_Pipe_Cb) (void *data, void *buffer,
				       unsigned int nbyte);
   /**
    * @typedef Ecore_Exe_Cb Ecore_Exe_Cb
    * A callback to run with the associated @ref Ecore_Exe, usually for cleanup purposes.
    */
	typedef void (*Ecore_Exe_Cb) (void *data, const Ecore_Exe * exe);
   /**
    * @typedef Ecore_Event_Handler_Cb Ecore_Event_Handler_Cb
    * A callback used by the main loop to handle events of a specified type.
    */
	typedef Eina_Bool(*Ecore_Event_Handler_Cb) (void *data, int type,
						    void *event);
   /**
    * @typedef Ecore_Thread_Heavy_Cb Ecore_Thread_Heavy_Cb
    * A callback used to run cpu intensive or blocking I/O operations.
    */
	typedef void (*Ecore_Thread_Heavy_Cb) (Ecore_Thread * thread,
					       void *data);
   /**
    * @typedef Ecore_Thread_Notify_Cb Ecore_Thread_Notify_Cb
    * A callback used by the main loop to receive data sent by an @ref Ecore_Thread.
    */
	typedef void (*Ecore_Thread_Notify_Cb) (Ecore_Thread * thread,
						void *msg_data,
						void *data);
   /**
    * @typedef Ecore_Task_Cb Ecore_Task_Cb
    * A callback run for a task (timer, idler, poller, animater, etc)
    */
	typedef Eina_Bool(*Ecore_Task_Cb) (void *data);
   /**
    * @typedef Ecore_Cb Ecore_Cb
    * A generic callback called as a hook when a certain point in execution is reached.
    */
	typedef void (*Ecore_Cb) (void *data);
   /**
    * @typedef Ecore_Fd_Cb Ecore_Fd_Cb
    * A callback used by an @ref Ecore_Fd_Handler.
    */
	typedef Eina_Bool(*Ecore_Fd_Cb) (void *data,
					 Ecore_Fd_Handler * fd_handler);
   /**
    * @typedef Ecore_Fd_Prep_Cb Ecore_Fd_Prep_Cb
    * A callback used by an @ref Ecore_Fd_Handler.
    */
	typedef void (*Ecore_Fd_Prep_Cb) (void *data,
					  Ecore_Fd_Handler * fd_handler);
   /**
    * @typedef Ecore_Fd_Win32_Cb Ecore_Fd_Win32_Cb
    * A callback used by an @ref Ecore_Win32_Handler.
    */
	typedef Eina_Bool(*Ecore_Fd_Win32_Cb) (void *data,
					       Ecore_Win32_Handler * wh);


	typedef struct _Ecore_Job Ecore_Job;
					/**< A job handle */

	struct _Ecore_Event_Signal_User {
/** User signal event */
		int number;
		      /**< The signal number. Either 1 or 2 */
		void *ext_data;
			/**< Extension data - not used */

#ifndef _WIN32
		siginfo_t data;
			/**< Signal info */
#endif
	};

	struct _Ecore_Event_Signal_Hup {
/** Hup signal event */
		void *ext_data;
			/**< Extension data - not used */

#ifndef _WIN32
		siginfo_t data;
			/**< Signal info */
#endif
	};

	struct _Ecore_Event_Signal_Exit {
/** Exit request event */
		unsigned int interrupt:1;
				      /**< Set if the exit request was an interrupt  signal*/
		unsigned int quit:1;  /**< set if the exit request was a quit signal */
		unsigned int terminate:1;
				      /**< Set if the exit request was a terminate singal */
		void *ext_data;	 /**< Extension data - not used */

#ifndef _WIN32
		siginfo_t data;
			/**< Signal info */
#endif
	};

	struct _Ecore_Event_Signal_Power {
/** Power event */
		void *ext_data;
			/**< Extension data - not used */

#ifndef _WIN32
		siginfo_t data;
			/**< Signal info */
#endif
	};

	struct _Ecore_Event_Signal_Realtime {
/** Realtime event */
		int num;
		 /**< The realtime signal's number */

#ifndef _WIN32
		siginfo_t data;
			/**< Signal info */
#endif
	};

	struct _Ecore_Exe_Event_Add {
/** Process add event */
		Ecore_Exe *exe;
			/**< The handle to the added process */
		void *ext_data;
			     /**< Extension data - not used */
	};

	struct _Ecore_Exe_Event_Del {
/** Process exit event */
		pid_t pid; /**< The process ID of the process that exited */
		int exit_code;	 /**< The exit code of the process */
		Ecore_Exe *exe;
			   /**< The handle to the exited process, or NULL if not found */
		int exit_signal;   /** < The signal that caused the process to exit */
		unsigned int exited:1;
				     /** < set to 1 if the process exited of its own accord */
		unsigned int signalled:1;
				     /** < set to 1 id the process exited due to uncaught signal */
		void *ext_data;	/**< Extension data - not used */
#ifndef _WIN32
		siginfo_t data;
			    /**< Signal info */
#endif
	};

	struct _Ecore_Exe_Event_Data_Line {
/**< Lines from a child process */
		char *line;
		int size;
	};

	struct _Ecore_Exe_Event_Data {
/** Data from a child process event */
		Ecore_Exe *exe;
			/**< The handle to the process */
		void *data;
		    /**< the raw binary data from the child process that was received */
		int size;
		    /**< the size of this data in bytes */
		Ecore_Exe_Event_Data_Line *lines;
					  /**< an array of line data if line buffered, the last one has it's line member set to NULL */
	};

	EAPI int ecore_init(void);
	EAPI int ecore_shutdown(void);

	EAPI void ecore_app_args_set(int argc, const char **argv);
	EAPI void ecore_app_args_get(int *argc, char ***argv);
	EAPI void ecore_app_restart(void);

	EAPI Ecore_Event_Handler *ecore_event_handler_add(int type,
							  Ecore_Event_Handler_Cb
							  func,
							  const void
							  *data);
	EAPI void *ecore_event_handler_del(Ecore_Event_Handler *
					   event_handler);
	EAPI Ecore_Event *ecore_event_add(int type, void *ev,
					  Ecore_End_Cb func_free,
					  void *data);
	EAPI void *ecore_event_del(Ecore_Event * event);
	EAPI int ecore_event_type_new(void);
	EAPI Ecore_Event_Filter *ecore_event_filter_add(Ecore_Data_Cb
							func_start,
							Ecore_Filter_Cb
							func_filter,
							Ecore_End_Cb
							func_end,
							const void *data);
	EAPI void *ecore_event_filter_del(Ecore_Event_Filter * ef);
	EAPI int ecore_event_current_type_get(void);
	EAPI void *ecore_event_current_event_get(void);


	EAPI void ecore_exe_run_priority_set(int pri);
	EAPI int ecore_exe_run_priority_get(void);
	EAPI Ecore_Exe *ecore_exe_run(const char *exe_cmd,
				      const void *data);
	EAPI Ecore_Exe *ecore_exe_pipe_run(const char *exe_cmd,
					   Ecore_Exe_Flags flags,
					   const void *data);
	EAPI void ecore_exe_callback_pre_free_set(Ecore_Exe * exe,
						  Ecore_Exe_Cb func);
	EAPI Eina_Bool ecore_exe_send(Ecore_Exe * exe, const void *data,
				      int size);
	EAPI void ecore_exe_close_stdin(Ecore_Exe * exe);
	EAPI void ecore_exe_auto_limits_set(Ecore_Exe * exe,
					    int start_bytes, int end_bytes,
					    int start_lines,
					    int end_lines);
	EAPI Ecore_Exe_Event_Data *ecore_exe_event_data_get(Ecore_Exe *
							    exe,
							    Ecore_Exe_Flags
							    flags);
	EAPI void ecore_exe_event_data_free(Ecore_Exe_Event_Data * data);
	EAPI void *ecore_exe_free(Ecore_Exe * exe);
	EAPI pid_t ecore_exe_pid_get(const Ecore_Exe * exe);
	EAPI void ecore_exe_tag_set(Ecore_Exe * exe, const char *tag);
	EAPI const char *ecore_exe_tag_get(const Ecore_Exe * exe);
	EAPI const char *ecore_exe_cmd_get(const Ecore_Exe * exe);
	EAPI void *ecore_exe_data_get(const Ecore_Exe * exe);
	EAPI Ecore_Exe_Flags ecore_exe_flags_get(const Ecore_Exe * exe);
	EAPI void ecore_exe_pause(Ecore_Exe * exe);
	EAPI void ecore_exe_continue(Ecore_Exe * exe);
	EAPI void ecore_exe_interrupt(Ecore_Exe * exe);
	EAPI void ecore_exe_quit(Ecore_Exe * exe);
	EAPI void ecore_exe_terminate(Ecore_Exe * exe);
	EAPI void ecore_exe_kill(Ecore_Exe * exe);
	EAPI void ecore_exe_signal(Ecore_Exe * exe, int num);
	EAPI void ecore_exe_hup(Ecore_Exe * exe);

	EAPI Ecore_Idler *ecore_idler_add(Ecore_Task_Cb func,
					  const void *data);
	EAPI void *ecore_idler_del(Ecore_Idler * idler);

	EAPI Ecore_Idle_Enterer *ecore_idle_enterer_add(Ecore_Task_Cb func,
							const void *data);
	EAPI Ecore_Idle_Enterer
	    *ecore_idle_enterer_before_add(Ecore_Task_Cb func,
					   const void *data);
	EAPI void *ecore_idle_enterer_del(Ecore_Idle_Enterer *
					  idle_enterer);

	EAPI Ecore_Idle_Exiter *ecore_idle_exiter_add(Ecore_Task_Cb func,
						      const void *data);
	EAPI void *ecore_idle_exiter_del(Ecore_Idle_Exiter * idle_exiter);

	EAPI void ecore_main_loop_iterate(void);

	EAPI void ecore_main_loop_select_func_set(Ecore_Select_Function
						  func);
	EAPI void *ecore_main_loop_select_func_get(void);

	EAPI Eina_Bool ecore_main_loop_glib_integrate(void);
	EAPI void ecore_main_loop_glib_always_integrate_disable(void);

	EAPI void ecore_main_loop_begin(void);
	EAPI void ecore_main_loop_quit(void);
	EAPI Ecore_Fd_Handler *ecore_main_fd_handler_add(int fd,
							 Ecore_Fd_Handler_Flags
							 flags,
							 Ecore_Fd_Cb func,
							 const void *data,
							 Ecore_Fd_Cb
							 buf_func,
							 const void
							 *buf_data);
	EAPI void
	    ecore_main_fd_handler_prepare_callback_set(Ecore_Fd_Handler *
						       fd_handler,
						       Ecore_Fd_Prep_Cb
						       func,
						       const void *data);
	EAPI void *ecore_main_fd_handler_del(Ecore_Fd_Handler *
					     fd_handler);
	EAPI int ecore_main_fd_handler_fd_get(Ecore_Fd_Handler *
					      fd_handler);
	EAPI Eina_Bool ecore_main_fd_handler_active_get(Ecore_Fd_Handler *
							fd_handler,
							Ecore_Fd_Handler_Flags
							flags);
	EAPI void ecore_main_fd_handler_active_set(Ecore_Fd_Handler *
						   fd_handler,
						   Ecore_Fd_Handler_Flags
						   flags);

	EAPI Ecore_Win32_Handler *ecore_main_win32_handler_add(void *h,
							       Ecore_Fd_Win32_Cb
							       func,
							       const void
							       *data);
	EAPI void *ecore_main_win32_handler_del(Ecore_Win32_Handler *
						win32_handler);

	EAPI Ecore_Pipe *ecore_pipe_add(Ecore_Pipe_Cb handler,
					const void *data);
	EAPI void *ecore_pipe_del(Ecore_Pipe * p);
	EAPI Eina_Bool ecore_pipe_write(Ecore_Pipe * p, const void *buffer,
					unsigned int nbytes);
	EAPI void ecore_pipe_write_close(Ecore_Pipe * p);
	EAPI void ecore_pipe_read_close(Ecore_Pipe * p);



	EAPI Ecore_Thread *ecore_thread_run(Ecore_Cb,
					    Ecore_Cb,
					    Ecore_Cb, const void *data);
	EAPI Ecore_Thread *ecore_thread_feedback_run(Ecore_Thread_Heavy_Cb,
						     Ecore_Thread_Notify_Cb,
						     Ecore_Cb,
						     Ecore_Cb,
						     const void *data,
						     Eina_Bool
						     try_no_queue);
	EAPI Eina_Bool ecore_thread_cancel(Ecore_Thread * thread);
	EAPI Eina_Bool ecore_thread_check(Ecore_Thread * thread);
	EAPI Eina_Bool ecore_thread_feedback(Ecore_Thread * thread,
					     const void *msg_data);
	EAPI int ecore_thread_active_get(void);
	EAPI int ecore_thread_pending_get(void);
	EAPI int ecore_thread_pending_feedback_get(void);
	EAPI int ecore_thread_pending_total_get(void);
	EAPI int ecore_thread_max_get(void);
	EAPI void ecore_thread_max_set(int num);
	EAPI void ecore_thread_max_reset(void);
	EAPI int ecore_thread_available_get(void);

	EAPI Eina_Bool ecore_thread_local_data_add(Ecore_Thread * thread,
						   const char *key,
						   void *value,
						   Eina_Free_Cb cb,
						   Eina_Bool direct);
	EAPI void *ecore_thread_local_data_set(Ecore_Thread * thread,
					       const char *key,
					       void *value,
					       Eina_Free_Cb cb);
	EAPI void *ecore_thread_local_data_find(Ecore_Thread * thread,
						const char *key);
	EAPI Eina_Bool ecore_thread_local_data_del(Ecore_Thread * thread,
						   const char *key);

	EAPI Eina_Bool ecore_thread_global_data_add(const char *key,
						    void *value,
						    Eina_Free_Cb cb,
						    Eina_Bool direct);
	EAPI void *ecore_thread_global_data_set(const char *key,
						void *value,
						Eina_Free_Cb cb);
	EAPI void *ecore_thread_global_data_find(const char *key);
	EAPI Eina_Bool ecore_thread_global_data_del(const char *key);
	EAPI void *ecore_thread_global_data_wait(const char *key,
						 double seconds);




	EAPI double ecore_time_get(void);
	EAPI double ecore_time_unix_get(void);
	EAPI double ecore_loop_time_get(void);

	EAPI Ecore_Timer *ecore_timer_add(double in, Ecore_Task_Cb func,
					  const void *data);
	EAPI Ecore_Timer *ecore_timer_loop_add(double in,
					       Ecore_Task_Cb func,
					       const void *data);
	EAPI void *ecore_timer_del(Ecore_Timer * timer);
	EAPI void ecore_timer_interval_set(Ecore_Timer * timer, double in);
	EAPI double ecore_timer_interval_get(Ecore_Timer * timer);
	EAPI void ecore_timer_freeze(Ecore_Timer * timer);
	EAPI void ecore_timer_thaw(Ecore_Timer * timer);
	EAPI void ecore_timer_delay(Ecore_Timer * timer, double add);
	EAPI double ecore_timer_pending_get(Ecore_Timer * timer);

	EAPI double ecore_timer_precision_get(void);
	EAPI void ecore_timer_precision_set(double precision);

	EAPI Ecore_Animator *ecore_animator_add(Ecore_Task_Cb func,
						const void *data);
	EAPI void *ecore_animator_del(Ecore_Animator * animator);
	EAPI void ecore_animator_freeze(Ecore_Animator * animator);
	EAPI void ecore_animator_thaw(Ecore_Animator * animator);
	EAPI void ecore_animator_frametime_set(double frametime);
	EAPI double ecore_animator_frametime_get(void);

	EAPI void ecore_poller_poll_interval_set(Ecore_Poller_Type type,
						 double poll_time);
	EAPI double ecore_poller_poll_interval_get(Ecore_Poller_Type type);
	EAPI Eina_Bool ecore_poller_poller_interval_set(Ecore_Poller *
							poller,
							int interval);
	EAPI int ecore_poller_poller_interval_get(Ecore_Poller * poller);
	EAPI Ecore_Poller *ecore_poller_add(Ecore_Poller_Type type,
					    int interval,
					    Ecore_Task_Cb func,
					    const void *data);
	EAPI void *ecore_poller_del(Ecore_Poller * poller);

	EAPI Ecore_Job *ecore_job_add(Ecore_Cb func, const void *data);
	EAPI void *ecore_job_del(Ecore_Job * job);

#ifdef __cplusplus
}
#endif
#endif
