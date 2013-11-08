#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "Ecore.h"
#include "ecore_private.h"

/* How of then we should retry to write to the pipe */
#define ECORE_PIPE_WRITE_RETRY 6

/*
 * On Windows, pipe() is implemented with sockets.
 * Contrary to Linux, Windows uses different functions
 * for sockets and fd's: write() is for fd's and send
 * is for sockets. So I need to put some win32 code
 * here. I can't think of a solution where the win32
 * code is in Evil and not here.
 */

#ifdef _WIN32

#include <winsock2.h>

#define pipe_write(fd, buffer, size) send((fd), (char *)(buffer), size, 0)
#define pipe_read(fd, buffer, size)  recv((fd), (char *)(buffer), size, 0)
#define pipe_close(fd)               closesocket(fd)
#define PIPE_FD_INVALID              INVALID_SOCKET
#define PIPE_FD_ERROR                SOCKET_ERROR

#else

#include <unistd.h>
#include <fcntl.h>

#define pipe_write(fd, buffer, size) write((fd), buffer, size)
#define pipe_read(fd, buffer, size)  read((fd), buffer, size)
#define pipe_close(fd)               close(fd)
#define PIPE_FD_INVALID              -1
#define PIPE_FD_ERROR                -1

#endif				/* ! _WIN32 */

struct _Ecore_Pipe {
	ECORE_MAGIC;
	int fd_read;
	int fd_write;
	Ecore_Fd_Handler *fd_handler;
	const void *data;
	Ecore_Pipe_Cb handler;
	unsigned int len;
	size_t already_read;
	void *passed_data;
};


static Eina_Bool _ecore_pipe_read(void *data,
				  Ecore_Fd_Handler * fd_handler);

/**
 * @defgroup Ecore_Pipe_Group Pipe wrapper
 *
 * These functions wrap the pipe / write / read functions to
 * easily integrate a loop that is in its own thread to the ecore
 * main loop.
 *
 * The ecore_pipe_add() function creates file descriptors (sockets on
 * Windows) and attach an handle to the ecore main loop. That handle is
 * called when data is read in the pipe. To write data in the pipe,
 * just call ecore_pipe_write(). When you are done, just call
 * ecore_pipe_del().
 *
 * Here is an example that uses the pipe wrapper with a Gstreamer
 * pipeline. For each decoded frame in the Gstreamer thread, a handle
 * is called in the ecore thread.
 *
 * @code#include <gst/gst.h>
 * #include <Ecore.h>
 *
 * static int nbr = 0;
 *
 * static GstElement *_buid_pipeline (gchar *filename, Ecore_Pipe *pipe);
 *
 * static void new_decoded_pad_cb (GstElement *demuxer,
 *                                 GstPad     *new_pad,
 *                                 gpointer    user_data);
 *
 * static void handler(void *data, void *buf, unsigned int len)
 * {
 *   GstBuffer  *buffer = *((GstBuffer **)buf);
 *
 *   printf ("handler : %p\n", buffer);
 *   printf ("frame  : %d %p %lld %p\n", nbr++, data, (long long)GST_BUFFER_DURATION(buffer), buffer);
 *   gst_buffer_unref (buffer);
 * }
 *
 *
 * static void handoff (GstElement* object,
 *                      GstBuffer* arg0,
 *                      GstPad* arg1,
 *                      gpointer user_data)
 * {
 *   Ecore_Pipe *pipe;
 *
 *   pipe = (Ecore_Pipe *)user_data;
 *   printf ("handoff : %p\n", arg0);
 *   gst_buffer_ref (arg0);
 *   ecore_pipe_write(pipe, &arg0, sizeof(arg0));
 * }
 *
 * int
 * main (int argc, char *argv[])
 * {
 *   GstElement *pipeline;
 *   char *filename;
 *   Ecore_Pipe *pipe;
 *
 *   gst_init (&argc, &argv);
 *
 *   if (!ecore_init ())
 *     {
 *       gst_deinit ();
 *       return 0;
 *     }
 *
 *   pipe = ecore_pipe_add (handler);
 *   if (!pipe)
 *     {
 *       ecore_shutdown ();
 *       gst_deinit ();
 *       return 0;
 *     }
 *
 *   if (argc < 2) {
 *     g_print ("usage: %s file.avi\n", argv[0]);
 *     ecore_pipe_del (pipe);
 *     ecore_shutdown ();
 *     gst_deinit ();
 *     return 0;
 *   }
 *   filename = argv[1];
 *
 *   pipeline = _buid_pipeline (filename, pipe);
 *   if (!pipeline) {
 *     g_print ("Error during the pipeline building\n");
 *     ecore_pipe_del (pipe);
 *     ecore_shutdown ();
 *     gst_deinit ();
 *     return -1;
 *   }
 *
 *   gst_element_set_state (pipeline, GST_STATE_PLAYING);
 *
 *   ecore_main_loop_begin();
 *
 *   ecore_pipe_del (pipe);
 *   ecore_shutdown ();
 *   gst_deinit ();
 *
 *   return 0;
 * }
 *
 * static void
 * new_decoded_pad_cb (GstElement *demuxer,
 *                     GstPad     *new_pad,
 *                     gpointer    user_data)
 * {
 *   GstElement *decoder;
 *   GstPad *pad;
 *   GstCaps *caps;
 *   gchar *str;
 *
 *   caps = gst_pad_get_caps (new_pad);
 *   str = gst_caps_to_string (caps);
 *
 *   if (g_str_has_prefix (str, "video/")) {
 *     decoder = GST_ELEMENT (user_data);
 *
 *     pad = gst_element_get_pad (decoder, "sink");
 *     if (GST_PAD_LINK_FAILED (gst_pad_link (new_pad, pad))) {
 *       g_warning ("Failed to link %s:%s to %s:%s", GST_DEBUG_PAD_NAME (new_pad),
 *                  GST_DEBUG_PAD_NAME (pad));
 *     }
 *   }
 *   g_free (str);
 *   gst_caps_unref (caps);
 * }
 *
 * static GstElement *
 * _buid_pipeline (gchar *filename, Ecore_Pipe *pipe)
 * {
 *   GstElement          *pipeline;
 *   GstElement          *filesrc;
 *   GstElement          *demuxer;
 *   GstElement          *decoder;
 *   GstElement          *sink;
  GstStateChangeReturn res;
 *
 *   pipeline = gst_pipeline_new ("pipeline");
 *   if (!pipeline)
 *     return NULL;
 *
 *   filesrc = gst_element_factory_make ("filesrc", "filesrc");
 *   if (!filesrc) {
 *     printf ("no filesrc");
 *     goto failure;
 *   }
 *   g_object_set (G_OBJECT (filesrc), "location", filename, NULL);
 *
 *   demuxer = gst_element_factory_make ("oggdemux", "demuxer");
 *   if (!demuxer) {
 *     printf ("no demux");
 *     goto failure;
 *   }
 *
 *   decoder = gst_element_factory_make ("theoradec", "decoder");
 *   if (!decoder) {
 *     printf ("no dec");
 *     goto failure;
 *   }
 *
 *   g_signal_connect (demuxer, "pad-added",
 *                     G_CALLBACK (new_decoded_pad_cb), decoder);
 *
 *   sink = gst_element_factory_make ("fakesink", "sink");
 *   if (!sink) {
 *     printf ("no sink");
 *     goto failure;
 *   }
 *   g_object_set (G_OBJECT (sink), "sync", EINA_TRUE, NULL);
 *   g_object_set (G_OBJECT (sink), "signal-handoffs", EINA_TRUE, NULL);
 *   g_signal_connect (sink, "handoff",
 *                     G_CALLBACK (handoff), pipe);
 *
 *   gst_bin_add_many (GST_BIN (pipeline),
 *                     filesrc, demuxer, decoder, sink, NULL);
 *
 *   if (!gst_element_link (filesrc, demuxer))
 *     goto failure;
 *   if (!gst_element_link (decoder, sink))
 *     goto failure;
 *
 *   res = gst_element_set_state (pipeline, GST_STATE_PAUSED);
 *   if (res == GST_STATE_CHANGE_FAILURE)
 *     goto failure;
 *
 *   res = gst_element_get_state( pipeline, NULL, NULL, GST_CLOCK_TIME_NONE );
 *   if (res != GST_STATE_CHANGE_SUCCESS)
 *     goto failure;
 *
 *   return pipeline;
 *
 *  failure:
 *   gst_object_unref (GST_OBJECT (pipeline));
 *   return NULL;
 * }
 * @endcode
 */


/**
 * Create two file descriptors (sockets on Windows). Add
 * a callback that will be called when the file descriptor that
 * is listened receives data. An event is also put in the event
 * queue when data is received.
 *
 * @param handler The handler called when data is received.
 * @param data    Data to pass to @p handler when it is called.
 * @return        A newly created Ecore_Pipe object if successful.
 *                @c NULL otherwise.
 * @ingroup Ecore_Pipe_Group
 */
EAPI Ecore_Pipe *ecore_pipe_add(Ecore_Pipe_Cb handler, const void *data)
{
	Ecore_Pipe *p;
	int fds[2];

	if (!handler)
		return NULL;

	p = (Ecore_Pipe *) calloc(1, sizeof(Ecore_Pipe));
	if (!p)
		return NULL;

	if (pipe(fds)) {
		free(p);
		return NULL;
	}

	ECORE_MAGIC_SET(p, ECORE_MAGIC_PIPE);
	p->fd_read = fds[0];
	p->fd_write = fds[1];
	p->handler = handler;
	p->data = data;

	fcntl(p->fd_read, F_SETFL, O_NONBLOCK);
	p->fd_handler = ecore_main_fd_handler_add(p->fd_read,
						  ECORE_FD_READ,
						  _ecore_pipe_read,
						  p, NULL, NULL);
	return p;
}

/**
 * Free an Ecore_Pipe object created with ecore_pipe_add().
 *
 * @param p The Ecore_Pipe object to be freed.
 * @return The pointer to the private data
 * @ingroup Ecore_Pipe_Group
 */
EAPI void *ecore_pipe_del(Ecore_Pipe * p)
{
	void *data;

	if (!ECORE_MAGIC_CHECK(p, ECORE_MAGIC_PIPE)) {
		ECORE_MAGIC_FAIL(p, ECORE_MAGIC_PIPE, "ecore_pipe_del");
		return NULL;
	}
	if (p->fd_handler)
		ecore_main_fd_handler_del(p->fd_handler);
	if (p->fd_read != PIPE_FD_INVALID)
		pipe_close(p->fd_read);
	if (p->fd_write != PIPE_FD_INVALID)
		pipe_close(p->fd_write);
	data = (void *) p->data;
	free(p);
	return data;
}

/**
 * Close the read end of an Ecore_Pipe object created with ecore_pipe_add().
 *
 * @param p The Ecore_Pipe object.
 * @ingroup Ecore_Pipe_Group
 */
EAPI void ecore_pipe_read_close(Ecore_Pipe * p)
{
	if (!ECORE_MAGIC_CHECK(p, ECORE_MAGIC_PIPE)) {
		ECORE_MAGIC_FAIL(p, ECORE_MAGIC_PIPE,
				 "ecore_pipe_read_close");
		return;
	}
	ecore_main_fd_handler_del(p->fd_handler);
	p->fd_handler = NULL;
	pipe_close(p->fd_read);
	p->fd_read = PIPE_FD_INVALID;
}

/**
 * Close the write end of an Ecore_Pipe object created with ecore_pipe_add().
 *
 * @param p The Ecore_Pipe object.
 * @ingroup Ecore_Pipe_Group
 */
EAPI void ecore_pipe_write_close(Ecore_Pipe * p)
{
	if (!ECORE_MAGIC_CHECK(p, ECORE_MAGIC_PIPE)) {
		ECORE_MAGIC_FAIL(p, ECORE_MAGIC_PIPE,
				 "ecore_pipe_write_close");
		return;
	}
	pipe_close(p->fd_write);
	p->fd_write = PIPE_FD_INVALID;
}

/**
 * Write on the file descriptor the data passed as parameter.
 *
 * @param p      The Ecore_Pipe object.
 * @param buffer The data to write into the pipe.
 * @param nbytes The size of the @p buffer in bytes
 * @return       Returns EINA_TRUE on a successful write, EINA_FALSE on an error
 * @ingroup Ecore_Pipe_Group
 */
EAPI Eina_Bool
ecore_pipe_write(Ecore_Pipe * p, const void *buffer, unsigned int nbytes)
{
	ssize_t ret;
	size_t already_written = 0;
	int retry = ECORE_PIPE_WRITE_RETRY;

	if (!ECORE_MAGIC_CHECK(p, ECORE_MAGIC_PIPE)) {
		ECORE_MAGIC_FAIL(p, ECORE_MAGIC_PIPE, "ecore_pipe_write");
		return EINA_FALSE;
	}

	if (p->fd_write == PIPE_FD_INVALID)
		return EINA_FALSE;

	/* First write the len into the pipe */
	do {
		ret = pipe_write(p->fd_write, &nbytes, sizeof(nbytes));
		if (ret == sizeof(nbytes)) {
			retry = ECORE_PIPE_WRITE_RETRY;
			break;
		} else if (ret > 0) {
			/* XXX What should we do here? */
			ERR("The length of the data was not written complete" " to the pipe");
			return EINA_FALSE;
		} else if (ret == PIPE_FD_ERROR && errno == EPIPE) {
			pipe_close(p->fd_write);
			p->fd_write = PIPE_FD_INVALID;
			return EINA_FALSE;
		} else if (ret == PIPE_FD_ERROR && errno == EINTR)
			/* try it again */
			;
		else {
			ERR("An unhandled error (ret: %zd errno: %d)"
			    "occurred while writing to the pipe the length",
			    ret, errno);
		}
	}
	while (retry--);

	if (retry != ECORE_PIPE_WRITE_RETRY)
		return EINA_FALSE;

	/* and now pass the data to the pipe */
	do {
		ret = pipe_write(p->fd_write,
				 ((unsigned char *) buffer) +
				 already_written,
				 nbytes - already_written);

		if (ret == (ssize_t) (nbytes - already_written))
			return EINA_TRUE;
		else if (ret >= 0) {
			already_written -= ret;
			continue;
		} else if (ret == PIPE_FD_ERROR && errno == EPIPE) {
			pipe_close(p->fd_write);
			p->fd_write = PIPE_FD_INVALID;
			return EINA_FALSE;
		} else if (ret == PIPE_FD_ERROR && errno == EINTR)
			/* try it again */
			;
		else {
			ERR("An unhandled error (ret: %zd errno: %d)"
			    "occurred while writing to the pipe the length",
			    ret, errno);
		}
	}
	while (retry--);

	return EINA_FALSE;
}

/* Private function */

static Eina_Bool
_ecore_pipe_read(void *data, Ecore_Fd_Handler * fd_handler __UNUSED__)
{
	Ecore_Pipe *p;
	double start_time;

	p = (Ecore_Pipe *) data;
	start_time = ecore_time_get();

	do {
		ssize_t ret;

		/* if we already have read some data we don't need to read the len
		 * but to finish the already started job
		 */
		if (p->len == 0) {
			/* read the len of the passed data */
			ret =
			    pipe_read(p->fd_read, &p->len, sizeof(p->len));

			/* catch the non error case first */
			if (ret == sizeof(p->len));
			else if (ret > 0) {
				/* XXX What should we do here? */
				ERR("Only read %zd bytes from the pipe, although" " we need to read %zd bytes.", ret, sizeof(p->len));
			} else if (ret == 0) {
				p->handler((void *) p->data, NULL, 0);
				pipe_close(p->fd_read);
				p->fd_read = PIPE_FD_INVALID;
				p->fd_handler = NULL;
				return ECORE_CALLBACK_CANCEL;
			}
#ifndef _WIN32
			else if ((ret == PIPE_FD_ERROR)
				 && ((errno == EINTR)
				     || (errno == EAGAIN)))
				return ECORE_CALLBACK_RENEW;
			else {
				ERR("An unhandled error (ret: %zd errno: %d)" "occurred while reading from the pipe the length", ret, errno);
				return ECORE_CALLBACK_RENEW;
			}
#else
			else {	/* ret == PIPE_FD_ERROR is the only other case on Windows */

				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					p->handler((void *) p->data, NULL,
						   0);
					pipe_close(p->fd_read);
					p->fd_read = PIPE_FD_INVALID;
					p->fd_handler = NULL;
					return ECORE_CALLBACK_CANCEL;
				}
			}
#endif
		}

		if (!p->passed_data)
			p->passed_data = malloc(p->len);

		/* and read the passed data */
		ret = pipe_read(p->fd_read,
				((unsigned char *) p->passed_data) +
				p->already_read, p->len - p->already_read);

		/* catch the non error case first */
		if (ret == (ssize_t) (p->len - p->already_read)) {
			p->handler((void *) p->data, p->passed_data,
				   p->len);
			free(p->passed_data);
			/* reset all values to 0 */
			p->passed_data = NULL;
			p->already_read = 0;
			p->len = 0;
		} else if (ret >= 0) {
			p->already_read += ret;
			return ECORE_CALLBACK_RENEW;
		} else if (ret == 0) {
			p->handler((void *) p->data, NULL, 0);
			pipe_close(p->fd_read);
			p->fd_read = PIPE_FD_INVALID;
			p->fd_handler = NULL;
			return ECORE_CALLBACK_CANCEL;
		}
#ifndef _WIN32
		else if (ret == PIPE_FD_ERROR
			 && (errno == EINTR || errno == EAGAIN))
			return ECORE_CALLBACK_RENEW;
		else {
			ERR("An unhandled error (ret: %zd errno: %d)"
			    "occurred while reading from the pipe the data",
			    ret, errno);
			return ECORE_CALLBACK_RENEW;
		}
#else
		else {		/* ret == PIPE_FD_ERROR is the only other case on Windows */

			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				p->handler((void *) p->data, NULL, 0);
				pipe_close(p->fd_read);
				p->fd_read = PIPE_FD_INVALID;
				p->fd_handler = NULL;
				return ECORE_CALLBACK_CANCEL;
			} else
				break;
		}
#endif
	}
	while (ecore_time_get() - start_time <
	       ecore_animator_frametime_get());

	return ECORE_CALLBACK_RENEW;
}
