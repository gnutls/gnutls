/* GnuTLS modifications: */
#define SetErrnoFromWinsockError(x) errno = EIO;
#define SetErrnoFromWinError(x) x

#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#if defined _WIN32 || defined __WIN32__

/*
     This file is part of PlibC.
     (C) 2005, 2006 Nils Durner (and other contributing authors)

	   This library is free software; you can redistribute it and/or
	   modify it under the terms of the GNU Lesser General Public
	   License as published by the Free Software Foundation; either
	   version 2.1 of the License, or (at your option) any later version.
	
	   This library is distributed in the hope that it will be useful,
	   but WITHOUT ANY WARRANTY; without even the implied warranty of
	   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	   Lesser General Public License for more details.
	
	   You should have received a copy of the GNU Lesser General Public
	   License along with this library; if not, write to the Free Software
	   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Code originally written by Wez Furlong <wez@thebrainroom.com>
 * who originally placed it under the PHP License Version 3.0.
 * Adapted for GNUnet by Nils Durner <durner@gnunet.org>.
 * GPLed with permission from Wez Furlong (see E-mail on
 * gnunet-developers, also quoted in the GNUnet CVS logs).
 *
 * @file src/select.c
 * @brief select implementation for Win32
 * @author Wez Furlong <wez@thebrainroom.com>
 * @author Nils Durner (GNUnet extensions)
 */

/*
 * Win32 select() will only work with sockets, so we roll our own
 * implementation here.
 * - If you supply only sockets, this simply passes through to winsock select().
 * - If you supply file handles, there is no way to distinguish between
 *   ready for read/write or OOB, so any set in which the handle is found will
 *   be marked as ready.
 * - If you supply a mixture of handles and sockets, the system will interleave
 *   calls between select() and WaitForMultipleObjects(). The time slicing may
 *   cause this function call to take up to 100 ms longer than you specified.
 * - Pipes are not checked for writability or errors (errno = ENOSYS)
 */
int
_win_select (int max_fd, fd_set * rfds, fd_set * wfds, fd_set * efds,
	     const struct timeval *tv)
{
  DWORD ms_total, limit;
  HANDLE handles[MAXIMUM_WAIT_OBJECTS], hPipes[MAXIMUM_WAIT_OBJECTS];
  int handle_slot_to_fd[MAXIMUM_WAIT_OBJECTS];
  int n_handles, i, iPipes;
  fd_set sock_read, sock_write, sock_except;
  fd_set aread, awrite, aexcept;
  int sock_max_fd;
  struct timeval tvslice;
  int retcode;

#define SAFE_FD_ISSET(fd, set)	(set != NULL && FD_ISSET(fd, set))

  n_handles = 0;
  sock_max_fd = -1;
  iPipes = 0;

  /* calculate how long we need to wait in milliseconds */
  if (tv == NULL)
    ms_total = INFINITE;
  else
    {
      ms_total = tv->tv_sec * 1000;
      ms_total += tv->tv_usec / 1000;
    }

  /* select() may be used as a portable way to sleep */
  if (!(rfds || wfds || efds))
    {
      Sleep (ms_total);

      return 0;
    }

  FD_ZERO (&sock_read);
  FD_ZERO (&sock_write);
  FD_ZERO (&sock_except);

  /* build an array of handles for non-sockets */
  for (i = 0; i < max_fd; i++)
    {
      if (SAFE_FD_ISSET (i, rfds) || SAFE_FD_ISSET (i, wfds) ||
	  SAFE_FD_ISSET (i, efds))
	{
	  unsigned long ulVal;

	  if (ioctlsocket (i, FIONREAD, &ulVal) != SOCKET_ERROR
	      && _get_osfhandle (i) == -1)
	    {
	      /* socket */
	      if (SAFE_FD_ISSET (i, rfds))
		FD_SET (i, &sock_read);

	      if (SAFE_FD_ISSET (i, wfds))
		FD_SET (i, &sock_write);

	      if (SAFE_FD_ISSET (i, efds))
		FD_SET (i, &sock_except);

	      if (i > sock_max_fd)
		sock_max_fd = i;
	    }
	  else
	    {
	      if (GetFileType ((HANDLE) i) == FILE_TYPE_PIPE)
		hPipes[iPipes++] = (HANDLE) i;	/* Pipe */
	      else
		{
		  handles[n_handles] = (HANDLE) _get_osfhandle (i);
		  if ((DWORD) handles[n_handles] == 0xffffffff)
		    handles[n_handles] = (HANDLE) i;
		  handle_slot_to_fd[n_handles] = i;
		  n_handles++;
		}
	    }
	}
    }

  if ((n_handles == 0) && (iPipes == 0))
    {
      /* plain sockets only - let winsock handle the whole thing */
      if ((retcode = select (max_fd, rfds, wfds, efds, tv)) == SOCKET_ERROR)
	SetErrnoFromWinsockError (WSAGetLastError ());
      return retcode;
    }

  /* mixture of handles and sockets; lets multiplex between
   * winsock and waiting on the handles */

  FD_ZERO (&aread);
  FD_ZERO (&awrite);
  FD_ZERO (&aexcept);

  limit = GetTickCount () + ms_total;
  do
    {
      retcode = 0;

      if (sock_max_fd >= 0)
	{
	  /* overwrite the zero'd sets here; the select call
	   * will clear those that are not active */
	  aread = sock_read;
	  awrite = sock_write;
	  aexcept = sock_except;

	  tvslice.tv_sec = 0;
	  tvslice.tv_usec = 100000;

	  if ((retcode = select (sock_max_fd + 1, &aread, &awrite, &aexcept,
				 &tvslice)) == SOCKET_ERROR)
	    {
	      SetErrnoFromWinsockError (WSAGetLastError ());

	      return -1;
	    }
	}

      if (n_handles > 0)
	{
	  /* check handles */
	  DWORD wret;

	  wret =
	    MsgWaitForMultipleObjects (n_handles, handles, FALSE,
				       retcode > 0 ? 0 : 100, QS_ALLEVENTS);

	  if (wret == WAIT_TIMEOUT)
	    {
	      /* set retcode to 0; this is the default.
	       * select() may have set it to something else,
	       * in which case we leave it alone, so this branch
	       * does nothing */
	      ;
	    }
	  else if (wret == WAIT_FAILED)
	    {
	      SetErrnoFromWinError (GetLastError ());

	      return -1;
	    }
	  else
	    {
	      for (i = 0; i < n_handles; i++)
		{
		  if (WAIT_OBJECT_0 == WaitForSingleObject (handles[i], 0))
		    {
		      if (SAFE_FD_ISSET (handle_slot_to_fd[i], rfds))
			{
			  FD_SET (handle_slot_to_fd[i], &aread);
			}

		      if (SAFE_FD_ISSET (handle_slot_to_fd[i], wfds))
			FD_SET (handle_slot_to_fd[i], &awrite);

		      if (SAFE_FD_ISSET (handle_slot_to_fd[i], efds))
			FD_SET (handle_slot_to_fd[i], &aexcept);

		      retcode++;
		    }
		}
	    }
	}

      /* Poll Pipes */
      for (i = 0; i < iPipes; i++)
	{
	  DWORD dwBytes;
	  if (SAFE_FD_ISSET (hPipes[i], rfds))
	    {
	      if (!PeekNamedPipe (hPipes[i], NULL, 0, NULL, &dwBytes, NULL))
		{
		  retcode = -1;
		  SetErrnoFromWinError (GetLastError ());
		}
	      else if (dwBytes)
		{
		  FD_SET ((int) hPipes[i], &aread);
		  retcode++;
		}
	    }
	  else if (SAFE_FD_ISSET (hPipes[i], wfds)
		   || SAFE_FD_ISSET (hPipes[i], efds))
	    {
	      errno = ENOSYS;
	      return -1;	/* Not implemented */
	    }
	}
    }
  while (retcode == 0 && (ms_total == INFINITE || GetTickCount () < limit));

  if (rfds)
    *rfds = aread;

  if (wfds)
    *wfds = awrite;

  if (efds)
    *efds = aexcept;

  return retcode;
}

#endif /* _WIN32 || defined __WIN32__ */
