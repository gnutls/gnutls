/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_record.h>

/* This is the only file that uses the berkeley sockets API.
 */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifndef EAGAIN
# define EAGAIN EWOULDBLOCK
#endif

#ifdef IO_DEBUG
# include <io_debug.h>
#endif

/* Buffers received packets of type APPLICATION DATA and
 * HANDSHAKE DATA.
 */
int gnutls_insert_to_data_buffer(ContentType type, GNUTLS_STATE state, char *data, int length)
{
	int old_buffer;

	if (length==0) return 0;
	if (type == GNUTLS_APPLICATION_DATA) {
		old_buffer = state->gnutls_internals.buffer.size;

		state->gnutls_internals.buffer.size += length;
#ifdef BUFFERS_DEBUG
	_gnutls_log( "RECORD BUFFER: Inserted %d bytes of Data(%d)\n", length, type);
#endif
		state->gnutls_internals.buffer.data =
		    gnutls_realloc_fast(state->gnutls_internals.buffer.data,
			   state->gnutls_internals.buffer.size);
		memcpy(&state->gnutls_internals.buffer.data[old_buffer], data, length);
	}
	if (type == GNUTLS_HANDSHAKE) {
		old_buffer = state->gnutls_internals.buffer_handshake.size;

		state->gnutls_internals.buffer_handshake.size += length;
#ifdef BUFFERS_DEBUG
	_gnutls_log( "HANDSHAKE BUFFER: Inserted %d bytes of Data(%d)\n", length, type);
#endif
		state->gnutls_internals.buffer_handshake.data =
		    gnutls_realloc_fast(state->gnutls_internals.buffer_handshake.data,
			   state->gnutls_internals.buffer_handshake.size);
		memcpy(&state->gnutls_internals.buffer_handshake.data[old_buffer], data, length);
	}

	return 0;

}

int gnutls_get_data_buffer_size(ContentType type, GNUTLS_STATE state)
{
	if (type == GNUTLS_APPLICATION_DATA)
		return state->gnutls_internals.buffer.size;
	if (type == GNUTLS_HANDSHAKE)
		return state->gnutls_internals.buffer_handshake.size;
	return 0;
}

/**
  * gnutls_check_pending - checks if there are any data to receive in gnutls buffers.
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function checks if there are any data to receive
  * in the gnutls buffers. Returns the size of that data or 0.
  * Notice that you may also use select() to check for data in
  * the TCP connection, instead of this function.
  * (gnutls leaves some data in the tcp buffer in order for select
  * to work).
  **/
int gnutls_check_pending(GNUTLS_STATE state) {
	return gnutls_get_data_buffer_size(GNUTLS_APPLICATION_DATA, state);
}

int gnutls_get_data_buffer(ContentType type, GNUTLS_STATE state, char *data, int length)
{
	if (type == GNUTLS_APPLICATION_DATA) {
	
		if (length > state->gnutls_internals.buffer.size) {
			length = state->gnutls_internals.buffer.size;
		}
#ifdef BUFFERS_DEBUG
	_gnutls_log( "RECORD BUFFER: Read %d bytes of Data(%d)\n", length, type);
#endif
		state->gnutls_internals.buffer.size -= length;
		memcpy(data, state->gnutls_internals.buffer.data, length);

		/* overwrite buffer */
		memcpy(state->gnutls_internals.buffer.data,
			&state->gnutls_internals.buffer.data[length],
			state->gnutls_internals.buffer.size);
		state->gnutls_internals.buffer.data =
		    gnutls_realloc_fast(state->gnutls_internals.buffer.data,
				   state->gnutls_internals.buffer.size);
	}
	if (type == GNUTLS_HANDSHAKE) {
		if (length > state->gnutls_internals.buffer_handshake.size) {
			length = state->gnutls_internals.buffer_handshake.size;
		}
#ifdef BUFFERS_DEBUG
	_gnutls_log( "HANDSHAKE BUFFER: Read %d bytes of Data(%d)\n", length, type);
#endif
		state->gnutls_internals.buffer_handshake.size -= length;
		memcpy(data, state->gnutls_internals.buffer_handshake.data, length);

		/* overwrite buffer */
		memcpy(state->gnutls_internals.buffer_handshake.data,
			&state->gnutls_internals.buffer_handshake.data[length],
			state->gnutls_internals.buffer_handshake.size);
		state->gnutls_internals.buffer_handshake.data =
		    gnutls_realloc_fast(state->gnutls_internals.buffer_handshake.data,
				   state->gnutls_internals.buffer_handshake.size);
	}


	return length;
}


/* This function is like read. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * Flags are only used if the default recv() function is being used.
 */
static ssize_t _gnutls_read( SOCKET fd, GNUTLS_STATE state, void *iptr, size_t sizeOfPtr, int flags)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;
#ifdef READ_DEBUG
	int j,x, sum=0;
#endif


	left = sizeOfPtr;
	while (left > 0) {
		
		if (state->gnutls_internals._gnutls_pull_func==NULL)
			i = recv(fd, &ptr[sizeOfPtr-left], left, flags);
		else
			i = state->gnutls_internals._gnutls_pull_func(fd, &ptr[sizeOfPtr-left], left);
				
		if (i < 0) {
#ifdef READ_DEBUG
			_gnutls_log( "READ: %d returned from %d, errno=%d\n", i, fd, errno);
#endif
			if (errno == EAGAIN || errno == EINTR) {
				if (sizeOfPtr-left > 0) {
#ifdef READ_DEBUG
					_gnutls_log( "READ: returning %d bytes from %d\n", sizeOfPtr-left, fd);
#endif
					goto finish;
				}
				gnutls_assert();
				if (errno==EAGAIN) return GNUTLS_E_AGAIN;
				else return GNUTLS_E_INTERRUPTED;
			} else {
				gnutls_assert();
				return GNUTLS_E_PULL_ERROR;
			}
		} else {
#ifdef READ_DEBUG
			_gnutls_log( "READ: Got %d bytes from %d\n", i, fd);
#endif
			if (i == 0)
				break;	/* EOF */
		}

		left -= i;

	}

	finish:
	
#ifdef READ_DEBUG
	_gnutls_log( "READ: read %d bytes from %d\n", (sizeOfPtr-left), fd);
	for (x=0;x<((sizeOfPtr-left)/16)+1;x++) {
		_gnutls_log( "%.4x - ",x);
		for (j=0;j<16;j++) {
			if (sum<(sizeOfPtr-left)) {
				_gnutls_log( "%.2x ", ((unsigned char*)ptr)[sum++]);
			}
		}
		_gnutls_log( "\n");
	
	}
#endif


	return (sizeOfPtr - left);
}


#define RCVLOWAT state->gnutls_internals.lowat 

int _gnutls_clear_peeked_data( SOCKET cd, GNUTLS_STATE state) {
char peekdata1[10];
char *peekdata2;
char * peek;
int ret, sum;

	if (state->gnutls_internals.have_peeked_data==0 || RCVLOWAT==0)
		return 0;
		
	if (RCVLOWAT > sizeof(peekdata1)) {
		peekdata2 = gnutls_malloc( RCVLOWAT);
		if (peekdata2==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		peek = peekdata2;
		
        } else {
        	peek = peekdata1;
        }

        /* this was already read by using MSG_PEEK - so it shouldn't fail */
	sum = 0;
        do { /* we need this to finish now */
        	ret = _gnutls_read( cd, state, peek, RCVLOWAT-sum, 0);
        	if (ret > 0) sum+=ret;
       	} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN || sum < RCVLOWAT);

	if (peek==peekdata2) {
		gnutls_free(peekdata2);
	}
	
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	state->gnutls_internals.have_peeked_data=0;

       	return 0;
}


void _gnutls_clear_read_buffer( GNUTLS_STATE state) {
	state->gnutls_internals.recv_buffer.size = 0;
}
                  	
/* This function is like recv(with MSG_PEEK). But it does not return -1 on error.
 * It does return gnutls_errno instead.
 * This function reads data from the socket and keeps them in a buffer, of up to
 * MAX_RECV_SIZE. 
 *
 * sizeOfPtr should be unsigned.
 *
 * This is not a general purpose function. It returns EXACTLY the data requested.
 *
 * FIXME: make the buffer, be dynamically allocated.
 */
ssize_t _gnutls_read_buffered( int fd, GNUTLS_STATE state, opaque **iptr, size_t sizeOfPtr, ContentType recv_type)
{
	ssize_t ret=0, ret2=0;
	int min, buf_pos;
	char *buf;
	int recvlowat = RCVLOWAT;
	int recvdata;

	*iptr = NULL;

	if ( sizeOfPtr > MAX_RECV_SIZE || sizeOfPtr == 0 
	|| (state->gnutls_internals.recv_buffer.size+sizeOfPtr) > MAX_RECV_SIZE) {
		gnutls_assert(); /* internal error */
		return GNUTLS_E_INVALID_PARAMETERS;
	}
	
	/* leave peeked data to the kernel space only if application data
	 * is received and we don't have any peeked 
	 * data in gnutls state.
	 */
	if ( recv_type != GNUTLS_APPLICATION_DATA
		&& state->gnutls_internals.have_peeked_data==0)
		recvlowat = 0;

	
	/* calculate the actual size, ie. get the minimum of the
	 * buffered data and the requested data.
	 */
	min = GMIN( state->gnutls_internals.recv_buffer.size, sizeOfPtr);
	if ( min > 0) {
		/* if we have enough buffered data
		 * then just return them.
		 */
		if ( min == sizeOfPtr) {
			return min;
		}
	}

	/* min is over zero. recvdata is the data we must
	 * receive in order to return the requested data.
	 */
	recvdata = sizeOfPtr - min;
	
	/* Allocate the data required to store the new packet.
	 */
	state->gnutls_internals.recv_buffer.data = gnutls_realloc_fast(
		state->gnutls_internals.recv_buffer.data, recvdata+state->gnutls_internals.recv_buffer.size);
	if ( state->gnutls_internals.recv_buffer.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	buf_pos = state->gnutls_internals.recv_buffer.size;
	buf = state->gnutls_internals.recv_buffer.data;
	*iptr = buf;

	/* READ DATA - but leave RCVLOWAT bytes in the kernel buffer.
	 */
	if ( recvdata - recvlowat > 0) {
		ret = _gnutls_read( fd, state, &buf[buf_pos], recvdata - recvlowat, 0);

		/* return immediately if we got an interrupt or eagain
		 * error.
		 */
		if (ret < 0 && gnutls_is_fatal_error(ret)==0) {
			return ret;
		}
	}

#ifdef READ_DEBUG
	if (ret > 0)
		_gnutls_log("RB: Have %d bytes into buffer. Adding %d bytes.\nRB: Requested %d bytes\n", state->gnutls_internals.recv_buffer_data_size, ret, sizeOfPtr);
#endif
	/* copy fresh data to our buffer.
	 */
	if (ret > 0)
		state->gnutls_internals.recv_buffer.size += ret;


	buf_pos = state->gnutls_internals.recv_buffer.size;
	
	/* This is hack in order for select to work. Just leave recvlowat data,
	 * into the kernel buffer (using a read with MSG_PEEK), thus making
	 * select think, that the socket is ready for reading
	 */
	if (ret == (recvdata - recvlowat) && recvlowat > 0) {
		ret2 = _gnutls_read( fd, state, &buf[buf_pos], recvlowat, MSG_PEEK);

		if (ret2 < 0 && gnutls_is_fatal_error(ret2)==0) {
			return ret2;
		}

#ifdef READ_DEBUG
		if (ret2 > 0) {
			_gnutls_log("RB-PEEK: Read %d bytes in PEEK MODE.\n", ret2); 
			_gnutls_log("RB-PEEK: Have %d bytes into buffer. Adding %d bytes.\nRB: Requested %d bytes\n", state->gnutls_internals.recv_buffer_data_size, ret2, sizeOfPtr);
		}
#endif

		if (ret2 > 0) {
			state->gnutls_internals.have_peeked_data = 1;
			state->gnutls_internals.recv_buffer.size += ret2;

		}
	}

	if (ret < 0 || ret2 < 0) {
		gnutls_assert();
		/* that's because they are initilized to 0 */
		return GMIN(ret, ret2);
	}

	ret += ret2;

	if (ret > 0 && ret < recvlowat) {
		gnutls_assert();
		return GNUTLS_E_AGAIN;
	}
	
	if (ret==0) { /* EOF */
		gnutls_assert();
		return 0;
	}

	ret = state->gnutls_internals.recv_buffer.size;

	if ((ret > 0) && (ret < sizeOfPtr)) {
		/* Short Read */
		gnutls_assert();
		return GNUTLS_E_AGAIN;
	} else {
		return ret;
	}
}



/* This function is like write. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * This function may not cope right with interrupted system calls
 * and EAGAIN error. Ideas?
 *
 * We need to push exactly the data in n, since we cannot send less
 * data. In TLS the peer must receive the whole packet in order
 * to decrypt and verify the integrity. 
 *
 */
ssize_t _gnutls_write_buffered(SOCKET fd, GNUTLS_STATE state, const void *iptr, size_t n)
{
	size_t left;
#ifdef WRITE_DEBUG
	int j,x, sum=0;
#endif
	ssize_t retval, i;
	const opaque * ptr;

	ptr = iptr;
	
	/* In case the previous write was interrupted, check if the
	 * iptr != NULL and we have data in the buffer.
	 * If this is true then return an error.
	 */
	if (state->gnutls_internals.send_buffer.size > 0 && iptr != NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	/* If data in the buffer exist
	 */
	if (iptr == NULL) {
		/* checking is handled above */
		ptr = state->gnutls_internals.send_buffer.data;
		n = state->gnutls_internals.send_buffer.size;
#ifdef WRITE_DEBUG
		_gnutls_log( "WRITE: Restoring old write. (%d data to send)\n", n);
#endif
	}

#ifdef WRITE_DEBUG
	_gnutls_log( "WRITE: Will write %d bytes to %d.\n", n, fd);
#endif

	i = 0;
	left = n;
	while (left > 0) {
		
		if (state->gnutls_internals._gnutls_push_func==NULL) 
			i = send(fd, &ptr[n-left], left, 0);
		else
			i = state->gnutls_internals._gnutls_push_func(fd, &ptr[n-left], left);

		if (i == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				state->gnutls_internals.send_buffer_prev_size += n - left;

				state->gnutls_internals.send_buffer.data = gnutls_realloc_fast( state->gnutls_internals.send_buffer.data, left);
				if (state->gnutls_internals.send_buffer.data == NULL) {
					gnutls_assert();
					return GNUTLS_E_MEMORY_ERROR;
				}
				state->gnutls_internals.send_buffer.size = left;
				/* use memmove since they may overlap 
				 */
				memmove( state->gnutls_internals.send_buffer.data, &ptr[n-left], left);
#ifdef WRITE_DEBUG
				_gnutls_log( "WRITE: Interrupted.\n");
#endif
				gnutls_assert();
				if (errno==EAGAIN) retval = GNUTLS_E_AGAIN;
				else retval = GNUTLS_E_INTERRUPTED;

				return retval;
			} else {
				gnutls_assert();
				return GNUTLS_E_PUSH_ERROR;
			}
		}
		left -= i;

#ifdef WRITE_DEBUG
		_gnutls_log( "WRITE: wrote %d bytes to %d. Left %d bytes\n", i, fd, left);
		for (x=0;x<((n-left)/16)+1;x++) {
			_gnutls_log( "%.4x - ",x);
			for (j=0;j<16;j++) {
				if (sum<n-left) {
					_gnutls_log( "%.2x ", ((unsigned char*)ptr)[sum++]);
				}
			}
			_gnutls_log( "\n");
		}
#endif

	}

	retval = n + state->gnutls_internals.send_buffer_prev_size;

	state->gnutls_internals.send_buffer.size = 0;
	state->gnutls_internals.send_buffer_prev_size = 0;

	return retval;

}

/* This function writes the data that are left in the
 * TLS write buffer (ie. because the previous write was
 * interrupted.
 */
ssize_t _gnutls_flush(SOCKET fd, GNUTLS_STATE state)
{
    ssize_t ret;

    if (state->gnutls_internals.send_buffer.size == 0)
        return 0; /* done */

    ret = _gnutls_write_buffered(fd, state, NULL, 0);
#ifdef WRITE_DEBUG 
    _gnutls_log("WRITE FLUSH: %d\n", ret);
#endif
    return ret;
}


/* This is a send function for the gnutls handshake 
 * protocol. Just makes sure that all data have been sent.
 */
ssize_t _gnutls_handshake_send_int( SOCKET fd, GNUTLS_STATE state, ContentType type, HandshakeType htype, void *iptr, size_t n)
{
	size_t left;
	ssize_t i = 0;
	char *ptr = iptr;

	if (iptr==NULL && n == 0) {
		/* resuming interrupted write. Put some random data into
		 * the data field so send_int() will proceed normally.
		 */
		return _gnutls_flush( fd, state);
	}

	left = n;
	while (left > 0) {
		i = gnutls_send_int(fd, state, type, htype, &ptr[i], left);
		if (i <= 0) {
			gnutls_assert();
			if (n-left > 0)  {
				gnutls_assert();
				return n-left;
			}
			return i;
		}
		left -= i;
	}

	return n;

}

/* This is a receive function for the gnutls handshake 
 * protocol. Makes sure that we have received all data.
 */
ssize_t _gnutls_handshake_recv_int(int fd, GNUTLS_STATE state, ContentType type, HandshakeType htype, void *iptr, size_t sizeOfPtr)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;

	left = sizeOfPtr;
	while (left > 0) {
		i = gnutls_recv_int(fd, state, type, htype, &ptr[i], left);
		if (i < 0) {
			if (sizeOfPtr - left > 0) {
				gnutls_assert();
				goto finish;
			}
			gnutls_assert();
			return i;
		} else {
			if (i == 0)
				break;	/* EOF */
		}

		left -= i;

	}

	finish:
	return (sizeOfPtr - left);
}

/* Buffer for handshake packets. Keeps the packets in order
 * for finished messages to use them.
 */
int gnutls_insert_to_handshake_buffer( GNUTLS_STATE state, char *data, int length)
{
	int old_buffer;

	if (length==0) return 0;	
	old_buffer = state->gnutls_internals.hash_buffer.size;

	state->gnutls_internals.hash_buffer.size += length;
	if (state->gnutls_internals.max_handshake_data_buffer_size > 0 && state->gnutls_internals.hash_buffer.size > state->gnutls_internals.max_handshake_data_buffer_size) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

#ifdef BUFFERS_DEBUG
	_gnutls_log( "HASH BUFFER: Inserted %d bytes of Data\n", length);
#endif
	state->gnutls_internals.hash_buffer.data =
		    gnutls_realloc_fast(state->gnutls_internals.hash_buffer.data,
			   state->gnutls_internals.hash_buffer.size);
	if (state->gnutls_internals.hash_buffer.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memcpy(&state->gnutls_internals.hash_buffer.data[old_buffer], data, length);

	return 0;
}

int gnutls_get_handshake_buffer_size( GNUTLS_STATE state)
{

	return state->gnutls_internals.hash_buffer.size;
}

int gnutls_get_handshake_buffer( GNUTLS_STATE state, char *data, int length)
{
	if (length > state->gnutls_internals.hash_buffer.size) {
		length = state->gnutls_internals.hash_buffer.size;
	}
#ifdef BUFFERS_DEBUG
	_gnutls_log( "HASH BUFFER: Got %d bytes of Data\n", length);
#endif
	state->gnutls_internals.hash_buffer.size -= length;
	memcpy(data, state->gnutls_internals.hash_buffer.data, length);
	/* overwrite buffer */
	memcpy(state->gnutls_internals.hash_buffer.data,
		&state->gnutls_internals.hash_buffer.data[length],
		state->gnutls_internals.hash_buffer.size);
	state->gnutls_internals.hash_buffer.data =
	    gnutls_realloc_fast(state->gnutls_internals.hash_buffer.data,
			   state->gnutls_internals.hash_buffer.size);

	if (state->gnutls_internals.hash_buffer.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return length;	

}

/* this function does not touch the buffer
 * and returns data from it (peek mode!)
 */
int gnutls_read_handshake_buffer( GNUTLS_STATE state, char *data, int length)
{
	if (length > state->gnutls_internals.hash_buffer.size) {
		length = state->gnutls_internals.hash_buffer.size;
	}
#ifdef BUFFERS_DEBUG
	_gnutls_log( "HASH BUFFER: Read %d bytes of Data\n", length);
#endif
	memcpy(data, state->gnutls_internals.hash_buffer.data, length);
	return length;	
}



int gnutls_clear_handshake_buffer( GNUTLS_STATE state)
{

#ifdef BUFFERS_DEBUG
	_gnutls_log( "HASH BUFFER: Cleared Data from buffer\n");
#endif
	state->gnutls_internals.hash_buffer.size = 0;
	if (state->gnutls_internals.hash_buffer.data!=NULL)
		gnutls_free(state->gnutls_internals.hash_buffer.data);
	state->gnutls_internals.hash_buffer.data = NULL;
	
	return 0;
}
