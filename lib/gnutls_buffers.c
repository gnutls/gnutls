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

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifndef EAGAIN
# define EAGAIN EWOULDBLOCK
#endif

extern ssize_t (*_gnutls_recv_func)( SOCKET, void*, size_t, int);
extern ssize_t (*_gnutls_send_func)( SOCKET,const void*, size_t, int);

/* Buffers received packets of type APPLICATION DATA and
 * HANDSHAKE DATA.
 */
int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length)
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

int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state)
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
	return gnutls_getDataBufferSize(GNUTLS_APPLICATION_DATA, state);
}

int gnutls_getDataFromBuffer(ContentType type, GNUTLS_STATE state, char *data, int length)
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
 */
static ssize_t _gnutls_Read(int fd, void *iptr, size_t sizeOfPtr, int flag)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;
#ifdef READ_DEBUG
	int j,x, sum=0;
#endif


	left = sizeOfPtr;
	while (left > 0) {
		i = _gnutls_recv_func(fd, &ptr[i], left, flag);
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
					//return sizeOfPtr-left;
				}
				if (errno==EAGAIN) return GNUTLS_E_AGAIN;
				else return GNUTLS_E_INTERRUPTED;
			} else 
				return GNUTLS_E_UNKNOWN_ERROR;
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
char peekdata1;
char *peekdata2;

	if (state->gnutls_internals.have_peeked_data==0)
		return 0;
		
	if (RCVLOWAT != 1) {
		if (RCVLOWAT == 0)
			return 0;
			
		peekdata2 = gnutls_malloc( RCVLOWAT);
	
	        /* this was already read by using MSG_PEEK - so it shouldn't fail */
	        _gnutls_Read( cd, peekdata2, RCVLOWAT, 0); 
        
      		gnutls_free(peekdata2);
        } else {
	        _gnutls_Read( cd, &peekdata1, RCVLOWAT, 0); 
        }
	state->gnutls_internals.have_peeked_data=0;

       	return 0;
}


void _gnutls_read_clear_buffer( GNUTLS_STATE state) {
	state->gnutls_internals.recv_buffer_data_size = 0;
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
 */
ssize_t _gnutls_read_buffered( int fd, GNUTLS_STATE state, opaque **iptr, size_t sizeOfPtr, int flag, ContentType recv_type)
{
	ssize_t ret=0, ret2=0;
	int min;
	char *buf;
	int recvlowat = RCVLOWAT;
	int recvdata;

	*iptr = NULL;

	if ( sizeOfPtr > MAX_RECV_SIZE || sizeOfPtr == 0) {
		gnutls_assert(); /* internal error */
		return GNUTLS_E_UNKNOWN_ERROR;
	}
	
	/* leave peeked data to the kernel space only if application data
	 * is received and we don't have any peeked 
	 * data in gnutls state.
	 */
	if ( (recv_type != GNUTLS_APPLICATION_DATA)
		&& state->gnutls_internals.have_peeked_data==0)
		recvlowat = 0;

	buf = state->gnutls_internals.recv_buffer_data;

	*iptr = buf;
	
	/* calculate the actual size, ie. get the minimum of the
	 * buffered data and the requested data.
	 */
	min = GMIN( state->gnutls_internals.recv_buffer_data_size, sizeOfPtr);
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

	/* read fresh data - but leave RCVLOWAT bytes in the kernel buffer.
	 */
	if ( recvdata - recvlowat > 0) {
		ret = _gnutls_Read( fd, &buf[min], recvdata - recvlowat, flag);

		/* return immediately if we got an interrupt or eagain
		 * error.
		 */
		if (ret < 0 && gnutls_is_fatal_error(ret)==0) 
			return ret;
	}

	if (ret >= 0 && recvlowat > 0) {
		ret2 = _gnutls_Read( fd, &buf[min+ret], recvlowat, MSG_PEEK|flag);

		if (ret2 < 0 && gnutls_is_fatal_error(ret2)==0) 
			return ret2;

		if (ret2 > 0)
			state->gnutls_internals.have_peeked_data = 1;
	}

	if (ret < 0 || ret2 < 0) {
		gnutls_assert();
		/* that's because they are initilized to 0 */
		return GMIN(ret, ret2);
	}

	ret += ret2;

#ifdef READ_DEBUG
	_gnutls_log("RB: Have %d bytes into buffer. Adding %d bytes.\nRB: Requested %d bytes\n", state->gnutls_internals.recv_buffer_data_size, ret, sizeOfPtr);
#endif

	if (ret > 0 && ret < recvlowat) {
		gnutls_assert();
		return GNUTLS_E_AGAIN;
	}
	
	/* copy fresh data to our buffer.
	 */
	state->gnutls_internals.recv_buffer_data_size += ret;

	if (ret==0) { /* EOF */
		gnutls_assert();
		return 0;
	}

	ret = state->gnutls_internals.recv_buffer_data_size;

	if ((ret > 0) && (ret < sizeOfPtr)) {
		/* Short Read */
		gnutls_assert();
		return GNUTLS_E_AGAIN;
	} else {
		return ret;
	}
}


/* This function is like write. But it does not return -1 on error.
 * It does return -errno instead.
 */
ssize_t _gnutls_write(int fd, const void *iptr, size_t n, int flags)
{
	size_t left;
#ifdef WRITE_DEBUG
	int j,x, sum=0;
#endif
	ssize_t i = 0;
	const char *ptr = iptr;

#ifdef WRITE_DEBUG
	_gnutls_log( "WRITE: wrote %d bytes to %d\n", n, fd);
	for (x=0;x<(n/16)+1;x++) {
		_gnutls_log( "%.4x - ",x);
		for (j=0;j<16;j++) {
			if (sum<n) {
				_gnutls_log( "%.2x ", ((unsigned char*)ptr)[sum++]);
			}
		}
		_gnutls_log( "\n");
	
	}
#endif
	left = n;
	while (left > 0) {
		i = _gnutls_send_func(fd, &ptr[i], left, flags);
		if (i == -1) {
#if 0 /* currently this is not right, since the functions
       * above this, cannot handle interrupt, and eagain errors.
       */
			if (errno == EAGAIN || errno == EINTR) {
				if (n-left > 0) {
					gnutls_assert();
					return n-left;
				}
				
				if (errno==EAGAIN) return GNUTLS_E_AGAIN;
				else return GNUTLS_E_INTERRUPTED;
			} else {
				gnutls_assert();
				return GNUTLS_E_UNKNOWN_ERROR;
			}
#endif
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;

		}
		left -= i;
	}

	return n;

}

/* This is a send function for the gnutls handshake 
 * protocol. Just makes sure that all data have been sent.
 */
ssize_t _gnutls_handshake_send_int(int fd, GNUTLS_STATE state, ContentType type, HandshakeType htype, void *iptr, size_t n)
{
	size_t left;
	ssize_t i = 0;
	char *ptr = iptr;

	left = n;
	while (left > 0) {
		i = gnutls_send_int(fd, state, type, htype, &ptr[i], left, 0);
		if (i <= 0) {
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
		i = gnutls_recv_int(fd, state, type, htype, &ptr[i], left, 0);
		if (i < 0) {
			return i;
		} else {
			if (i == 0)
				break;	/* EOF */
		}

		left -= i;

	}

	return (sizeOfPtr - left);
}

/* Buffer for handshake packets. Keeps the packets in order
 * for finished messages to use them.
 */
int gnutls_insertHashDataBuffer( GNUTLS_STATE state, char *data, int length)
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

int gnutls_getHashDataBufferSize( GNUTLS_STATE state)
{

	return state->gnutls_internals.hash_buffer.size;
}

int gnutls_getHashDataFromBuffer( GNUTLS_STATE state, char *data, int length)
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
 */
int gnutls_readHashDataFromBuffer( GNUTLS_STATE state, char *data, int length)
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



int gnutls_clearHashDataBuffer( GNUTLS_STATE state)
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
