/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length)
{
	int old_buffer;

	if (length==0) return 0;
	if (type == GNUTLS_APPLICATION_DATA) {
		old_buffer = state->gnutls_internals.buffer.size;

		state->gnutls_internals.buffer.size += length;
#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Inserted %d bytes of Data(%d) into buffer\n", length, type);
#endif
		state->gnutls_internals.buffer.data =
		    gnutls_realloc(state->gnutls_internals.buffer.data,
			   state->gnutls_internals.buffer.size);
		memmove(&state->gnutls_internals.buffer.data[old_buffer], data, length);
	}
	if (type == GNUTLS_HANDSHAKE) {
		old_buffer = state->gnutls_internals.buffer_handshake.size;

		state->gnutls_internals.buffer_handshake.size += length;
#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Inserted %d bytes of Data(%d) into buffer\n", length, type);
#endif
		state->gnutls_internals.buffer_handshake.data =
		    gnutls_realloc(state->gnutls_internals.buffer_handshake.data,
			   state->gnutls_internals.buffer_handshake.size);
		memmove(&state->gnutls_internals.buffer_handshake.data[old_buffer], data, length);
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
	fprintf(stderr, "Read %d bytes of Data(%d) from buffer\n", length, type);
#endif
		state->gnutls_internals.buffer.size -= length;
		memmove(data, state->gnutls_internals.buffer.data, length);

		/* overwrite buffer */
		memmove(state->gnutls_internals.buffer.data,
			&state->gnutls_internals.buffer.data[length],
			state->gnutls_internals.buffer.size);
		state->gnutls_internals.buffer.data =
		    gnutls_realloc(state->gnutls_internals.buffer.data,
				   state->gnutls_internals.buffer.size);
	}
	if (type == GNUTLS_HANDSHAKE) {
		if (length > state->gnutls_internals.buffer_handshake.size) {
			length = state->gnutls_internals.buffer_handshake.size;
		}
#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Read %d bytes of Data(%d) from buffer\n", length, type);
#endif
		state->gnutls_internals.buffer_handshake.size -= length;
		memmove(data, state->gnutls_internals.buffer_handshake.data, length);

		/* overwrite buffer */
		memmove(state->gnutls_internals.buffer_handshake.data,
			&state->gnutls_internals.buffer_handshake.data[length],
			state->gnutls_internals.buffer_handshake.size);
		state->gnutls_internals.buffer_handshake.data =
		    gnutls_realloc(state->gnutls_internals.buffer_handshake.data,
				   state->gnutls_internals.buffer_handshake.size);
	}


	return length;
}

/* This function is like read. But it does not return -1 on error.
 * It does return -errno instead.
 */
ssize_t _gnutls_Read(int fd, void *iptr, size_t sizeOfPtr, int flag)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;
#ifdef READ_DEBUG
	int j,x, sum=0;
#endif


	left = sizeOfPtr;
	while (left > 0) {
		i = recv(fd, &ptr[i], left, flag);
		if (i < 0) {
			return (0-errno);
		} else {
			if (i == 0)
				break;	/* EOF */
		}

		left -= i;

	}

#ifdef READ_DEBUG
	fprintf(stderr, "read %d bytes from %d\n", (sizeOfPtr-left), fd);
	for (x=0;x<((sizeOfPtr-left)/16)+1;x++) {
		fprintf(stderr, "%.4x - ",x);
		for (j=0;j<16;j++) {
			if (sum<(sizeOfPtr-left)) {
				fprintf(stderr, "%.2x ", ((unsigned char*)ptr)[sum++]);
			}
		}
		fprintf(stderr, "\n");
	
	}
#endif


	return (sizeOfPtr - left);
}


/* This function is like write. But it does not return -1 on error.
 * It does return -errno instead.
 */
ssize_t _gnutls_Write(int fd, const void *iptr, size_t n)
{
	size_t left;
#ifdef WRITE_DEBUG
	int j,x, sum=0;
#endif
	ssize_t i = 0;
	const char *ptr = iptr;

#ifdef WRITE_DEBUG
	fprintf(stderr, "wrote %d bytes to %d\n", n, fd);
	for (x=0;x<(n/16)+1;x++) {
		fprintf(stderr, "%.4x - ",x);
		for (j=0;j<16;j++) {
			if (sum<n) {
				fprintf(stderr, "%.2x ", ((unsigned char*)ptr)[sum++]);
			}
		}
		fprintf(stderr, "\n");
	
	}
#endif
	left = n;
	while (left > 0) {
		i = write(fd, &ptr[i], left);
		if (i == -1) {
			return (0-errno);
		}
		left -= i;
	}

	return n;

}
ssize_t _gnutls_Send_int(int fd, GNUTLS_STATE state, ContentType type, void *iptr, size_t n)
{
	size_t left;
	ssize_t i = 0;
	char *ptr = iptr;

	left = n;
	while (left > 0) {
		i = gnutls_send_int(fd, state, type, &ptr[i], left, 0);
		if (i <= 0) {
			return i;
		}
		left -= i;
	}

	return n;

}

ssize_t _gnutls_Recv_int(int fd, GNUTLS_STATE state, ContentType type, void *iptr, size_t sizeOfPtr)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;

	left = sizeOfPtr;
	while (left > 0) {
		i = gnutls_recv_int(fd, state, type, &ptr[i], left, 0);
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

int gnutls_insertHashDataBuffer( GNUTLS_STATE state, char *data, int length)
{
	int old_buffer;

	if (length==0) return 0;	
	old_buffer = state->gnutls_internals.hash_buffer.size;

	state->gnutls_internals.hash_buffer.size += length;
#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Inserted %d bytes of Hash Data into buffer\n", length);
#endif
	state->gnutls_internals.hash_buffer.data =
		    gnutls_realloc(state->gnutls_internals.hash_buffer.data,
			   state->gnutls_internals.hash_buffer.size);
		memmove(&state->gnutls_internals.hash_buffer.data[old_buffer], data, length);

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
	fprintf(stderr, "Got %d bytes of Hash Data from buffer\n", length);
#endif
	state->gnutls_internals.hash_buffer.size -= length;
	memmove(data, state->gnutls_internals.hash_buffer.data, length);
	/* overwrite buffer */
	memmove(state->gnutls_internals.hash_buffer.data,
		&state->gnutls_internals.hash_buffer.data[length],
		state->gnutls_internals.hash_buffer.size);
	state->gnutls_internals.hash_buffer.data =
	    gnutls_realloc(state->gnutls_internals.hash_buffer.data,
			   state->gnutls_internals.hash_buffer.size);

	return length;	

}

int gnutls_readHashDataFromBuffer( GNUTLS_STATE state, char *data, int length)
{
	if (length > state->gnutls_internals.hash_buffer.size) {
		length = state->gnutls_internals.hash_buffer.size;
	}
#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Read %d bytes of Hash Data from buffer\n", length);
#endif
	memmove(data, state->gnutls_internals.hash_buffer.data, length);
	return length;	
}



int gnutls_clearHashDataBuffer( GNUTLS_STATE state)
{

#ifdef BUFFERS_DEBUG
	fprintf(stderr, "Cleared Hash Data from buffer\n");
#endif
	state->gnutls_internals.hash_buffer.size = 0;
	if (state->gnutls_internals.hash_buffer.data!=NULL)
		gnutls_free(state->gnutls_internals.hash_buffer.data);
	state->gnutls_internals.hash_buffer.data = NULL;
	
	return 0;
}
