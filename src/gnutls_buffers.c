#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"

int gnutls_insertDataBuffer(GNUTLS_STATE state, char *data, int length)
{
	int old_buffer = state->gnutls_internals.bufferSize;

	state->gnutls_internals.bufferSize += length;
	state->gnutls_internals.buffer =
	    gnutls_realloc(state->gnutls_internals.buffer,
			   state->gnutls_internals.bufferSize);
	memmove(&state->gnutls_internals.buffer[old_buffer], data, length);

	return 0;

}

int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state)
{
	if (type == GNUTLS_APPLICATION_DATA)
		return state->gnutls_internals.bufferSize;
	return -1;
}

int gnutls_getDataFromBuffer(GNUTLS_STATE state, char *data, int length)
{
	length = state->gnutls_internals.bufferSize;

	state->gnutls_internals.bufferSize -= length;
	memmove(data, state->gnutls_internals.buffer, length);

	/* overwrite buffer */
	memmove(state->gnutls_internals.buffer,
		&state->gnutls_internals.buffer[length],
		state->gnutls_internals.bufferSize);
	state->gnutls_internals.buffer =
	    gnutls_realloc(state->gnutls_internals.buffer,
			   state->gnutls_internals.bufferSize);

	return length;
}

ssize_t Read(int fd, void *iptr, size_t sizeOfPtr)
{
	size_t left;
	ssize_t i=0;
	char *ptr = iptr;

	left = sizeOfPtr;
	while (left > 0) {
		i = read(fd, &ptr[i], left);
		if (i < 0) {
			return -1;
		} else {
			if (i == 0)
				break;	/* EOF */
		}

		left -= i;

	}

	return (sizeOfPtr - left);
}


ssize_t Write(int fd, const void *iptr, size_t n)
{
	size_t left;
	ssize_t i = 0;
	const char *ptr = iptr;

	left = n;
	while (left > 0) {
		i = write(fd, &ptr[i], left);
		if (i <= 0) {
			return -1;
		}
		left -= i;
	}

	return n;

}
