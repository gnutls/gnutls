#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"

int gnutls_insertDataBuffer(GNUTLS_STATE state, char *data, int length)
{
	int old_buffer=state->gnutls_internals.bufferSize;
	
	state->gnutls_internals.bufferSize+=length;
	state->gnutls_internals.buffer = gnutls_realloc( state->gnutls_internals.buffer, state->gnutls_internals.bufferSize);
	memmove( &state->gnutls_internals.buffer[old_buffer], data, length);

	return 0;
	
}

int gnutls_getDataBufferSize(GNUTLS_STATE state) {
	return state->gnutls_internals.bufferSize;
	return 0;
}

int gnutls_getDataFromBuffer(GNUTLS_STATE state, char *data, int length)
{
	length = state->gnutls_internals.bufferSize;
	
	state->gnutls_internals.bufferSize-=length;
	memmove( data, state->gnutls_internals.buffer, length);
		
	/* overwrite buffer */
	memmove( state->gnutls_internals.buffer, &state->gnutls_internals.buffer[length], state->gnutls_internals.bufferSize);
	state->gnutls_internals.buffer = gnutls_realloc( state->gnutls_internals.buffer, state->gnutls_internals.bufferSize);

	return length;
}
