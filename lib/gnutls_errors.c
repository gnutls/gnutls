#include "defines.h"
#include "gnutls_errors.h"

void tolow(char *str, int size);

int gnutls_is_fatal_error(int error)
{
	int ret = 0;
	GNUTLS_ERROR_ALG_LOOP(ret = p->fatal);
	return ret;
}

void gnutls_perror(int error)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_ERROR_ALG_LOOP(ret =
			      strdup(p->name + sizeof("GNUTLS_E_") - 1));


	if (ret != NULL) {
		tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = ' ';
			pointerTo_ = strchr(ret, '_');
		}
	}
	fprintf(stderr, "GNUTLS ERROR: %s\n", ret);
	
	free( ret);
}
