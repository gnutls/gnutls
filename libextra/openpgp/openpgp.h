#ifndef OPENPGP_H
# define OPENPGP_H

#include <opencdk.h>

typedef struct gnutls_openpgp_key_int {
	cdk_kbnode_t knode;
} gnutls_openpgp_key_int;

typedef enum gnutls_openpgp_key_fmt { GNUTLS_X509_FMT_RAW,
        GNUTLS_X509_FMT_BASE64 } gnutls_openpgp_key_fmt;

typedef struct gnutls_openpgp_key_int *gnutls_openpgp_key;

int
_gnutls_map_cdk_rc( int rc);
int
gnutls_openpgp_key_get_name( gnutls_openpgp_key key, 
	int idx,
        char *buf, size_t *sizeof_buf);

#endif
