#ifndef OPENPGP_H
# define OPENPGP_H

typedef struct gnutls_openpgp_key_int {
	cdk_kbnode_t knode;
} gnutls_openpgp_key_int;

typedef enum gnutls_openpgp_key_fmt { GNUTLS_X509_FMT_RAW,
        GNUTLS_X509_FMT_BASE64 } gnutls_openpgp_key_fmt;

typedef struct gnutls_openpgp_key_int *gnutls_openpgp_key;

int
_gnutls_map_cdk_rc( int rc);

#endif
