#include <config.h>

#ifdef HAVE_LIBOPENCDK

#ifndef OPENPGP_H
# define OPENPGP_H

#include <opencdk.h>

typedef struct gnutls_openpgp_key_int {
	cdk_kbnode_t knode;
} gnutls_openpgp_key_int;

typedef struct gnutls_openpgp_keyring_int {
	cdk_keydb_hd_t hd;
} gnutls_openpgp_keyring_int;

typedef struct gnutls_openpgp_trustdb_int {
	cdk_stream_t st;
} gnutls_openpgp_trustdb_int;

typedef enum gnutls_openpgp_key_fmt { GNUTLS_X509_FMT_RAW,
        GNUTLS_X509_FMT_BASE64 } gnutls_openpgp_key_fmt;

typedef struct gnutls_openpgp_key_int *gnutls_openpgp_key;
typedef struct gnutls_openpgp_keyring_int *gnutls_openpgp_keyring;
typedef struct gnutls_openpgp_trustdb_int *gnutls_openpgp_trustdb;

int
_gnutls_map_cdk_rc( int rc);
int
gnutls_openpgp_key_get_name( gnutls_openpgp_key key, 
	int idx,
        char *buf, size_t *sizeof_buf);
int gnutls_openpgp_key_get_fingerprint( gnutls_openpgp_key key, 
                            unsigned char *fpr, size_t *fprlen);
int gnutls_openpgp_key_get_pk_algorithm( gnutls_openpgp_key key, int *r_bits);
int gnutls_openpgp_key_get_version( gnutls_openpgp_key key);
time_t gnutls_openpgp_key_get_creation_time( gnutls_openpgp_key key);
time_t gnutls_openpgp_key_get_expiration_time( gnutls_openpgp_key key);
int gnutls_openpgp_key_get_id( gnutls_openpgp_key key,
                               unsigned char keyid[8]);

int gnutls_openpgp_key_init(gnutls_openpgp_key * key);
void gnutls_openpgp_key_deinit(gnutls_openpgp_key key);
int gnutls_openpgp_key_import(gnutls_openpgp_key key, 
	const gnutls_datum * data, gnutls_openpgp_key_fmt format);


void gnutls_openpgp_keyring_deinit(gnutls_openpgp_keyring keyring);
int gnutls_openpgp_keyring_init(gnutls_openpgp_keyring * keyring);
int gnutls_openpgp_keyring_import(gnutls_openpgp_keyring keyring, 
	const gnutls_datum * data,
	gnutls_openpgp_key_fmt format);

void gnutls_openpgp_trustdb_deinit(gnutls_openpgp_trustdb trustdb);
int gnutls_openpgp_trustdb_init(gnutls_openpgp_trustdb * trustdb);
int gnutls_openpgp_trustdb_import_file(gnutls_openpgp_trustdb trustdb, 
	const char * file);

int gnutls_openpgp_key_verify_ring( gnutls_openpgp_key key,
                           gnutls_openpgp_keyring keyring,
                           unsigned int flags, unsigned int *verify);

int gnutls_openpgp_key_verify_trustdb( gnutls_openpgp_key key, 
	gnutls_openpgp_trustdb trustdb,
        unsigned int flags, unsigned int *verify);

#endif

#endif /* HAVE_LIBOPENCDK */
