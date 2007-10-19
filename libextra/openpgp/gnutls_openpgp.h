#include <config.h>

#ifdef ENABLE_OPENPGP

#ifndef GNUTLS_OPENPGP_H
#define GNUTLS_OPENPGP_H

#include <auth_cert.h>
#include <opencdk.h>

typedef struct
{
  int type;
  size_t size;
  uint8_t *data;
} keybox_blob;

typedef enum
{
  KBX_BLOB_FILE = 0x00,
  KBX_BLOB_DATA = 0x01
} keyring_blob_types;

/* OpenCDK compatible */
typedef enum
{
  KEY_ATTR_NONE = 0,
  KEY_ATTR_SHORT_KEYID = 3,
  KEY_ATTR_KEYID = 4,
  KEY_ATTR_FPR = 5
} key_attr_t;

int
gnutls_certificate_set_openpgp_key_file (gnutls_certificate_credentials_t
					 res, const char *CERTFILE,
					 const char *KEYFILE);

int gnutls_openpgp_count_key_names (const gnutls_datum_t * cert);

int gnutls_openpgp_add_keyring_mem (gnutls_datum_t * keyring,
				    const void *data, size_t len);

int gnutls_openpgp_add_keyring_file (gnutls_datum_t * keyring,
				     const char *name);

int gnutls_certificate_set_openpgp_keyring_file
  (gnutls_certificate_credentials_t c, const char *file);

int
gnutls_certificate_set_openpgp_keyring_mem (gnutls_certificate_credentials_t
					    c, const opaque * data,
					    size_t dlen);

int gnutls_openpgp_get_key (gnutls_datum_t * key,
			    gnutls_openpgp_keyring_t keyring,
			    key_attr_t by, opaque * pattern);

int gnutls_openpgp_recv_key (const char *host,
			     short port, uint32_t keyid,
			     gnutls_datum_t * key);

/* internal */
int _gnutls_openpgp_raw_key_to_gcert (gnutls_cert * cert,
				      const gnutls_datum_t * raw);

int
_gnutls_openpgp_raw_privkey_to_gkey (gnutls_privkey * pkey,
				     const gnutls_datum_t * raw_key,
				     gnutls_openpgp_cert_fmt_t format);

int
_gnutls_openpgp_request_key (gnutls_session_t,
			     gnutls_datum_t * ret,
			     const gnutls_certificate_credentials_t cred,
			     opaque * key_fpr, int key_fpr_size);

keybox_blob *kbx_read_blob (const gnutls_datum_t * keyring, size_t pos);
cdk_keydb_hd_t kbx_to_keydb (keybox_blob * blob);
void kbx_blob_release (keybox_blob * ctx);

int _gnutls_openpgp_verify_key (const gnutls_certificate_credentials_t,
				const gnutls_datum_t * cert_list,
				int cert_list_length, unsigned int *status);
int _gnutls_openpgp_fingerprint (const gnutls_datum_t * cert,
				 unsigned char *fpr, size_t * fprlen);
time_t _gnutls_openpgp_get_raw_key_creation_time (const gnutls_datum_t *
						  cert);
time_t _gnutls_openpgp_get_raw_key_expiration_time (const gnutls_datum_t *
						    cert);

#endif /*GNUTLS_OPENPGP_H */

#endif /*ENABLE_OPENPGP */
