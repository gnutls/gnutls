#include <auth_cert.h>

typedef int (*OPENPGP_VERIFY_KEY_FUNC) (const
					gnutls_certificate_credentials_t,
					const gnutls_datum_t *, int,
					unsigned int *);

typedef time_t(*OPENPGP_KEY_CREATION_TIME_FUNC) (const gnutls_datum_t *);
typedef time_t(*OPENPGP_KEY_EXPIRATION_TIME_FUNC) (const gnutls_datum_t *);
typedef int (*OPENPGP_KEY_REQUEST) (gnutls_session_t, gnutls_datum_t *,
				    const gnutls_certificate_credentials_t,
				    opaque *, int);

typedef int (*OPENPGP_FINGERPRINT) (const gnutls_datum_t *,
				    unsigned char *, size_t *);

typedef int (*OPENPGP_RAW_KEY_TO_GCERT) (gnutls_cert *,
					 const gnutls_datum_t *);
typedef int (*OPENPGP_RAW_PRIVKEY_TO_GKEY) (gnutls_privkey *,
					    const gnutls_datum_t *);

typedef int (*OPENPGP_KEY_TO_GCERT) (gnutls_cert *, gnutls_openpgp_key_t);
typedef int (*OPENPGP_PRIVKEY_TO_GKEY) (gnutls_privkey *,
					gnutls_openpgp_privkey_t);

typedef void (*OPENPGP_KEY_DEINIT) (gnutls_openpgp_key_t);
typedef void (*OPENPGP_PRIVKEY_DEINIT) (gnutls_openpgp_privkey_t);
