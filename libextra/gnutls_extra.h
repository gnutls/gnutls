#include <auth_cert.h>

typedef int (*OPENPGP_VERIFY_KEY_FUNC)( const char *,
	const gnutls_datum *, const gnutls_datum*, int);
typedef time_t (*OPENPGP_KEY_CREATION_TIME_FUNC)( const gnutls_datum*);
typedef time_t (*OPENPGP_KEY_EXPIRATION_TIME_FUNC)( const gnutls_datum*);
typedef int (*OPENPGP_KEY_REQUEST)(gnutls_session, gnutls_datum*, 
	const gnutls_certificate_credentials, opaque*,int);
typedef int (*OPENPGP_FINGERPRINT)(const gnutls_datum*, unsigned char*, size_t*);

typedef int (*OPENPGP_RAW_KEY_TO_GCERT)(gnutls_cert*, const gnutls_datum*);
typedef int (*OPENPGP_RAW_PRIVKEY_TO_GKEY)(gnutls_privkey*, const gnutls_datum*);

typedef int (*OPENPGP_KEY_TO_GCERT)(gnutls_cert*, gnutls_openpgp_key);
typedef int (*OPENPGP_PRIVKEY_TO_GKEY)(gnutls_privkey*, gnutls_openpgp_privkey);

typedef void (*OPENPGP_KEY_DEINIT)(gnutls_openpgp_key);
typedef void (*OPENPGP_PRIVKEY_DEINIT)(gnutls_openpgp_privkey);
