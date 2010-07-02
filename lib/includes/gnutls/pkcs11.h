#ifndef __GNUTLS_PKCS11_H
#define __GNUTLS_PKCS11_H


#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define GNUTLS_PKCS11_MAX_PIN_LEN 32

/* Token callback function. The callback will be used to
 * ask the user to re-enter the token with given null terminated
 * label. Callback should return zero if token has been inserted
 * by user and a negative error code otherwise. It might be called
 * multiple times if the token is not detected and the retry counter
 * will be increased.
 */
typedef int (*gnutls_pkcs11_token_callback_t)(
	void * const global_data,
	const char * const label,
	const unsigned retry
);

/* flags */
#define GNUTLS_PKCS11_PIN_FINAL_TRY (1<<0)
#define GNUTLS_PKCS11_PIN_COUNT_LOW (1<<1)

typedef int (*gnutls_pkcs11_pin_callback_t)(void *userdata, int attempt,
		const char *token_url, const char *token_label,
		unsigned int flags, char *pin, size_t pin_max);

struct gnutls_pkcs11_obj_st;
typedef struct gnutls_pkcs11_obj_st* gnutls_pkcs11_obj_t;


#define GNUTLS_PKCS11_FLAG_MANUAL 0 /* Manual loading of libraries */
#define GNUTLS_PKCS11_FLAG_AUTO 1 /* Automatically load libraries by reading /etc/gnutls/pkcs11.conf */

/* pkcs11.conf format:
 * load = /lib/xxx-pkcs11.so
 * load = /lib/yyy-pkcs11.so
 */

int gnutls_pkcs11_init (unsigned int flags, const char* configfile);
void gnutls_pkcs11_deinit (void);
void gnutls_pkcs11_set_token_function(gnutls_pkcs11_token_callback_t fn, void *userdata);
void gnutls_pkcs11_set_pin_function (gnutls_pkcs11_pin_callback_t callback, void * data);
int gnutls_pkcs11_add_provider (const char * name, const char * params);
int gnutls_pkcs11_obj_init ( gnutls_pkcs11_obj_t *certificate);

#define GNUTLS_PKCS11_OBJ_FLAG_LOGIN (1<<0) /* force login in the token for the operation */
#define GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED (1<<1) /* object marked as trusted */
#define GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE (1<<2) /* object marked as sensitive (unexportable) */

int gnutls_pkcs11_obj_import_url (gnutls_pkcs11_obj_t, const char * url,
	unsigned int flags/* GNUTLS_PKCS11_OBJ_FLAG_* */);
int gnutls_pkcs11_obj_export_url (gnutls_pkcs11_obj_t, char** url);
void gnutls_pkcs11_obj_deinit ( gnutls_pkcs11_obj_t);

int gnutls_pkcs11_obj_export(gnutls_pkcs11_obj_t obj,
		     void *output_data, size_t * output_data_size);


int gnutls_pkcs11_copy_x509_crt(const char* token_url, gnutls_x509_crt_t crt, 
	const char* label, unsigned int flags /* GNUTLS_PKCS11_OBJ_FLAG_* */);
int gnutls_pkcs11_copy_x509_privkey(const char* token_url, 
	gnutls_x509_privkey_t crt, const char* label, unsigned int key_usage /*GNUTLS_KEY_* */,
	unsigned int flags /* GNUTLS_PKCS11_OBJ_FLAG_* */);
int gnutls_pkcs11_delete_url(const char* object_url, 
	unsigned int flags/* GNUTLS_PKCS11_OBJ_FLAG_* */);

typedef enum {
	GNUTLS_PKCS11_OBJ_ID_HEX=1,
	GNUTLS_PKCS11_OBJ_LABEL,
	GNUTLS_PKCS11_OBJ_TOKEN_LABEL,
	GNUTLS_PKCS11_OBJ_TOKEN_SERIAL,
	GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER,
	GNUTLS_PKCS11_OBJ_TOKEN_MODEL,
	GNUTLS_PKCS11_OBJ_ID,
} gnutls_pkcs11_obj_info_t;

int gnutls_pkcs11_obj_get_info(gnutls_pkcs11_obj_t crt, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);

typedef enum {
	GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL=1, /* all certificates */
	GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED, /* certificates marked as trusted */
	GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY, /* certificates with corresponding private key */
	GNUTLS_PKCS11_OBJ_ATTR_PUBKEY, /* public keys */
	GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY, /* private keys */
	GNUTLS_PKCS11_OBJ_ATTR_ALL, /* everything! */
} gnutls_pkcs11_obj_attr_t;

/* token info */
typedef enum {
	GNUTLS_PKCS11_TOKEN_LABEL,
	GNUTLS_PKCS11_TOKEN_SERIAL,
	GNUTLS_PKCS11_TOKEN_MANUFACTURER,
	GNUTLS_PKCS11_TOKEN_MODEL,
} gnutls_pkcs11_token_info_t;

typedef enum {
	GNUTLS_PKCS11_OBJ_UNKNOWN,
	GNUTLS_PKCS11_OBJ_X509_CRT,
	GNUTLS_PKCS11_OBJ_PUBKEY,
	GNUTLS_PKCS11_OBJ_PRIVKEY,
	GNUTLS_PKCS11_OBJ_SECRET_KEY,
	GNUTLS_PKCS11_OBJ_DATA,
} gnutls_pkcs11_obj_type_t;

int gnutls_pkcs11_token_get_url (unsigned int seq, char** url);
int gnutls_pkcs11_token_get_info(const char* url, gnutls_pkcs11_token_info_t, void* output, size_t *output_size);

#define GNUTLS_PKCS11_TOKEN_HW 1
int gnutls_pkcs11_token_get_flags(const char* url, unsigned int *flags);

int gnutls_pkcs11_obj_list_import_url (gnutls_pkcs11_obj_t * p_list, 
	unsigned int *const n_list, const char* url, 
	gnutls_pkcs11_obj_attr_t attrs, 
	unsigned int flags/* GNUTLS_PKCS11_OBJ_FLAG_* */);

int gnutls_x509_crt_import_pkcs11( gnutls_x509_crt_t crt, gnutls_pkcs11_obj_t pkcs11_crt);
int gnutls_x509_crt_import_pkcs11_url( gnutls_x509_crt_t crt, const char* url, 
	unsigned int flags/* GNUTLS_PKCS11_OBJ_FLAG_* */);

gnutls_pkcs11_obj_type_t gnutls_pkcs11_obj_get_type (gnutls_pkcs11_obj_t certificate);
const char* gnutls_pkcs11_type_get_name (gnutls_pkcs11_obj_type_t);

int gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t * certs,
                                   unsigned int cert_max,
                                   gnutls_pkcs11_obj_t * const pkcs11_certs,
                                   unsigned int flags/* must be zero */);


/* private key functions...*/
int gnutls_pkcs11_privkey_init (gnutls_pkcs11_privkey_t * key);
void gnutls_pkcs11_privkey_deinit (gnutls_pkcs11_privkey_t key);
int gnutls_pkcs11_privkey_get_pk_algorithm (gnutls_pkcs11_privkey_t key, unsigned int* bits);
int gnutls_pkcs11_privkey_get_info(gnutls_pkcs11_privkey_t crt, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);

int gnutls_pkcs11_privkey_import_url (gnutls_pkcs11_privkey_t key,
				  const char* url, unsigned int flags);

int gnutls_pkcs11_privkey_sign_data(gnutls_pkcs11_privkey_t signer,
				gnutls_digest_algorithm_t hash,
				unsigned int flags,
				const gnutls_datum_t * data,
				gnutls_datum_t * signature);
int gnutls_pkcs11_privkey_sign_hash (gnutls_pkcs11_privkey_t key,
				 const gnutls_datum_t * hash,
				 gnutls_datum_t * signature);
int
gnutls_pkcs11_privkey_decrypt_data(gnutls_pkcs11_privkey_t key,
				unsigned int flags, const gnutls_datum_t * ciphertext,
				gnutls_datum_t * plaintext);
int gnutls_pkcs11_privkey_export_url (gnutls_pkcs11_privkey_t key, char ** url);

/** @} */

#endif
