#ifndef PKCS11_INT_H
#define PKCS11_INT_H

#ifdef ENABLE_PKCS11

#define CRYPTOKI_GNU
#include <gnutls/pkcs11.h>

#define PKCS11_ID_SIZE 128
#define PKCS11_LABEL_SIZE 128

#define P11_KIT_API_SUBJECT_TO_CHANGE 1
#include <p11-kit/uri.h>
#include <p11-kit/pkcs11.h>

typedef unsigned char ck_bool_t;

struct token_info
{
  struct ck_token_info tinfo;
  struct ck_slot_info sinfo;
  ck_slot_id_t sid;
  struct gnutls_pkcs11_provider_s *prov;
};

struct gnutls_pkcs11_obj_st
{
  gnutls_datum_t raw;
  gnutls_pkcs11_obj_type_t type;
  struct p11_kit_uri *info;

  /* only when pubkey */
  gnutls_datum_t pubkey[MAX_PUBLIC_PARAMS_SIZE];
  gnutls_pk_algorithm pk_algorithm;
  unsigned int key_usage;
};

/* thus function is called for every token in the traverse_tokens
 * function. Once everything is traversed it is called with NULL tinfo.
 * It should return 0 if found what it was looking for.
 */
typedef int (*find_func_t) (struct ck_function_list *module,
                            ck_session_handle_t pks,
                            struct token_info * tinfo, struct ck_info *,
                            void *input);

int pkcs11_rv_to_err (ck_rv_t rv);
int pkcs11_url_to_info (const char *url, struct p11_kit_uri **info);
int
pkcs11_find_slot (struct ck_function_list ** module, ck_slot_id_t * slot,
                  struct p11_kit_uri *info, struct token_info *_tinfo);

int pkcs11_get_info (struct p11_kit_uri *info,
                     gnutls_pkcs11_obj_info_t itype, void *output,
                     size_t * output_size);
int pkcs11_login (struct ck_function_list * module, ck_session_handle_t pks,
                  const struct token_info *tinfo, struct p11_kit_uri *info, int admin);

int pkcs11_call_token_func (struct p11_kit_uri *info, const unsigned retry);

extern gnutls_pkcs11_token_callback_t token_func;
extern void *token_data;

void pkcs11_rescan_slots (void);
int pkcs11_info_to_url (struct p11_kit_uri *info,
                        gnutls_pkcs11_url_type_t detailed, char **url);

#define SESSION_WRITE (1<<0)
#define SESSION_LOGIN (1<<1)
#define SESSION_SO (1<<2)       /* security officer session */
int pkcs11_open_session (struct ck_function_list **_module, ck_session_handle_t * _pks,
                         struct p11_kit_uri *info, unsigned int flags);
int _pkcs11_traverse_tokens (find_func_t find_func, void *input,
                             struct p11_kit_uri *info, unsigned int flags);
ck_object_class_t pkcs11_strtype_to_class (const char *type);

int pkcs11_token_matches_info (struct p11_kit_uri *info,
                               struct ck_token_info *tinfo,
                               struct ck_info *lib_info);

/* flags are SESSION_* */
int pkcs11_find_object (struct ck_function_list ** _module,
                        ck_session_handle_t * _pks,
                        ck_object_handle_t * _obj,
                        struct p11_kit_uri *info, unsigned int flags);

unsigned int pkcs11_obj_flags_to_int (unsigned int flags);

int
_gnutls_pkcs11_privkey_sign_hash (gnutls_pkcs11_privkey_t key,
                                  const gnutls_datum_t * hash,
                                  gnutls_datum_t * signature);

int
_gnutls_pkcs11_privkey_decrypt_data (gnutls_pkcs11_privkey_t key,
                                    unsigned int flags,
                                    const gnutls_datum_t * ciphertext,
                                    gnutls_datum_t * plaintext);

ck_rv_t
pkcs11_get_slot_list (struct ck_function_list * module,
                      unsigned char token_present,
                      ck_slot_id_t *slot_list,
                      unsigned long *count);

ck_rv_t
pkcs11_get_module_info (struct ck_function_list * module,
                        struct ck_info * info);

ck_rv_t
pkcs11_get_slot_info(struct ck_function_list * module,
                     ck_slot_id_t slot_id,
                     struct ck_slot_info *info);

ck_rv_t
pkcs11_get_token_info (struct ck_function_list * module,
                       ck_slot_id_t slot_id,
                       struct ck_token_info *info);

ck_rv_t
pkcs11_find_objects_init (struct ck_function_list *module,
                          ck_session_handle_t sess,
                          struct ck_attribute *templ,
                          unsigned long count);

ck_rv_t
pkcs11_find_objects (struct ck_function_list *module,
                       ck_session_handle_t sess,
                       ck_object_handle_t *objects,
                       unsigned long max_object_count,
                       unsigned long *object_count);

ck_rv_t
pkcs11_find_objects_final (struct ck_function_list *module,
                           ck_session_handle_t sess);

ck_rv_t
pkcs11_close_session (struct ck_function_list *module,
                      ck_session_handle_t sess);

ck_rv_t
pkcs11_get_attribute_value(struct ck_function_list *module,
                           ck_session_handle_t sess,
                           ck_object_handle_t object,
                           struct ck_attribute *templ,
                           unsigned long count);

ck_rv_t
pkcs11_get_mechanism_list (struct ck_function_list *module,
                           ck_slot_id_t slot_id,
                           ck_mechanism_type_t *mechanism_list,
                           unsigned long *count);

ck_rv_t
pkcs11_sign_init (struct ck_function_list *module,
                  ck_session_handle_t sess,
                  struct ck_mechanism *mechanism,
                  ck_object_handle_t key);

ck_rv_t
pkcs11_sign (struct ck_function_list *module,
             ck_session_handle_t sess,
             unsigned char *data,
             unsigned long data_len,
             unsigned char *signature,
             unsigned long *signature_len);

ck_rv_t
pkcs11_decrypt_init (struct ck_function_list *module,
                     ck_session_handle_t sess,
                     struct ck_mechanism *mechanism,
                     ck_object_handle_t key);

ck_rv_t
pkcs11_decrypt (struct ck_function_list *module,
                ck_session_handle_t sess,
                unsigned char *encrypted_data,
                unsigned long encrypted_data_len,
                unsigned char *data, unsigned long *data_len);

ck_rv_t
pkcs11_create_object (struct ck_function_list *module,
                      ck_session_handle_t sess,
                      struct ck_attribute *templ,
                      unsigned long count,
                      ck_object_handle_t *object);

ck_rv_t
pkcs11_destroy_object (struct ck_function_list *module,
                       ck_session_handle_t sess,
                       ck_object_handle_t object);

ck_rv_t
pkcs11_init_token (struct ck_function_list *module,
                   ck_slot_id_t slot_id, unsigned char *pin,
                   unsigned long pin_len, unsigned char *label);

ck_rv_t
pkcs11_init_pin (struct ck_function_list *module,
                 ck_session_handle_t sess,
                 unsigned char *pin,
                 unsigned long pin_len);

ck_rv_t
pkcs11_set_pin (struct ck_function_list *module,
                ck_session_handle_t sess,
                unsigned char *old_pin,
                unsigned long old_len,
                unsigned char *new_pin,
                unsigned long new_len);

const char *
pkcs11_strerror (ck_rv_t rv);

#endif /* ENABLE_PKCS11 */

#endif
