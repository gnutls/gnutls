#include <gnutls/x509.h>
#include <stdio.h>

enum
{
  ACTION_SELF_SIGNED,
  ACTION_GENERATE_PRIVKEY,
  ACTION_CERT_INFO,
  ACTION_GENERATE_REQUEST,
  ACTION_GENERATE_CERTIFICATE,
  ACTION_VERIFY_CHAIN,
  ACTION_PRIVKEY_INFO,
  ACTION_UPDATE_CERTIFICATE,
  ACTION_TO_PKCS12,
  ACTION_PKCS12_INFO,
  ACTION_GENERATE_DH,
  ACTION_GET_DH,
  ACTION_CRL_INFO,
  ACTION_P7_INFO,
  ACTION_GENERATE_CRL,
  ACTION_VERIFY_CRL,
  ACTION_SMIME_TO_P7,
  ACTION_GENERATE_PROXY,
  ACTION_GENERATE_PKCS8,
  ACTION_PGP_INFO,
  ACTION_PGP_PRIVKEY_INFO,
  ACTION_RING_INFO,
  ACTION_REQUEST,
  ACTION_PKCS11_LIST,
  ACTION_PKCS11_TOKENS,
  ACTION_PKCS11_EXPORT_URL,
  ACTION_PKCS11_WRITE_URL,
  ACTION_PKCS11_DELETE_URL,
  ACTION_PUBKEY_INFO,
};

#define TYPE_CRT 1
#define TYPE_CRQ 2

void certtool_version (void);
void pkcs11_list( FILE*outfile, const char* url, int type);
void pkcs11_export(FILE* outfile, const char *pkcs11_url);
void pkcs11_token_list(FILE* outfile);
void pkcs11_write(FILE* outfile, const char *pkcs11_url, const char* label, int trusted);
void pkcs11_delete(FILE* outfile, const char *pkcs11_url, int batch);

#define PKCS11_TYPE_CRT_ALL 1
#define PKCS11_TYPE_TRUSTED 2
#define PKCS11_TYPE_PK 3
#define PKCS11_TYPE_ALL 4

extern unsigned char buffer[];
extern const int buffer_size;

#include <gnutls/x509.h>
#include <gnutls/abstract.h>

gnutls_x509_privkey_t load_private_key (int mand);
gnutls_x509_crq_t load_request (void);
gnutls_x509_privkey_t load_ca_private_key (void);
gnutls_x509_crt_t load_ca_cert (void);
gnutls_x509_crt_t load_cert (int mand);
gnutls_pubkey_t load_pubkey (int mand);
