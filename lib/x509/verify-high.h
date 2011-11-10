struct named_cert_st {
  gnutls_x509_crt_t cert;
  uint8_t name[MAX_NAME_SIZE];
  unsigned int name_size;
};

struct node_st {
  /* The trusted certificates */
  gnutls_x509_crt_t *trusted_cas;
  unsigned int trusted_ca_size;

  struct named_cert_st *named_certs;
  unsigned int named_cert_size;

  /* The trusted CRLs */
  gnutls_x509_crl_t *crls;
  unsigned int crl_size;
};

struct gnutls_x509_trust_list_st {
  int size;
  struct node_st *node;
};

#define INIT_HASH 0x33a1
