#ifndef SBUF_H
# define SBUF_H

#include <gnutls_str.h>
#include <gnutls/gnutls.h>

struct gnutls_credentials_st {
  gnutls_certificate_credentials_t xcred;
  char tofu_file[MAX_FILENAME];
  unsigned vflags;
};

struct gnutls_sbuf_st {
  gnutls_session_t session;
  gnutls_buffer_st buf;

  char server_name[MAX_SERVER_NAME_SIZE];
  char service_name[MAX_SERVER_NAME_SIZE];

  gnutls_credentials_t cred;

  unsigned int flags;
};

#endif
