#ifndef SBUF_H
# define SBUF_H

#include <gnutls_str.h>

struct gnutls_sbuf_st {
  gnutls_session_t session;
  gnutls_buffer_st buf;
  unsigned int flags;
};

#endif
