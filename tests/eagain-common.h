#define min(x,y) ((x)<(y)?(x):(y))
//#define EAGAIN_DEBUG
#define RANDOMIZE

static char to_server[64*1024];
static size_t to_server_len = 0;

static char to_client[64*1024];
static size_t to_client_len = 0;

#ifdef RANDOMIZE
#define RETURN_RND_EAGAIN() \
  static unsigned char rnd = 0; \
  if (rnd++ % 2 == 0) \
    { \
      gnutls_transport_set_global_errno (EAGAIN); \
      return -1; \
    }
#else
#define RETURN_RND_EAGAIN()
#endif

static ssize_t
client_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  size_t newlen;
  RETURN_RND_EAGAIN();

  len = min(len, sizeof(to_server)-to_server_len);

  newlen = to_server_len + len;
  memcpy (to_server + to_server_len, data, len);
  to_server_len = newlen;
#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: pushed %d bytes to server (avail: %d)\n", (int)len, (int)to_server_len);
#endif
  return len;
}

static ssize_t
client_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  RETURN_RND_EAGAIN();

  if (to_client_len == 0)
    {
#ifdef EAGAIN_DEBUG
      fprintf(stderr, "eagain: Not enough data by server (asked for: %d, have: %d)\n", (int)len, (int)to_client_len);
#endif
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  len = min(len, to_client_len);

  memcpy (data, to_client, len);

  memmove (to_client, to_client + len, to_client_len - len);
  to_client_len -= len;
#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: pulled %d bytes by client (avail: %d)\n", (int)len, (int)to_client_len);
#endif
  return len;
}

static ssize_t
server_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  //success ("server_pull len %d has %d\n", len, to_server_len);
  RETURN_RND_EAGAIN();

  if (to_server_len == 0)
    {
#ifdef EAGAIN_DEBUG
      fprintf(stderr, "eagain: Not enough data by client (asked for: %d, have: %d)\n", (int)len, (int)to_server_len);
#endif
      gnutls_transport_set_global_errno (EAGAIN);
      return -1;
    }

  len = min(len, to_server_len);
#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: pulled %d bytes by server (avail: %d)\n", (int)len, (int)to_server_len);
#endif
  memcpy (data, to_server, len);

  memmove (to_server, to_server + len, to_server_len - len);
  to_server_len -= len;

  return len;
}

static ssize_t
server_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  size_t newlen;
  RETURN_RND_EAGAIN();

//  hexprint (data, len);

  len = min(len, sizeof(to_client)-to_client_len);

  newlen = to_client_len + len;
  memcpy (to_client + to_client_len, data, len);
  to_client_len = newlen;
#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: pushed %d bytes to client (avail: %d)\n", (int)len, (int)to_client_len);
#endif

  return len;
}

/* inline is used to avoid a gcc warning if used in mini-eagain */
inline static int server_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
int ret;

  if (to_server_len > 0)
    ret = 1; /* available data */
  else
    ret = 0; /* timeout */

#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: server_pull_timeout: %d\n", ret);
#endif

  return ret;
}

inline static int client_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
int ret;

  if (to_client_len > 0)
    ret = 1;
  else
    ret = 0;

#ifdef EAGAIN_DEBUG
  fprintf(stderr, "eagain: client_pull_timeout: %d\n", ret);
#endif

  return ret;
}
