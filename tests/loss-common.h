#define min(x,y) ((x)<(y)?(x):(y))

char tmpbuf[128];
extern const char* prefix;

#define HANDSHAKE_EXPECT(c, s, clierr, serverr) \
  sret = cret = GNUTLS_E_AGAIN; \
  do \
    { \
      if (cret == GNUTLS_E_AGAIN) \
        { \
          prefix = "client"; \
          cret = gnutls_handshake (c); \
        } \
      else if (cret >= 0) \
        { \
          prefix = "client"; \
          ret = gnutls_record_recv(c, tmpbuf, sizeof(tmpbuf)); \
        } \
      if (sret == GNUTLS_E_AGAIN) \
        { \
          prefix = "server"; \
          sret = gnutls_handshake (s); \
        } \
      else if (sret >= 0) \
        { \
          prefix = "server"; \
          ret = gnutls_record_recv(s, tmpbuf, sizeof(tmpbuf)); \
        } \
    } \
  while ((cret == GNUTLS_E_AGAIN || (cret == 0 && sret == GNUTLS_E_AGAIN)) && (sret == GNUTLS_E_AGAIN || (sret == 0 && cret == GNUTLS_E_AGAIN))); \
  if (cret != clierr || sret != serverr) \
    { \
      fprintf(stderr, "client: %s\n", gnutls_strerror(cret)); \
      fprintf(stderr, "server: %s\n", gnutls_strerror(sret)); \
      fail("Handshake failed\n"); \
      exit(1); \
    }

#define HANDSHAKE(c, s) \
  HANDSHAKE_EXPECT(c,s,0,0)

#define TRANSFER(c, s, msg, msglen, buf, buflen) \
  sret = cret = GNUTLS_E_AGAIN; \
  do \
    { \
      if (cret == GNUTLS_E_AGAIN) \
        { \
          prefix = "client"; \
          cret = gnutls_record_send (c, msg, msglen); \
        } \
      if (sret == GNUTLS_E_AGAIN) \
        { \
          prefix = "server"; \
          sret = gnutls_record_recv (s, buf, buflen); \
        } \
    } \
  while ((cret == GNUTLS_E_AGAIN || (cret >= 0 && sret == GNUTLS_E_AGAIN)) && (sret == GNUTLS_E_AGAIN || (sret >= 0 && cret == GNUTLS_E_AGAIN))); \
  \
  if (cret < 0) fail ("client send error: %s\n", gnutls_strerror (ret)); \
  if (sret < 0) fail ("server send error: %s\n", gnutls_strerror (ret))

static char to_server[64*1024];
static size_t to_server_len = 0;

static char to_client[64*1024];
static size_t to_client_len = 0;

extern int counter;
extern int packet_to_lose;

#ifdef LOSS_DEBUG
# define RETURN_RND_LOSS(session, len) { \
  if (counter++ == packet_to_lose) \
    { \
    int t = gnutls_handshake_get_last_out(session); \
    fprintf(stderr, "Discarding packet (%d) with seq %d\n", \
        t, counter); \
      return len; \
    } \
  }
#else
# define RETURN_RND_LOSS(session, len) { \
  if (counter++ == packet_to_lose) \
    { \
      return len; \
    } \
  }
#endif

static void reset_counters(void)
{
  to_client_len = to_server_len = 0;
}

static ssize_t
client_push (gnutls_transport_ptr_t tr, const void *data, size_t len)
{
  size_t newlen;

  len = min(len, sizeof(to_server)-to_server_len);
//  RETURN_RND_LOSS(tr, len);

  newlen = to_server_len + len;
  memcpy (to_server + to_server_len, data, len);
  to_server_len = newlen;
#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: pushed %d bytes to server (avail: %d)\n", (int)len, (int)to_server_len);
#endif
  return len;
}

static ssize_t
client_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  if (to_client_len == 0)
    {
#ifdef LOSS_DEBUG2
      fprintf(stderr, "loss: Not enough data by server (asked for: %d, have: %d)\n", (int)len, (int)to_client_len);
#endif
      return -1;
    }

  len = min(len, to_client_len);

  memcpy (data, to_client, len);
  memmove (to_client, to_client + len, to_client_len - len);
  to_client_len -= len;
#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: pulled %d bytes by client (avail: %d)\n", (int)len, (int)to_client_len);
#endif
  return len;
}

static ssize_t
server_pull (gnutls_transport_ptr_t tr, void *data, size_t len)
{
  if (to_server_len == 0)
    {
#ifdef LOSS_DEBUG2
      fprintf(stderr, "loss: Not enough data by client (asked for: %d, have: %d)\n", (int)len, (int)to_server_len);
#endif
      return -1;
    }

  len = min(len, to_server_len);
#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: pulled %d bytes by server (avail: %d)\n", (int)len, (int)to_server_len);
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

//  hexprint (data, len);

  len = min(len, sizeof(to_client)-to_client_len);
  RETURN_RND_LOSS(tr, len);

  newlen = to_client_len + len;
  memcpy (to_client + to_client_len, data, len);
  to_client_len = newlen;
#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: pushed %d bytes to client (avail: %d)\n", (int)len, (int)to_client_len);
#endif

  return len;
}

/* inline is used to avoid a gcc warning if used in mini-loss */
inline static int server_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
int ret;

  if (to_server_len > 0)
    ret = 1; /* available data */
  else
    ret = 0; /* timeout */

#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: server_pull_timeout: %d\n", ret);
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

#ifdef LOSS_DEBUG
  fprintf(stderr, "loss: client_pull_timeout: %d\n", ret);
#endif

  return ret;
}

inline static void reset_buffers(void)
{
  to_server_len = 0;
  to_client_len = 0;
}
