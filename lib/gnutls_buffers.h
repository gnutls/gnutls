int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state);
int gnutls_getDataFromBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
ssize_t _gnutls_Read(int fd, void *iptr, size_t n);
ssize_t _gnutls_Write(int fd, const void *iptr, size_t n);

/* used in SSL3 */
int gnutls_getHashDataFromBuffer(int type, GNUTLS_STATE state, char *data, int length);
int gnutls_getHashDataBufferSize(int type, GNUTLS_STATE state);
int gnutls_readHashDataFromBuffer(int type, GNUTLS_STATE state, char *data, int length);
int gnutls_insertHashDataBuffer(int type, GNUTLS_STATE state, char *data, int length);
int gnutls_clearHashDataBuffer(int type, GNUTLS_STATE state);
