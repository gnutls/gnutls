int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state);
int gnutls_getDataFromBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
ssize_t Read(int fd, void *iptr, size_t n);
ssize_t Write(int fd, const void *iptr, size_t n);
ssize_t _gnutls_Recv_int(int fd, GNUTLS_STATE state, ContentType type, void *iptr, size_t sizeOfPtr);
ssize_t _gnutls_Send_int(int fd, GNUTLS_STATE state, ContentType type, void *, size_t);

/* used in SSL3 */
int gnutls_getHashDataFromBuffer(int type, GNUTLS_STATE state, char *data, int length);
int gnutls_getHashDataBufferSize(int type, GNUTLS_STATE state);
int gnutls_insertHashDataBuffer(int type, GNUTLS_STATE state, char *data, int length);
