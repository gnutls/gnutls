int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state);
int gnutls_getDataFromBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
ssize_t _gnutls_Read(int fd, void *iptr, size_t n, int flag);
ssize_t _gnutls_Write(int fd, const void *iptr, size_t n);

/* used in SSL3 */
int gnutls_getHashDataFromBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_getHashDataBufferSize( GNUTLS_STATE state);
int gnutls_readHashDataFromBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_insertHashDataBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_clearHashDataBuffer( GNUTLS_STATE state);

ssize_t _gnutls_Recv_int(int fd, GNUTLS_STATE state, ContentType type, void *iptr, size_t sizeOfPtr);
ssize_t _gnutls_Send_int(int fd, GNUTLS_STATE state, ContentType type, void *iptr, size_t n);
