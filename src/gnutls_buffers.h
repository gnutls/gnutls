int gnutls_insertDataBuffer(GNUTLS_STATE state, ContentType type, char *data, int length);
int gnutls_getDataBufferSize(GNUTLS_STATE state, ContentType type);
int gnutls_getDataFromBuffer(GNUTLS_STATE state, ContentType type, char *data, int length);
