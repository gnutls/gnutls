int gnutls_insertDataBuffer(GNUTLS_STATE state, char *data, int length);
int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state);
int gnutls_getDataFromBuffer(GNUTLS_STATE state, char *data, int length);
