enum ContentType { GNUTLS_APPLICATION_DATA=23 };
typedef enum ContentType ContentType;
enum BulkCipherAlgorithm { CIPHER_NULL, CIPHER_3DES = 4 };
typedef enum BulkCipherAlgorithm BulkCipherAlgorithm;
enum MACAlgorithm { MAC_NULL, MAC_MD5, MAC_SHA };
typedef enum MACAlgorithm MACAlgorithm;
enum CompressionMethod { COMPRESSION_NULL };
typedef enum CompressionMethod CompressionMethod;
enum ConnectionEnd { GNUTLS_SERVER, GNUTLS_CLIENT };
typedef enum ConnectionEnd ConnectionEnd;

struct GNUTLS_STATE_INT;
typedef struct GNUTLS_STATE_INT* GNUTLS_STATE;

int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end);
int gnutls_deinit(GNUTLS_STATE * state);
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char* data, size_t sizeofdata);
int gnutls_close(int cd, GNUTLS_STATE state);
int gnutls_handshake(int cd, GNUTLS_STATE state);

#define gnutls_send( x, y, z, w) gnutls_send_int( x, y, GNUTLS_APPLICATION_DATA, z, w)
#define gnutls_recv( x, y, z, w) gnutls_recv_int( x, y, GNUTLS_APPLICATION_DATA, z, w)
