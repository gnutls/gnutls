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

int gnutls_is_fatal_error( int error);
void gnutls_perror( int error);

#define gnutls_send( x, y, z, w) gnutls_send_int( x, y, GNUTLS_APPLICATION_DATA, z, w)
#define gnutls_recv( x, y, z, w) gnutls_recv_int( x, y, GNUTLS_APPLICATION_DATA, z, w)


#define	GNUTLS_E_MAC_FAILED -1
#define	GNUTLS_E_UNKNOWN_CIPHER -2
#define	GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define	GNUTLS_E_UNKNOWN_MAC_ALGORITHM -4
#define	GNUTLS_E_UNKNOWN_ERROR -5
#define	GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define	GNUTLS_E_LARGE_PACKET -7
#define GNUTLS_E_UNSUPPORTED_VERSION_PACKET -8
#define GNUTLS_E_UNEXPECTED_PACKET_LENGTH -9
#define GNUTLS_E_INVALID_SESSION -10
#define GNUTLS_E_UNABLE_SEND_DATA -11
#define GNUTLS_E_FATAL_ALERT_RECEIVED -12
#define GNUTLS_E_RECEIVED_BAD_MESSAGE -13
#define GNUTLS_E_RECEIVED_MORE_DATA -14
#define GNUTLS_E_UNEXPECTED_PACKET -15
#define GNUTLS_E_WARNING_ALERT_RECEIVED -16
#define GNUTLS_E_CLOSURE_ALERT_RECEIVED -17
