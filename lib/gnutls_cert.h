#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>

typedef struct {
	char common_name[X509_CN_SIZE];
	char country[X509_C_SIZE];
	char organization[X509_O_SIZE];
	char organizational_unit_name[X509_OU_SIZE];
	char locality_name[X509_L_SIZE];
	char state_or_province_name[X509_S_SIZE];
} gnutls_DN;

#define X509KEY_DIGITAL_SIGNATURE 	256
#define X509KEY_NON_REPUDIATION		128
#define X509KEY_KEY_ENCIPHERMENT	64
#define X509KEY_DATA_ENCIPHERMENT	32
#define X509KEY_KEY_AGREEMENT		16
#define X509KEY_KEY_CERT_SIGN		8
#define X509KEY_CRL_SIGN		4
#define X509KEY_ENCIPHER_ONLY		2
#define X509KEY_DECIPHER_ONLY		1


typedef struct {
	MPI *params;		/* the size of params depends on the public 
				 * key algorithm 
				 */
	PKAlgorithm subject_pk_algorithm;

	gnutls_DN  cert_info;
	gnutls_DN  issuer_info;
	opaque	   subjectAltName[X509_CN_SIZE];
	int 	   subjectAltName_size;
	
	opaque	   signature[1024];
	int	   signature_size;
	
	time_t	   expiration_time;
	time_t	   activation_time;

	int	   version; /* 1,2,3 
 	                     */
 	
 	uint8	   keyUsage; /* bits from X509KEY_* 
 	                      */
 	
	int        valid; /* 0 if the certificate looks good.
	                   */

	int        CA;    /* 0 if the certificate does not belong to
	                   * a certificate authority. 1 otherwise.
	                   */
	gnutls_datum raw; /* the raw certificate */
} gnutls_cert;

typedef struct {
	MPI *params;		/* the size of params depends on the public 
				 * key algorithm 
				 */
	PKAlgorithm pk_algorithm;

	gnutls_datum raw; /* the raw key */
} gnutls_private_key;


int _gnutls_cert_supported_kx(gnutls_cert* cert, KXAlgorithm **alg, int *alg_size);
PKAlgorithm _gnutls_map_pk_get_pk(KXAlgorithm kx_algorithm);
int _gnutls_cert2gnutlsCert(gnutls_cert * gCert, gnutls_datum derCert);
gnutls_cert* _gnutls_find_cert( gnutls_cert** cert_list, int cert_list_length, char* name);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(int k, char* data);

#endif
