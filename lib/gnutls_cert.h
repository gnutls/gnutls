#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

#include <gnutls_pk.h>
#include <x509_asn1.h>
#include <gnutls_ui.h>

#define MAX_PARAMS_SIZE 2 /* ok for RSA */
typedef struct gnutls_cert {
	MPI params[MAX_PARAMS_SIZE];		/* the size of params depends on the public 
				 * key algorithm 
				 */
	PKAlgorithm subject_pk_algorithm;

	gnutls_DN  cert_info;
	gnutls_DN  issuer_info;
	opaque	   subjectAltDNSName[X509_CN_SIZE]; 
	int 	   subjectAltDNSName_size;
	
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
	MPI params[MAX_PARAMS_SIZE];/* the size of params depends on the public 
				 * key algorithm 
				 */
	PKAlgorithm pk_algorithm;

	gnutls_datum raw; /* the raw key */
} gnutls_private_key;


int _gnutls_cert_supported_kx(gnutls_cert* cert, KXAlgorithm **alg, int *alg_size);
PKAlgorithm _gnutls_map_pk_get_pk(KXAlgorithm kx_algorithm);
int _gnutls_cert2gnutlsCert(gnutls_cert * gCert, gnutls_datum derCert);
gnutls_cert* _gnutls_find_cert( gnutls_cert** cert_list, int cert_list_length, const char* name);
int _gnutls_find_cert_list_index(gnutls_cert ** cert_list,
			       int cert_list_length, const char *name);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(int k, char* data);
int _gnutls_get_name_type( node_asn *rasn, char *root, gnutls_DN * dn);
void gnutls_free_cert(gnutls_cert cert);
int _gnutls_check_x509_key_usage(gnutls_cert * cert, KXAlgorithm alg);

#endif
