#ifndef GNUTLS_CERT_H
# define GNUTLS_CERT_H

typedef struct {
	char common_name[256];
	char country[3];
	char organization[256];
	char organizational_unit_name[256];
	char locality_name[256];
	char state_or_province_name[256];
} gnutls_DN;

typedef enum PKAlgorithm { GNUTLS_PK_RSA = 1, GNUTLS_PK_DSA,	/* sign only */
	GNUTLS_PK_DH
} PKAlgorithm;

typedef struct {
	MPI *params;		/* the size of params depends on the public 
				 * key algorithm 
				 */
	PKAlgorithm subject_pk_algorithm;

	gnutls_DN  cert_info;
	gnutls_DN  issuer_info;

	time_t	   expiration_time;
	time_t	   activation_time;

	int	   version; /* 1,2,3 
	                     */
	int        valid; /* 0 if the certificate looks good.
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

#endif
