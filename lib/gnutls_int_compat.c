/* This file contains functions needed only for binary compatibility
 * with previous versions.
 */
#define GNUTLS_BACKWARDS_COMPATIBLE 

#ifdef GNUTLS_BACKWARDS_COMPATIBLE

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <x509_b64.h> /* for PKCS3 PEM decoding */
#include <gnutls_global.h>
#include <gnutls_dh.h>
#include <gnutls_rsa_export.h>
#include <gnutls_errors.h>
#include <string.h> /* memset */
#include <libtasn1.h>
#include <gnutls/compat8.h>

/* dh_compat.c */

/* Replaces the prime in the static DH parameters, with a randomly
 * generated one.
 */
/*-
  * gnutls_dh_params_set - This function will replace the old DH parameters
  * @dh_params: Is a structure will hold the prime numbers
  * @prime: holds the new prime
  * @generator: holds the new generator
  * @bits: is the prime's number of bits. This value is ignored.
  *
  * This function will replace the pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters should be stored in the
  * appropriate gnutls_datum. 
  * 
  -*/
int gnutls_dh_params_set(gnutls_dh_params dh_params, gnutls_datum prime,
			 gnutls_datum generator, int bits)
{
	GNUTLS_MPI tmp_prime, tmp_g;
	size_t siz = 0;

	/* sprime is not null, because of the check_bits()
	 * above.
	 */

	siz = prime.size;
	if (_gnutls_mpi_scan(&tmp_prime, prime.data, &siz)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = generator.size;
	if (_gnutls_mpi_scan(&tmp_g, generator.data, &siz)) {
		_gnutls_mpi_release(&tmp_prime);
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* copy the generated values to the structure
	 */
	dh_params->params[0] = tmp_prime;
	dh_params->params[1] = tmp_g;

	return 0;

}

/*-
  * gnutls_dh_params_generate - This function will generate new DH parameters
  * @prime: will hold the new prime
  * @generator: will hold the new generator
  * @bits: is the prime's number of bits
  *
  * This function will generate a new pair of prime and generator for use in 
  * the Diffie-Hellman key exchange. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * This function is normally very slow. Another function
  * (gnutls_dh_params_set()) should be called in order to replace the 
  * included DH primes in the gnutls library.
  * 
  * Note that the bits value should be one of 768, 1024, 2048, 3072 or 4096.
  * Also note that the generation of new DH parameters is only useful
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  -*/
int gnutls_dh_params_generate(gnutls_datum * prime,
			      gnutls_datum * generator, int bits)
{

	GNUTLS_MPI tmp_prime, tmp_g;
	size_t siz;

	if (_gnutls_dh_generate_prime(&tmp_g, &tmp_prime, bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	siz = 0;
	_gnutls_mpi_print(NULL, &siz, tmp_g);

	generator->data = gnutls_malloc(siz);
	if (generator->data == NULL) {
		_gnutls_mpi_release(&tmp_g);
		_gnutls_mpi_release(&tmp_prime);
		return GNUTLS_E_MEMORY_ERROR;
	}

	generator->size = siz;
	_gnutls_mpi_print(generator->data, &siz, tmp_g);


	siz = 0;
	_gnutls_mpi_print(NULL, &siz, tmp_prime);

	prime->data = gnutls_malloc(siz);
	if (prime->data == NULL) {
		gnutls_free(generator->data);
		generator->data = NULL; generator->size = 0;
		_gnutls_mpi_release(&tmp_g);
		_gnutls_mpi_release(&tmp_prime);
		return GNUTLS_E_MEMORY_ERROR;
	}
	prime->size = siz;
	_gnutls_mpi_print(prime->data, &siz, tmp_prime);

#ifdef DEBUG
	{
		opaque buffer[512];

		_gnutls_debug_log
		    ("dh_params_generate: Generated %d bits prime %s, generator %s.\n",
	     	bits, _gnutls_bin2hex(prime->data, prime->size, buffer, sizeof(buffer)),
	     	_gnutls_bin2hex(generator->data, generator->size, buffer, sizeof(buffer)));
	}
#endif

	return 0;
}

/* rsa_compat.c */

/* This function takes a number of bits and returns a supported
 * number of bits. Ie a number of bits that we have a prime in the
 * dh_primes structure.
 */

#define MAX_SUPPORTED_BITS 512

/* returns a negative value if the bits size is not supported 
 */
static int check_bits(int bits)
{
	if (bits > MAX_SUPPORTED_BITS)
		return GNUTLS_E_INVALID_REQUEST;
		
	return 0;
}


#define FREE_PRIVATE_PARAMS for (i=0;i<RSA_PRIVATE_PARAMS;i++) \
               _gnutls_mpi_release(&rsa_params->params[i]);

/*-
  * gnutls_rsa_params_set - This function will replace the old RSA parameters
  * @rsa_params: Is a structure which will hold the parameters
  * @m: holds the modulus
  * @e: holds the public exponent
  * @d: holds the private exponent
  * @p: holds the first prime (p)
  * @q: holds the second prime (q)
  * @u: holds the coefficient
  * @bits: is the modulus's number of bits
  *
  * This function will replace the parameters used in the RSA-EXPORT key
  * exchange. The new parameters should be stored in the
  * appropriate gnutls_datum. 
  * 
  * Note that the bits value should only be less than 512. That is because 
  * the RSA-EXPORT ciphersuites are only allowed to sign a modulus of 512 
  * bits.
  *
  -*/
int gnutls_rsa_params_set(gnutls_rsa_params rsa_params, 
	gnutls_datum m, gnutls_datum e,
	gnutls_datum d, gnutls_datum p, gnutls_datum q, gnutls_datum u,
	int bits) 
{
	int i;
	size_t siz;

	if (check_bits(bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	FREE_PRIVATE_PARAMS

	siz = m.size;
	if (_gnutls_mpi_scan(&rsa_params->params[0], m.data, &siz)) {
		gnutls_assert();
		failed:
		FREE_PRIVATE_PARAMS
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	siz = e.size;
	if (_gnutls_mpi_scan(&rsa_params->params[1], e.data, &siz)) {
		gnutls_assert();
		goto failed;
	}

	siz = d.size;
	if (_gnutls_mpi_scan(&rsa_params->params[2], d.data, &siz)) {
		gnutls_assert();
		goto failed;
	}

	siz = p.size;
	if (_gnutls_mpi_scan(&rsa_params->params[3], p.data, &siz)) {
		gnutls_assert();
		goto failed;
	}

	siz = q.size;
	if (_gnutls_mpi_scan(&rsa_params->params[4], q.data, &siz)) {
		gnutls_assert();
		goto failed;
	}

	siz = u.size;
	if (_gnutls_mpi_scan(&rsa_params->params[5], u.data, &siz)) {
		gnutls_assert();
		goto failed;
	}

	return 0;

}


#define FREE_ALL_MPIS for (i=0;i<sizeof(rsa_params)/sizeof(GNUTLS_MPI);i++) \
	_gnutls_mpi_release( &rsa_params[i]) \

/*-
  * gnutls_rsa_params_generate - This function will generate temporary RSA parameters
  * @m: will hold the modulus
  * @e: will hold the public exponent
  * @d: will hold the private exponent
  * @p: will hold the first prime (p)
  * @q: will hold the second prime (q)
  * @u: will hold the coefficient
  * @bits: is the prime's number of bits
  *
  * This function will generate new temporary RSA parameters for use in 
  * RSA-EXPORT ciphersuites. The new parameters will be allocated using
  * gnutls_malloc() and will be stored in the appropriate datum.
  * This function is normally slow. An other function
  * (gnutls_rsa_params_set()) should be called in order to use the 
  * generated RSA parameters.
  * 
  * Note that the bits value should be 512.
  * Also note that the generation of new RSA parameters is only useful
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  -*/
int gnutls_rsa_params_generate(gnutls_datum * m, gnutls_datum *e,
	gnutls_datum *d, gnutls_datum *p, gnutls_datum* q, 
	gnutls_datum* u, int bits)
{

	GNUTLS_MPI rsa_params[RSA_PRIVATE_PARAMS];
	size_t siz;
	uint i;
	int ret, params_len;

	if (check_bits(bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	ret = _gnutls_rsa_generate_params( rsa_params, &params_len, bits);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[0]);

	m->data = gnutls_malloc(siz);
	if (m->data == NULL) {
		FREE_ALL_MPIS;
		return GNUTLS_E_MEMORY_ERROR;
	}

	m->size = siz;
	_gnutls_mpi_print( m->data, &siz, rsa_params[0]);

	/* E */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[1]);

	e->data = gnutls_malloc(siz);
	if (e->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		return GNUTLS_E_MEMORY_ERROR;
	}

	e->size = siz;
	_gnutls_mpi_print( e->data, &siz, rsa_params[1]);

	/* D */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[2]);

	d->data = gnutls_malloc(siz);
	if (d->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		return GNUTLS_E_MEMORY_ERROR;
	}

	d->size = siz;
	_gnutls_mpi_print( d->data, &siz, rsa_params[2]);

	/* P */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[3]);

	p->data = gnutls_malloc(siz);
	if (p->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		return GNUTLS_E_MEMORY_ERROR;
	}

	p->size = siz;
	_gnutls_mpi_print(p->data, &siz, rsa_params[3]);

	/* Q */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[4]);

	q->data = gnutls_malloc(siz);
	if (q->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		return GNUTLS_E_MEMORY_ERROR;
	}

	q->size = siz;
	_gnutls_mpi_print(q->data, &siz, rsa_params[4]);

	/* U */
	siz = 0;
	_gnutls_mpi_print(NULL, &siz, rsa_params[5]);

	u->data = gnutls_malloc(siz);
	if (u->data == NULL) {
		FREE_ALL_MPIS;
		_gnutls_free_datum( m);
		_gnutls_free_datum( e);
		_gnutls_free_datum( d);
		_gnutls_free_datum( p);
		_gnutls_free_datum( q);
		return GNUTLS_E_MEMORY_ERROR;
	}

	u->size = siz;
	_gnutls_mpi_print(u->data, &siz, rsa_params[5]);

	FREE_ALL_MPIS;

#ifdef DEBUG
	{
	opaque buffer[512];

	_gnutls_debug_log("rsa_params_generate: Generated %d bits modulus %s, exponent %s.\n",
		    bits, _gnutls_bin2hex(m->data, m->size, buffer, sizeof(buffer)),
		    _gnutls_bin2hex( e->data, e->size, buffer, sizeof(buffer)));
	}
#endif

	return 0;

}

/* compat.c - X.509 */

/* This file includes all functions that were in the 0.5.x and 0.8.x
 * gnutls API. They are now implemented over the new certificate parsing
 * API.
 */

#include <x509/dn.h>
#include <x509/common.h>
#include <x509/verify.h>
#include <x509/pkcs7.h>
#include <gnutls/compat8.h>

/*-
  * gnutls_x509_extract_dn - This function parses an RDN sequence
  * @idn: should contain a DER encoded RDN sequence
  * @rdn: a pointer to a structure to hold the name
  *
  * This function will return the name of the given RDN sequence.
  * The name will be returned as a gnutls_x509_dn structure.
  * Returns a negative error code in case of an error.
  *
  -*/
int gnutls_x509_extract_dn(const gnutls_datum * idn, gnutls_x509_dn * rdn)
{
	ASN1_TYPE dn = ASN1_TYPE_EMPTY;
	int result;
	size_t len;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.Name", &dn
				   )) != ASN1_SUCCESS) {
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&dn, idn->data, idn->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		asn1_delete_structure(&dn);
		return _gnutls_asn2err(result);
	}

	memset( rdn, 0, sizeof(gnutls_x509_dn));

	len = sizeof(rdn->country);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_COUNTRY_NAME, 0, 0, rdn->country, &len);

	len = sizeof(rdn->organization);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_ORGANIZATION_NAME, 0, 0, rdn->organization, &len);

	len = sizeof(rdn->organizational_unit_name);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, rdn->organizational_unit_name, &len);

	len = sizeof(rdn->common_name);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_COMMON_NAME, 0, 0, rdn->common_name, &len);

	len = sizeof(rdn->locality_name);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_LOCALITY_NAME, 0, 0, rdn->locality_name, &len);

	len = sizeof(rdn->state_or_province_name);
	_gnutls_x509_parse_dn_oid( dn, "", OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, rdn->state_or_province_name, &len);

	len = sizeof(rdn->email);
	_gnutls_x509_parse_dn_oid( dn, "", OID_PKCS9_EMAIL, 0, 0, rdn->email, &len);

	asn1_delete_structure(&dn);

	return 0;
}

/*-
  * gnutls_x509_extract_certificate_dn - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the peer's name
  *
  * This function will return the name of the certificate holder. The name is gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  -*/
int gnutls_x509_extract_certificate_dn(const gnutls_datum * cert,
					  gnutls_x509_dn * ret)
{
	gnutls_x509_crt xcert;
	int result;
	size_t len;
	
	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}

	len = sizeof( ret->country);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_COUNTRY_NAME, 0, 0,
		ret->country, &len);

	len = sizeof( ret->organization);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_ORGANIZATION_NAME, 0, 0,
		ret->organization, &len);

	len = sizeof( ret->organizational_unit_name);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0,
		ret->organizational_unit_name, &len);

	len = sizeof( ret->common_name);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_COMMON_NAME, 0, 0,
		ret->common_name, &len);

	len = sizeof( ret->locality_name);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_LOCALITY_NAME, 0, 0,
		ret->locality_name, &len);

	len = sizeof( ret->state_or_province_name);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_X520_STATE_OR_PROVINCE_NAME, 0, 0,
		ret->state_or_province_name, &len);

	len = sizeof( ret->email);
	gnutls_x509_crt_get_dn_by_oid( xcert, OID_PKCS9_EMAIL, 0, 0,
		ret->email, &len);

	gnutls_x509_crt_deinit( xcert);

	return 0;
}

/*-
  * gnutls_x509_extract_certificate_issuer_dn - This function returns the certificate's issuer distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the issuer's name
  *
  * This function will return the name of the issuer stated in the certificate. The name is a gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  -*/
int gnutls_x509_extract_certificate_issuer_dn(const gnutls_datum * cert,
						 gnutls_x509_dn * ret)
{
	gnutls_x509_crt xcert;
	int result;
	size_t len;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}

	len = sizeof( ret->country);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_COUNTRY_NAME, 0, 0,
		ret->country, &len);

	len = sizeof( ret->organization);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_ORGANIZATION_NAME, 0, 0,
		ret->organization, &len);

	len = sizeof( ret->organizational_unit_name);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0,
		ret->organizational_unit_name, &len);

	len = sizeof( ret->common_name);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_COMMON_NAME, 0, 0,
		ret->common_name, &len);

	len = sizeof( ret->locality_name);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_LOCALITY_NAME, 0, 0,
		ret->locality_name, &len);

	len = sizeof( ret->state_or_province_name);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_X520_STATE_OR_PROVINCE_NAME, 0, 0,
		ret->state_or_province_name, &len);

	len = sizeof( ret->email);
	gnutls_x509_crt_get_issuer_dn_by_oid( xcert, OID_PKCS9_EMAIL, 0, 0,
		ret->email, &len);

	gnutls_x509_crt_deinit( xcert);

	return 0;
}


/*-
  * gnutls_x509_extract_certificate_subject_alt_name - This function returns the certificate's alternative name, if any
  * @cert: should contain an X.509 DER encoded certificate
  * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
  * @ret: is the place where the alternative name will be copied to
  * @ret_size: holds the size of ret.
  *
  * This function will return the alternative names, contained in the
  * given certificate.
  * 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will return the Alternative name, or a negative
  * error code.
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if ret_size is not enough to hold the alternative 
  * name, or the type of alternative name if everything was ok. The type is 
  * one of the enumerated GNUTLS_X509_SUBJECT_ALT_NAME.
  *
  * If the certificate does not have an Alternative name with the specified 
  * sequence number then returns GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  *
  -*/
int gnutls_x509_extract_certificate_subject_alt_name(const gnutls_datum * cert, int seq, char *ret, int *ret_size)
{
	gnutls_x509_crt xcert;
	int result;
	size_t size = *ret_size;
	
	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_subject_alt_name( xcert, seq, ret, &size, NULL);
	*ret_size = size;
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/*-
  * gnutls_x509_extract_certificate_ca_status - This function returns the certificate CA status
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return certificates CA status, by reading the 
  * basicConstraints X.509 extension. If the certificate is a CA a positive
  * value will be returned, or zero if the certificate does not have
  * CA flag set. 
  *
  * A negative value may be returned in case of parsing error.
  * If the certificate does not contain the basicConstraints extension
  * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
  *
  -*/
int gnutls_x509_extract_certificate_ca_status(const gnutls_datum * cert)
{
	gnutls_x509_crt xcert;
	int result;
	
	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_ca_status( xcert, NULL);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/*-
  * gnutls_x509_extract_certificate_activation_time - This function returns the peer's certificate activation time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's activation time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  -*/
time_t gnutls_x509_extract_certificate_activation_time(const
							  gnutls_datum *
							  cert)
{
	gnutls_x509_crt xcert;
	time_t result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_activation_time( xcert);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/*-
  * gnutls_x509_extract_certificate_expiration_time - This function returns the certificate's expiration time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's expiration time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  -*/
time_t gnutls_x509_extract_certificate_expiration_time(const
							  gnutls_datum *
							  cert)
{
	gnutls_x509_crt xcert;
	time_t result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_expiration_time( xcert);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/*-
  * gnutls_x509_extract_certificate_version - This function returns the certificate's version
  * @cert: is an X.509 DER encoded certificate
  *
  * This function will return the X.509 certificate's version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. Returns a negative value in case of an error.
  *
  -*/
int gnutls_x509_extract_certificate_version(const gnutls_datum * cert)
{
	gnutls_x509_crt xcert;
	int result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_version( xcert);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;

}

/*-
  * gnutls_x509_extract_certificate_serial - This function returns the certificate's serial number
  * @cert: is an X.509 DER encoded certificate
  * @result: The place where the serial number will be copied
  * @result_size: Holds the size of the result field.
  *
  * This function will return the X.509 certificate's serial number. 
  * This is obtained by the X509 Certificate serialNumber
  * field. Serial is not always a 32 or 64bit number. Some CAs use
  * large serial numbers, thus it may be wise to handle it as something
  * opaque. 
  * Returns a negative value in case of an error.
  *
  -*/
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size)
{
	gnutls_x509_crt xcert;
	size_t size = *result_size;
	int ret;

	ret = gnutls_x509_crt_init( &xcert);
	if (ret < 0) return ret;
	
	ret = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_x509_crt_deinit( xcert);
		return ret;
	}
	
	ret = gnutls_x509_crt_get_serial( xcert, result, &size);
	*result_size = size;
	
	gnutls_x509_crt_deinit( xcert);
	
	return ret;
}


/*-
  * gnutls_x509_extract_certificate_pk_algorithm - This function returns the certificate's PublicKey algorithm
  * @cert: is a DER encoded X.509 certificate
  * @bits: if bits is non null it will hold the size of the parameters' in bits
  *
  * This function will return the public key algorithm of an X.509 
  * certificate.
  *
  * If bits is non null, it should have enough size to hold the parameters
  * size in bits. For RSA the bits returned is the modulus. 
  * For DSA the bits returned are of the public
  * exponent.
  *
  * Returns a member of the gnutls_pk_algorithm enumeration on success,
  * or a negative value on error.
  *
  -*/
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits)
{
	gnutls_x509_crt xcert;
	int result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_pk_algorithm( xcert, bits);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}


/*-
  * gnutls_x509_extract_certificate_dn_string - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @buf: a pointer to a structure to hold the peer's name
  * @sizeof_buf: holds the size of 'buf'
  * @issuer: if non zero, then extract the name of the issuer, instead of the holder
  *
  * This function will copy the name of the certificate holder in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough,
  * and 0 on success.
  *
  -*/
int gnutls_x509_extract_certificate_dn_string(char *buf, unsigned int sizeof_buf, 
   const gnutls_datum * cert, int issuer)
{
	gnutls_x509_crt xcert;
	int result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	if (!issuer)
		result = gnutls_x509_crt_get_dn( xcert, buf, &sizeof_buf);
	else
		result = gnutls_x509_crt_get_issuer_dn( xcert, buf, &sizeof_buf);

	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/*-
  * gnutls_x509_verify_certificate - This function verifies given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: not used
  * @CRL_list_length: not used
  *
  * This function will try to verify the given certificate list and return its status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd. Note that expiration and activation dates are not checked 
  * by this function, you should check them using the appropriate functions.
  *
  * This function understands the basicConstraints (2.5.29.19) PKIX extension.
  * This means that only a certificate authority can sign a certificate.
  *
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. 
  *
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd.
  *
  * GNUTLS_CERT_INVALID\: the peer's certificate is not valid.
  *
  * GNUTLS_CERT_REVOKED\: the certificate has been revoked.
  *
  * A negative error code is returned in case of an error.
  * GNUTLS_E_NO_CERTIFICATE_FOUND is returned to indicate that
  * no certificate was sent by the peer.
  *  
  *
  -*/
int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, 
	const gnutls_datum * CA_list, int CA_list_length, 
	const gnutls_datum* CRL_list, int CRL_list_length)
{
	unsigned int verify;
	gnutls_x509_crt *peer_certificate_list = NULL;
	gnutls_x509_crt *ca_certificate_list = NULL;
	gnutls_x509_crl *crl_list = NULL;
	int peer_certificate_list_size=0, i, x, ret;
	int ca_certificate_list_size=0, crl_list_size=0;

	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = cert_list_length;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_x509_crt));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	ca_certificate_list_size = CA_list_length;
	ca_certificate_list =
	    gnutls_calloc(1,
			  ca_certificate_list_size *
			  sizeof(gnutls_x509_crt));
	if (ca_certificate_list == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	/* allocate memory for CRL
	 */
	crl_list_size = CRL_list_length;
	crl_list =
	    gnutls_calloc(1,
			  crl_list_size *
			  sizeof(gnutls_x509_crl));
	if (crl_list == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	/* convert certA_list to gnutls_cert* list
	 */
	for (i = 0; i < peer_certificate_list_size; i++) {
		ret = gnutls_x509_crt_init( &peer_certificate_list[i]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
				
		ret =
		     gnutls_x509_crt_import(peer_certificate_list[i],
					     &cert_list[i], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	/* convert CA_list to gnutls_x509_cert* list
	 */
	for (i = 0; i < ca_certificate_list_size; i++) {
		ret = gnutls_x509_crt_init(&ca_certificate_list[i]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret =
		     gnutls_x509_crt_import(ca_certificate_list[i],
					 &CA_list[i], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

#ifdef ENABLE_PKI
	/* convert CRL_list to gnutls_x509_crl* list
	 */
	for (i = 0; i < crl_list_size; i++) {
		ret = gnutls_x509_crl_init( &crl_list[i]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret =
		     gnutls_x509_crl_import(crl_list[i],
					 &CRL_list[i], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}
#endif

	/* Verify certificate 
	 */
	ret =
	    gnutls_x509_crt_list_verify(peer_certificate_list,
				      peer_certificate_list_size,
				      ca_certificate_list, ca_certificate_list_size, 
				      crl_list, crl_list_size, 0, &verify);

	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}
	
	ret = verify;

	cleanup:

	if (peer_certificate_list != NULL)
		for(x=0;x<peer_certificate_list_size;x++) {
			if (peer_certificate_list[x] != NULL)
				gnutls_x509_crt_deinit(peer_certificate_list[x]);
		}

	if (ca_certificate_list != NULL)
		for(x=0;x<ca_certificate_list_size;x++) {
			if (ca_certificate_list[x] !=  NULL)
				gnutls_x509_crt_deinit(ca_certificate_list[x]);
		}

#ifdef ENABLE_PKI
	if (crl_list != NULL)
		for(x=0;x<crl_list_size;x++) {
			if (crl_list[x] != NULL)
				gnutls_x509_crl_deinit(crl_list[x]);
		}
	
	gnutls_free( crl_list);
#endif

	gnutls_free( ca_certificate_list);
	gnutls_free( peer_certificate_list);

	return ret;
}

/*-
  * gnutls_x509_extract_key_pk_algorithm - This function returns the keys's PublicKey algorithm
  * @cert: is a DER encoded private key
  *
  * This function will return the public key algorithm of a DER encoded private
  * key.
  *
  * Returns a member of the gnutls_pk_algorithm enumeration on success,
  * or GNUTLS_E_UNKNOWN_PK_ALGORITHM on error.
  *
  -*/
int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key)
{
	gnutls_x509_privkey pkey;
	int ret, pk;
	
	ret = gnutls_x509_privkey_init( &pkey);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	ret = gnutls_x509_privkey_import( pkey, key, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	pk = gnutls_x509_privkey_get_pk_algorithm( pkey);
	
	gnutls_x509_privkey_deinit( pkey);
	return pk;
}

#ifdef ENABLE_PKI

/*-
  * gnutls_x509_pkcs7_extract_certificate - This function returns a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  * @indx: contains the index of the certificate to extract
  * @certificate: the contents of the certificate will be copied there
  * @certificate_size: should hold the size of the certificate
  *
  * This function will return a certificate of the PKCS7 or RFC2630 certificate set.
  * Returns 0 on success. If the provided buffer is not long enough,
  * then GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
  *
  * After the last certificate has been read GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
  * will be returned.
  *
  -*/
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size)
{
	gnutls_pkcs7 pkcs7;
	int result;
	size_t size = *certificate_size;

	result = gnutls_pkcs7_init( &pkcs7);
	if (result < 0) return result;
	
	result = gnutls_pkcs7_import( pkcs7, pkcs7_struct, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_pkcs7_deinit( pkcs7);
		return result;
	}
	
	result = gnutls_pkcs7_get_crt_raw( pkcs7, indx, certificate, &size);
	*certificate_size = size;

	gnutls_pkcs7_deinit( pkcs7);
	
	return result;
}


/*-
  * gnutls_x509_pkcs7_extract_certificate_count - This function returns the number of certificates in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  *
  * This function will return the number of certifcates in the PKCS7 or 
  * RFC2630 certificate set.
  *
  * Returns a negative value on failure.
  *
  -*/
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct)
{
	gnutls_pkcs7 pkcs7;
	int result;

	result = gnutls_pkcs7_init( &pkcs7);
	if (result < 0) return result;
	
	result = gnutls_pkcs7_import( pkcs7, pkcs7_struct, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_pkcs7_deinit( pkcs7);
		return result;
	}
	
	result = gnutls_pkcs7_get_crt_count( pkcs7);
	
	gnutls_pkcs7_deinit( pkcs7);
	
	return result;
}

#endif /* ENABLE_PKI */

/* rfc2818_hostname.c */

/* compare hostname against certificate, taking account of wildcards
 * return 1 on success or 0 on error 
 */
static int _gnutls_hostname_compare(const char *certname, const char *hostname)
{
   const char *cmpstr1, *cmpstr2;

   if (strlen(certname) == 0 || strlen(hostname) == 0)
      return 0;

   if (strlen(certname) > 2 && strncmp(certname, "*.", 2) == 0) {
      /* a wildcard certificate */

      cmpstr1 = certname + 1;

      /* find the first dot in hostname, compare from there on */
      cmpstr2 = strchr(hostname, '.');

      if (cmpstr2 == NULL) {
         /* error, the hostname we're connecting to is only a local part */
         return 0;
      }

      if (strcasecmp(cmpstr1, cmpstr2) == 0) {
         return 1;
      }

      return 0;
   }

   if (strcasecmp(certname, hostname) == 0) {
      return 1;
   }

   return 0;
}

#define MAX_CN 256

/*-
  * gnutls_x509_check_certificates_hostname - This function compares the given hostname with the hostname in the certificate
  * @cert: should contain a DER encoded certificate
  * @hostname: A null terminated string that contains a DNS name
  *
  * This function will check if the given certificate's subject matches
  * the given hostname. This is a basic implementation of the matching 
  * described in RFC2818 (HTTPS), which takes into account wildcards.
  *
  * Returns non zero on success, and zero on failure.
  *
  -*/
int gnutls_x509_check_certificates_hostname(const gnutls_datum * cert,
                                const char *hostname)
{
   char dnsname[MAX_CN];
   int dnsnamesize;
   int found_dnsname = 0;
   int ret = 0;
   gnutls_x509_dn dn;
   int i = 0;

   /* try matching against:
    *  1) a DNS name as an alternative name (subjectAltName) extension
    *     in the certificate
    *  2) the common name (CN) in the certificate
    *
    *  either of these may be of the form: *.domain.tld
    *
    *  only try (2) if there is no subjectAltName extension of
    *  type dNSName
    */

   /* Check through all included subjectAltName extensions, comparing
    * against all those of type dNSName.
    */
   for (i = 0; !(ret < 0); i++) {

      dnsnamesize = MAX_CN;
      ret =
          gnutls_x509_extract_certificate_subject_alt_name(cert, i,
                                                           dnsname,
                                                           &dnsnamesize);

      if (ret == GNUTLS_SAN_DNSNAME) {
         found_dnsname = 1;
         if (_gnutls_hostname_compare(dnsname, hostname)) {
            return 1;
         }
      }

   }

   if (!found_dnsname) {
      /* not got the necessary extension, use CN instead 
       */
      if (gnutls_x509_extract_certificate_dn(cert, &dn) != 0) {
         /* got an error, can't find a name 
          */
         return 0;
      }

      if (_gnutls_hostname_compare(dn.common_name, hostname)) {
         return 1;
      }
   }

   /* not found a matching name
    */
   return 0;
}

/* gnutls_state.c
 */
void gnutls_record_set_cbc_protection(gnutls_session session, int prot)
{
	/* obsoleted by TLS 1.1 */
	return;
}

#endif /* GNUTLS_BACKWARDS_COMPATIBLE */
