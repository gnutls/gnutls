#ifndef GNUTLS_SIG_H
# define GNUTLS_SIG_H
# include <auth_cert.h>

gnutls_certificate_status_t gnutls_x509_verify_signature(gnutls_cert *
							 cert,
							 gnutls_cert *
							 issuer);
int _gnutls_tls_sign_hdata(gnutls_session_t session, gnutls_cert * cert,
			   gnutls_privkey * pkey,
			   gnutls_datum_t * signature);
int _gnutls_tls_sign_params(gnutls_session_t session, gnutls_cert * cert,
			    gnutls_privkey * pkey, gnutls_datum_t * params,
			    gnutls_datum_t * signature);
int _gnutls_verify_sig_hdata(gnutls_session_t session, gnutls_cert * cert,
			     gnutls_datum_t * signature);
int _gnutls_verify_sig_params(gnutls_session_t session, gnutls_cert * cert,
			      const gnutls_datum_t * params,
			      gnutls_datum_t * signature);
int _gnutls_sign(gnutls_pk_algorithm_t algo, mpi_t * params,
		 int params_size, const gnutls_datum_t * data,
		 gnutls_datum_t * signature);

#endif
