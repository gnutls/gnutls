#ifndef GNUTLS_SIG_H
# define GNUTLS_SIG_H
# include <auth_cert.h>

gnutls_certificate_status gnutls_x509_verify_signature(gnutls_cert * cert,
						       gnutls_cert *
						       issuer);
int _gnutls_tls_sign_hdata(gnutls_session session, gnutls_cert * cert,
			   gnutls_privkey * pkey,
			   gnutls_datum * signature);
int _gnutls_tls_sign_params(gnutls_session session, gnutls_cert * cert,
			    gnutls_privkey * pkey, gnutls_datum * params,
			    gnutls_datum * signature);
int _gnutls_verify_sig_hdata(gnutls_session session, gnutls_cert * cert,
			     gnutls_datum * signature);
int _gnutls_verify_sig_params(gnutls_session session, gnutls_cert * cert,
			      const gnutls_datum * params,
			      gnutls_datum * signature);
int _gnutls_sign(gnutls_pk_algorithm algo, mpi_t * params, int params_size,
		 const gnutls_datum * data, gnutls_datum * signature);

#endif
