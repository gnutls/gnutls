int _gnutls_pkcs1_rsa_verify_sig( gnutls_datum* signature, gnutls_datum *text, MPI m, MPI e);
CertificateStatus gnutls_verify_signature(gnutls_cert* cert, gnutls_cert* issuer);

