int gnutls_x509_certificate_list_verify( gnutls_x509_certificate* cert_list, int cert_list_length, 
	gnutls_x509_certificate * CA_list, int CA_list_length, 
	gnutls_x509_crl* CRL_list, int CRL_list_length, unsigned int* verify);
