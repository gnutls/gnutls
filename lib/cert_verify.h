int gnutls_verify_certificate(gnutls_cert * certificate_list,
    int clist_size, gnutls_cert * trusted_cas, int tcas_size, void *CRLs,
			      int crls_size);
