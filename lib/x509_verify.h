int _gnutls_x509_verify_certificate(gnutls_cert * certificate_list,
    int clist_size, gnutls_cert * trusted_cas, int tcas_size, void *CRLs,
			      int crls_size);
time_t _gnutls_utcTime2gtime(char *ttime);
time_t _gnutls_generalTime2gtime(char *ttime);
