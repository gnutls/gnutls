time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);

int gnutls_x509_extract_certificate_subject_alt_name( const gnutls_datum*, int seq, char*, int*);
int gnutls_x509_extract_certificate_dn( const gnutls_datum*, gnutls_x509_dn*);

int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct);
