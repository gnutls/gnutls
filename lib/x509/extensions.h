int _gnutls_x509_crt_get_extension( gnutls_x509_crt cert, const char* extension_id, 
	int indx, gnutls_datum* ret, unsigned int* critical);
int _gnutls_x509_crt_get_extension_oid( gnutls_x509_crt cert,
	int indx, void* ret, size_t * ret_size);
int _gnutls_x509_ext_extract_keyUsage(uint16 *keyUsage, opaque * extnValue,
			     int extnValueLen);
int _gnutls_x509_ext_extract_basicConstraints(int *CA, opaque * extnValue,
				     int extnValueLen);

int _gnutls_x509_crt_set_extension( gnutls_x509_crt cert, const char* extension_id, 
	const gnutls_datum* ext_data, unsigned int critical);
int _gnutls_x509_ext_gen_basicConstraints(int CA, gnutls_datum* der_ext);
int _gnutls_x509_ext_gen_keyUsage(uint16 usage, gnutls_datum* der_ext);
int _gnutls_x509_ext_gen_subject_alt_name(gnutls_x509_subject_alt_name type, 
	const char* data_string, gnutls_datum* der_ext);
int _gnutls_x509_ext_gen_crl_dist_points(gnutls_x509_subject_alt_name type, 
	const char* data_string, gnutls_datum* der_ext);
