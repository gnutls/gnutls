int _gnutls_x509_parse_dn(ASN1_TYPE asn1_struct, 
	const char* asn1_rdn_name, char *buf,
	int* sizeof_buf);

int _gnutls_x509_parse_dn_oid(ASN1_TYPE asn1_struct, 
	const char* asn1_rdn_name, const char* oid, char *buf,
	int* sizeof_buf);
