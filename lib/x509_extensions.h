int _gnutls_get_ext_type( ASN1_TYPE rasn, char *root, gnutls_cert *cert, int no_critical_ext);
int _gnutls_get_extension( const gnutls_datum * cert, const char* extension_id, gnutls_datum* ret);
