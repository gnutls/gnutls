#ifndef DN_H
# define DN_H

/* Some OIDs usually found in Distinguished names
 */
#define OID_X520_COUNTRY_NAME		"2 5 4 6"
#define OID_X520_ORGANIZATION_NAME 	"2 5 4 10"
#define OID_X520_ORGANIZATIONAL_UNIT_NAME "2 5 4 11"
#define OID_X520_COMMON_NAME 		"2 5 4 3"
#define OID_X520_LOCALITY_NAME 		"2 5 4 7"
#define OID_X520_STATE_OR_PROVINCE_NAME 	"2 5 4 8"
#define OID_LDAP_DC			"0 9 2342 19200300 100 1 25"
#define OID_LDAP_UID			"0 9 2342 19200300 100 1 1"
#define OID_PKCS9_EMAIL 			"1 2 840 113549 1 9 1"

int _gnutls_x509_parse_dn(ASN1_TYPE asn1_struct, 
	const char* asn1_rdn_name, char *buf,
	int* sizeof_buf);

int _gnutls_x509_parse_dn_oid(ASN1_TYPE asn1_struct, 
	const char* asn1_rdn_name, const char* oid, int indx, char *buf,
	int* sizeof_buf);

#endif
