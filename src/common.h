#define PORT 5556
#define SERVER "127.0.0.1"

#define PRINTX(x,y) if (y[0]!=0) printf(" -   %s %s\n", x, y)
#define PRINT_DN(X) PRINTX( "CN:", X.common_name); \
	PRINTX( "OU:", X.organizational_unit_name); \
	PRINTX( "O:", X.organization); \
	PRINTX( "L:", X.locality_name); \
	PRINTX( "S:", X.state_or_province_name); \
	PRINTX( "C:", X.country); \
	PRINTX( "E:", X.email); \
	dnsname_size = sizeof(dnsname); \
	gnutls_x509pki_client_get_subject_dns_name(state, dnsname, &dnsname_size); \
	PRINTX( "SAN:", dnsname)
