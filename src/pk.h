#define PKIX "pkix.asn"
#define PKCS "pkcs1.asn"
void PARSE()
{
	/* this is to be moved to gnutls */
	int result = parser_asn1(PKIX);

	signal( SIGPIPE, SIG_IGN);

	if (result == ASN_SYNTAX_ERROR) {
		printf("%s: PARSE ERROR\n", PKIX);
		return;
	} else if (result == ASN_IDENTIFIER_NOT_FOUND) {
		printf("%s: IDENTIFIER NOT FOUND\n", PKIX);
		return;
	}

	result = parser_asn1(PKCS);

	if (result == ASN_SYNTAX_ERROR) {
		printf("%s: PARSE ERROR\n", PKCS);
		return;
	} else if (result == ASN_IDENTIFIER_NOT_FOUND) {
		printf("%s: IDENTIFIER NOT FOUND\n", PKCS);
		return;
	}

}
