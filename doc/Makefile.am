EXTRA_DIST = TODO gnutls-api.html ASN1.readme.txt

gnutls-api: gnutls-api.html 
gnutls-api.html: API-template.html
	@cat API-template.html > gnutls-api.html
	@scripts/gdoc -html ../lib/*.c >> gnutls-api.html
	@echo "</body></html>" >> gnutls-api.html
