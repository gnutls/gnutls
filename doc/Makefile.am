EXTRA_DIST = TODO gnutls.3 gnutls-api.txt gnutls-api.html
man_MANS = gnutls.3

gnutls.3: 
	@scripts/gdoc -man ../lib/*.c > gnutls.3
gnutls-api: gnutls-api.html gnutls-api.txt
gnutls-api.html: 
	@scripts/gdoc -html ../lib/*.c > gnutls-api.html
gnutls-api.txt:
	@scripts/gdoc -text ../lib/*.c > gnutls-api.txt
