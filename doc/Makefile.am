EXTRA_DIST = TODO gnutls.3 gnutls-api.txt gnutls-api.html
man_MANS = gnutls.3

gnutls.3: 
	@gdoc -man ../lib/*.c > gnutls.3
gnutls-api: gnutls-api.html gnutls-api.txt
gnutls-api.html: 
	@gdoc -html ../lib/*.c > gnutls-api.html
gnutls-api.txt:
	@gdoc -text ../lib/*.c > gnutls-api.txt
