EXTRA_DIST = TODO gnutls-api.txt gnutls-api.html

gnutls-api: gnutls-api.html gnutls-api.txt
gnutls-api.html: 
	@scripts/gdoc -html ../lib/*.c > gnutls-api.html
gnutls-api.txt:
	@scripts/gdoc -text ../lib/*.c > gnutls-api.txt
