EXTRA_DIST = run-tests testutils.c testutils.h

AM_CPPFLAGS = -I$(srcdir)/..

noinst_PROGRAMS = aes-test arcfour-test arctwo-test \
	   des-test des3-test des-compat-test \
	   md5-test \
	   sha1-test \
	   knuth-lfib-test \
	   cbc-test hmac-test

LDADD = testutils.o ../libnettle.la

TESTS = $(noinst_PROGRAMS)
