EXTRA_DIST = run-tests

AM_CPPFLAGS = -I$(srcdir)/..

noinst_PROGRAMS = aes-test arcfour-test arctwo-test \
	   des-test des3-test des-compat-test \
	   md5-test md5-compat-test \
	   sha1-test \
	   knuth-lfib-test \
	   cbc-test hmac-test

SOURCES = testutils.c testutils.h
LDADD = testutils.o ../libnettle.la

TESTS = $(noinst_PROGRAMS)
