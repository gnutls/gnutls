## Process this file with automake to produce Makefile.in
EXTRA_DIST = test1.pem test2.pem test3.pem test10.pem test25.pem \
	test22.pem test23.pem test24.pem test26.pem test13.pem ca.pem
INCLUDES= -I../lib/ -I../libtasn1/lib/ -I../includes

noinst_PROGRAMS = x509test
x509test_SOURCES = x509_test.c
x509test_LDADD = ../lib/libgnutls.la  -lgcrypt
TESTS = x509test
