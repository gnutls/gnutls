## Process this file with automake to produce Makefile.in

INCLUDES= -I../lib/ -I../libtasn1/lib/

noinst_PROGRAMS = x509test
x509test_SOURCES = x509_test.c
x509test_LDADD = ../lib/libgnutls.la  -lgcrypt
TESTS = x509test
