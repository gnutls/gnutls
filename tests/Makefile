LIBS=`../lib/libgnutls-config --libs`  -lgcrypt
LIBS2=`../lib/libgnutls-config --libs` `../libextra/libgnutls-extra-config --libs` -lgcrypt -lopencdk
CC=gcc
CFLAGS=-O2 -I../libextra/ -I../ -I../lib/ `../lib/libgnutls-config --cflags` -I../lib/minitasn1/

all: x509test opgptest

x509test: x509_test.c
	$(CC) $(CFLAGS) x509_test.c $(LIBS) -o x509test

opgptest: openpgp_test.c
	$(CC) $(CFLAGS) openpgp_test.c $(LIBS2) -o opgptest


check: x509test
	./x509test
	./opgptest

clean:
	rm *~
	rm *.o
	rm x509test
	rm opgptest
