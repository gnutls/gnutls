LIBS=`../lib/libgnutls-config --libs`  -lgcrypt
CC=gcc
CFLAGS=-O2 -I../ -I../lib/ `../lib/libgnutls-config --cflags`

all: x509test

x509test: x509_test.o

x509_test.o: x509_test.c
	$(CC) $(CFLAGS) x509_test.c $(LIBS) -o x509test

check: x509test
	./x509test

clean:
	rm *~
	rm *.o
	rm x509test
