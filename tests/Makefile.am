## Process this file with automake to produce Makefile.in
# Copyright (C) 2004 Free Software Foundation
#
# This file is part of GNUTLS.
#
# GNUTLS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNUTLS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

AM_CPPFLAGS = -I../includes -I$(top_srcdir)/includes
AM_LDFLAGS = -no-install
LDADD = ../lib/libgnutls.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

ctests = simple anonself
TESTS = pkcs12_neon $(ctests)	
check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = pkcs12_neon

# LIBS=`../lib/libgnutls-config --libs`  -lgcrypt
# LIBS2=`../lib/libgnutls-config --libs` `../libextra/libgnutls-extra-config --libs` -lgcrypt -lopencdk
# CC=gcc
# CFLAGS=-O2 -I../libextra/ -I../ -I../lib/ `../lib/libgnutls-config --cflags` -I../lib/minitasn1/
#
# all: x509test opgptest
#
# x509test: x509_test.c
# 	$(CC) $(CFLAGS) x509_test.c $(LIBS) -o x509test
#
# opgptest: openpgp_test.c
# 	$(CC) $(CFLAGS) openpgp_test.c $(LIBS2) -o opgptest
#
# check: x509test
# 	./x509test
# 	./opgptest
#
# clean:
# 	rm *~
# 	rm *.o
# 	rm x509test
# 	rm opgptest
