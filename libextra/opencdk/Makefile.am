INCLUDES = -I../../ -DVERSION=\"gnutls/opencdk\"
EXTRA_DIST =  md.h packet.h opencdk.h context.h README \
        main.h cipher.h stream.h types.h filters.h
noinst_LTLIBRARIES = libopencdk.la
libopencdk_la_SOURCES = new-packet.c \
        read-packet.c write-packet.c main.c \
        verify.c armor.c sig-check.c sign.c keydb.c \
        keylist.c seskey.c pubkey.c misc.c encrypt.c \
        trustdb.c kbnode.c compress.c plaintext.c cipher.c \
	sym-cipher.c stream.c keyserver.c keygen.c md.c

