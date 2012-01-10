
GNUTLS_FILE:=gnutls-3.0.11.tar.xz
GNUTLS_DIR:=gnutls-3.0.11

GMP_FILE:=gmp-5.0.2.tar.bz2
GMP_DIR:=gmp-5.0.2

P11_KIT_FILE:=p11-kit-0.10.tar.gz
P11_KIT_DIR:=p11-kit-0.10

NETTLE_FILE:=nettle-2.4.tar.gz
NETTLE_DIR:=nettle-2.4

CROSS_DIR:=$(PWD)/win32
BIN_DIR:=$(CROSS_DIR)/bin
LIB_DIR:=$(CROSS_DIR)/lib
HEADERS_DIR:=$(LIB_DIR)/include

all: update-gpg-keys gnutls-w32

update-gpg-keys:
	gpg --recv-keys 96865171 B565716F D92765AF A8F4C2FD DB899F46

$(GNUTLS_DIR)-w32.zip: $(LIB_DIR) $(BIN_DIR) $(GNUTLS_DIR)/.installed
	-mv $(CROSS_DIR)/lib/include $(CROSS_DIR)/include
	cd $(CROSS_DIR) && zip -r $(PWD)/$@ *
	gpg --sign --detach $(GNUTLS_DIR)-w32.zip

gnutls-w32: $(GNUTLS_DIR)-w32.zip

nettle: $(NETTLE_DIR)/.installed

gmp: $(GMP_DIR)/.installed

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)
	mkdir -p $(HEADERS_DIR)

CONFIG_FLAGS := --host=i686-w64-mingw32 --enable-shared --disable-static --bindir=$(BIN_DIR) --libdir=$(LIB_DIR) --includedir=$(HEADERS_DIR)

$(P11_KIT_DIR)/.configured:
	test -f $(P11_KIT_FILE) || wget http://p11-glue.freedesktop.org/releases/$(P11_KIT_FILE)
	test -f $(P11_KIT_FILE).sig || wget http://p11-glue.freedesktop.org/releases/$(P11_KIT_FILE).sig
	gpg --verify $(P11_KIT_FILE).sig
	test -d $(P11_KIT_DIR) || tar -xf $(P11_KIT_FILE)
	cd $(P11_KIT_DIR) && ./configure $(CONFIG_FLAGS) && cd ..
	touch $@

$(P11_KIT_DIR)/.installed: $(P11_KIT_DIR)/.configured
	make -C $(P11_KIT_DIR) -j2
	make -C $(P11_KIT_DIR) install -i
	-rm -rf $(HEADERS_DIR)/p11-kit
	-mv $(HEADERS_DIR)/p11-kit-1/p11-kit $(HEADERS_DIR)
	-rmdir $(HEADERS_DIR)/p11-kit-1
	rm -f $(BIN_DIR)/p11-kit.exe
	touch $@

$(GMP_DIR)/.configured: 
	test -f $(GMP_FILE) || wget ftp://ftp.gmplib.org/pub/$(GMP_DIR)/$(GMP_FILE)
	test -f $(GMP_FILE).sig || wget ftp://ftp.gmplib.org/pub/$(GMP_DIR)/$(GMP_FILE).sig
	gpg --verify $(GMP_FILE).sig
	test -d $(GMP_DIR) || tar -xf $(GMP_FILE)
	cd $(GMP_DIR) && ./configure $(CONFIG_FLAGS) --enable-fat --exec-prefix=$(LIB_DIR) --oldincludedir=$(HEADERS_DIR) && cd ..
	touch $@

$(GMP_DIR)/.installed: $(GMP_DIR)/.configured
	make -C $(GMP_DIR) -j2
	make -C $(GMP_DIR) install -i
	touch $@

$(NETTLE_DIR)/.configured: $(GMP_DIR)/.installed
	test -f $(NETTLE_FILE) || wget http://www.lysator.liu.se/~nisse/archive/$(NETTLE_FILE)
	test -f $(NETTLE_FILE).sig || wget http://www.lysator.liu.se/~nisse/archive/$(NETTLE_FILE).sig
	gpg --verify $(NETTLE_FILE).sig
	test -d $(NETTLE_DIR) || tar -xf $(NETTLE_FILE)
	cd $(NETTLE_DIR) && CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" ./configure $(CONFIG_FLAGS) --with-lib-path=$(LIB_DIR) && cd ..
	touch $@

#nettle messes up installation
$(NETTLE_DIR)/.installed: $(NETTLE_DIR)/.configured
	make -C $(NETTLE_DIR) -j2
	make -C $(NETTLE_DIR) install -i
	rm -f $(LIB_DIR)/libnettle.a $(LIB_DIR)/libhogweed.a $(BIN_DIR)/nettle-hash.exe $(BIN_DIR)/nettle-lfib-stream.exe $(BIN_DIR)/pkcs1-conv.exe $(BIN_DIR)/sexp-conv.exe
	cp $(NETTLE_DIR)/libnettle.dll.a $(NETTLE_DIR)/libhogweed.dll.a $(LIB_DIR)/
	cp $(NETTLE_DIR)/libnettle*.dll $(NETTLE_DIR)/libhogweed*.dll $(BIN_DIR)/
	touch $@

$(GNUTLS_DIR)/.installed: $(GNUTLS_DIR)/.configured
	make -C $(GNUTLS_DIR) -j2
	make -C $(GNUTLS_DIR) install -i
	cp $(GNUTLS_DIR)/COPYING $(GNUTLS_DIR)/COPYING.LESSER $(CROSS_DIR)
	touch $@

$(GNUTLS_DIR)/.configured: $(NETTLE_DIR)/.installed $(P11_KIT_DIR)/.installed
	test -f $(GNUTLS_FILE) || wget ftp://ftp.gnu.org/gnu/gnutls/$(GNUTLS_FILE)
	test -f $(GNUTLS_FILE).sig || wget ftp://ftp.gnu.org/gnu/gnutls/$(GNUTLS_FILE).sig
	gpg --verify $(GNUTLS_FILE).sig
	test -d $(GNUTLS_DIR) || tar -xf $(GNUTLS_FILE)
	cd $(GNUTLS_DIR) && \
		P11_KIT_CFLAGS="-I$(HEADERS_DIR)" \
		P11_KIT_LIBS="$(LIB_DIR)/libp11-kit.la" \
		LDFLAGS="-L$(LIB_DIR)" CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" \
		./configure $(CONFIG_FLAGS) --with-libnettle-prefix=$(LIB_DIR) \
		--disable-openssl-compatibility && cd ..
	touch $@

clean:
	rm -rf $(CROSS_DIR) $(GNUTLS_DIR)/.installed $(NETTLE_DIR)/.installed $(GMP_DIR)/.installed $(P11_KIT_DIR)/.installed

dirclean:
	rm -rf $(CROSS_DIR) $(GNUTLS_DIR) $(NETTLE_DIR) $(GMP_DIR) $(P11_KIT_DIR)

