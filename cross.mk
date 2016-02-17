SMP=-j4

GNUTLS_VERSION:=3.4.9
GNUTLS_FILE:=gnutls-$(GNUTLS_VERSION).tar.xz
GNUTLS_DIR:=gnutls-$(GNUTLS_VERSION)

OPENCONNECT_VERSION:=6.00
OPENCONNECT_FILE:=openconnect-$(OPENCONNECT_VERSION).tar.gz
OPENCONNECT_DIR:=openconnect-$(OPENCONNECT_VERSION)

GMP_VERSION=6.1.0
GMP_VERSIONA=6.1.0
GMP_FILE:=gmp-$(GMP_VERSIONA).tar.lz
GMP_SERV_DIR:=gmp-$(GMP_VERSIONA)
GMP_DIR:=gmp-$(GMP_VERSION)

XML2_VERSION=2.9.1
XML2_FILE:=libxml2-$(XML2_VERSION).tar.gz
XML2_DIR:=libxml2-$(XML2_VERSION)

LIBZ_VERSION=1.2.8
LIBZ_FILE:=zlib-$(LIBZ_VERSION).tar.gz
LIBZ_DIR:=zlib-$(LIBZ_VERSION)

P11_KIT_VERSION=0.23.2
P11_KIT_FILE:=p11-kit-$(P11_KIT_VERSION).tar.gz
P11_KIT_DIR:=p11-kit-$(P11_KIT_VERSION)

NETTLE_VERSION=3.2
NETTLE_FILE:=nettle-$(NETTLE_VERSION).tar.gz
NETTLE_DIR:=nettle-$(NETTLE_VERSION)

ifeq ($(BITS),64)
HOST:=x86_64-w64-mingw32
CROSS_DIR:=$(PWD)/win64
ZIPNAME:=$(GNUTLS_DIR)-w64.zip
else
HOST:=i686-w64-mingw32
CROSS_DIR:=$(PWD)/win32
ZIPNAME:=$(GNUTLS_DIR)-w32.zip
GMP_FLAGS=--enable-fat
endif

PKG_CONFIG_DIR:=$(CROSS_DIR)/lib/pkgconfig/
BIN_DIR:=$(CROSS_DIR)/bin
LIB_DIR:=$(CROSS_DIR)/lib
HEADERS_DIR:=$(CROSS_DIR)/include
DEVCPP_DIR:=$(PWD)/devcpp
LDFLAGS=
#doesn't seem to work
#LDFLAGS=-static-libgcc


all: update-gpg-keys gnutls-w32

upload: gnutls-w32 devpak
	../build-aux/gnupload --to ftp.gnu.org:gnutls/w32 $(ZIPNAME)
	../build-aux/gnupload --to ftp.gnu.org:gnutls/w32 gnutls-$(GNUTLS_VERSION)-1gn.DevPak

update-gpg-keys:
	gpg --recv-keys 96865171 B565716F D92765AF A8F4C2FD DB899F46

$(ZIPNAME): $(LIB_DIR) $(BIN_DIR) $(GNUTLS_DIR)/.installed
	rm -rf $(CROSS_DIR)/etc $(CROSS_DIR)/share $(CROSS_DIR)/lib/include
	cd $(CROSS_DIR) && zip -r $(PWD)/$@ *
	gpg --sign --detach $(ZIPNAME)

gnutls-$(GNUTLS_VERSION)-1gn.DevPak: $(ZIPNAME) devcpp.tar
	rm -rf $(DEVCPP_DIR)
	mkdir -p $(DEVCPP_DIR)
	cd $(DEVCPP_DIR) && unzip ../$(ZIPNAME)
	cd $(DEVCPP_DIR) && tar xf ../devcpp.tar && sed -i 's/@VERSION@/$(GNUTLS_VERSION)/g' gnutls.DevPackage
	cd $(DEVCPP_DIR) && tar -cjf ../$@ .

devpak: gnutls-$(GNUTLS_VERSION)-1gn.DevPak

gnutls-w32: $(ZIPNAME)

openconnect-w32: $(OPENCONNECT_DIR)/.installed

nettle: $(NETTLE_DIR)/.installed

gmp: $(GMP_DIR)/.installed

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

CONFIG_ENV := PKG_CONFIG_PATH="$(PKG_CONFIG_DIR)"
CONFIG_ENV += PKG_CONFIG_LIBDIR="$(PKG_CONFIG_DIR)"
CONFIG_FLAGS1 := --prefix=$(CROSS_DIR) --enable-shared \
	--libdir=$(LIB_DIR) --includedir=$(HEADERS_DIR)
CONFIG_FLAGS := --host=$(HOST) $(CONFIG_FLAGS1) --disable-static --bindir=$(BIN_DIR) --sbindir=$(BIN_DIR) \
	 --enable-threads=win32 

$(P11_KIT_DIR)/.configured:
	test -f $(P11_KIT_FILE) || wget http://p11-glue.freedesktop.org/releases/$(P11_KIT_FILE)
	test -f $(P11_KIT_FILE).sig || wget http://p11-glue.freedesktop.org/releases/$(P11_KIT_FILE).sig
	gpg --verify $(P11_KIT_FILE).sig
	test -d $(P11_KIT_DIR) || tar -xf $(P11_KIT_FILE)
	cd $(P11_KIT_DIR) && LDFLAGS="$(LDFLAGS)" $(CONFIG_ENV) ./configure $(CONFIG_FLAGS) --without-libffi --without-libtasn1 && cd ..
	touch $@

$(P11_KIT_DIR)/.installed: $(P11_KIT_DIR)/.configured
	make -C $(P11_KIT_DIR) $(SMP)
	make -C $(P11_KIT_DIR) install -i
	-rm -rf $(HEADERS_DIR)/p11-kit
	-mv $(HEADERS_DIR)/p11-kit-1/p11-kit $(HEADERS_DIR)
	-rm -rf $(HEADERS_DIR)/p11-kit-1
	rm -f $(BIN_DIR)/p11-kit.exe
	touch $@

$(GMP_DIR)/.configured: 
	test -f $(GMP_FILE) || wget ftp://ftp.gmplib.org/pub/$(GMP_DIR)/$(GMP_FILE)
	test -f $(GMP_FILE).sig || wget ftp://ftp.gmplib.org/pub/$(GMP_DIR)/$(GMP_FILE).sig
	gpg --verify $(GMP_FILE).sig
	test -d $(GMP_DIR) || tar -xf $(GMP_FILE)
	cd $(GMP_DIR) && LDFLAGS="$(LDFLAGS)" CC=$(HOST)-gcc $(CONFIG_ENV) ./configure $(GMP_FLAGS) $(CONFIG_FLAGS) --exec-prefix=$(LIB_DIR)  --oldincludedir=$(HEADERS_DIR) && cd ..
	cp $(GMP_DIR)/COPYING.LESSERv3 $(CROSS_DIR)/COPYING.GMP
	touch $@

$(GMP_DIR)/.installed: $(GMP_DIR)/.configured
	make -C $(GMP_DIR) $(SMP)
	make -C $(GMP_DIR) install -i
	-mkdir -p $(HEADERS_DIR)
	mv $(LIB_DIR)/include/* $(HEADERS_DIR)/
	rmdir $(LIB_DIR)/include/
	touch $@

$(NETTLE_DIR)/.configured: $(GMP_DIR)/.installed
	test -f $(NETTLE_FILE) || wget http://www.lysator.liu.se/~nisse/archive/$(NETTLE_FILE)
	test -f $(NETTLE_FILE).sig || wget http://www.lysator.liu.se/~nisse/archive/$(NETTLE_FILE).sig
	gpg --verify $(NETTLE_FILE).sig
	test -d $(NETTLE_DIR) || tar -xf $(NETTLE_FILE)
	cd $(NETTLE_DIR) && CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" LDFLAGS="$(LDFLAGS)" $(CONFIG_ENV) ./configure $(CONFIG_FLAGS) --with-lib-path=$(LIB_DIR) && cd ..
	touch $@

#nettle messes up installation
$(NETTLE_DIR)/.installed: $(NETTLE_DIR)/.configured
	make -C $(NETTLE_DIR) $(SMP) -i
	make -C $(NETTLE_DIR) install -i
	rm -f $(LIB_DIR)/libnettle.a $(LIB_DIR)/libhogweed.a $(BIN_DIR)/nettle-hash.exe $(BIN_DIR)/nettle-lfib-stream.exe $(BIN_DIR)/pkcs1-conv.exe $(BIN_DIR)/sexp-conv.exe
	cp $(NETTLE_DIR)/libnettle.dll.a $(NETTLE_DIR)/libhogweed.dll.a $(LIB_DIR)/
	cp $(NETTLE_DIR)/libnettle*.dll $(NETTLE_DIR)/libhogweed*.dll $(BIN_DIR)/
	touch $@

GCC_DLLS_PATH=/usr/lib/gcc/$(HOST)/4.9-win32/
GCC_DLLS=libgcc_s_sjlj-1.dll libgcc_s_seh-1.dll libwinpthread-1.dll

$(GNUTLS_DIR)/.installed: $(GNUTLS_DIR)/.configured
	make -C $(GNUTLS_DIR) $(SMP)
	-for j in $(GNUTLS_DIR)/tests $(GNUTLS_DIR)/tests/safe-renegotiation $(GNUTLS_DIR)/tests/slow;do \
	for i in $(GCC_DLLS);do cp $(GCC_DLLS_PATH)/$$i $$j && echo $$i;done;done
	sed -i 's/^"$$@" >$$log_file/echo $$@|grep exe >\/dev\/null; if [ $$? == 0 ];then wine "$$@" >$$log_file;else \/bin\/true >$$log_file;fi/g' $(GNUTLS_DIR)/build-aux/test-driver
	-make -C $(GNUTLS_DIR)/tests check $(SMP)
	make -C $(GNUTLS_DIR) install -i
	cp $(GNUTLS_DIR)/COPYING $(GNUTLS_DIR)/COPYING.LESSER $(CROSS_DIR)
	-for i in $(GCC_DLLS);do cp $(GCC_DLLS_PATH)/$$i $(BIN_DIR)/ && echo $$i;done
	touch $@

$(GNUTLS_DIR)/.configured: $(NETTLE_DIR)/.installed $(P11_KIT_DIR)/.installed
	test -f $(GNUTLS_FILE) || wget ftp://ftp.gnutls.org/gcrypt/gnutls/v3.4/$(GNUTLS_FILE)
	test -f $(GNUTLS_FILE).sig || wget ftp://ftp.gnutls.org/gcrypt/gnutls/v3.4/$(GNUTLS_FILE).sig
	gpg --verify $(GNUTLS_FILE).sig
	test -d $(GNUTLS_DIR) || tar -xf $(GNUTLS_FILE)
	cd $(GNUTLS_DIR) && \
		$(CONFIG_ENV) LDFLAGS="$(LDFLAGS) -L$(LIB_DIR)" CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" \
		./configure $(CONFIG_FLAGS) --enable-local-libopts --disable-cxx \
		--disable-doc --without-zlib --disable-nls --enable-gcc-warnings --disable-libdane --disable-openssl-compatibility --with-included-libtasn1 && cd ..
	touch $@

$(OPENCONNECT_DIR)/.installed: $(OPENCONNECT_DIR)/.configured
	make -C $(OPENCONNECT_DIR) $(SMP)
	make -C $(OPENCONNECT_DIR) install -i
	touch $@

$(OPENCONNECT_DIR)/.configured: $(GNUTLS_DIR)/.installed $(XML2_DIR)/.installed
	test -f $(OPENCONNECT_FILE) || wget ftp://ftp.infradead.org/pub/openconnect/$(OPENCONNECT_FILE)
	test -f $(OPENCONNECT_FILE).sig || wget ftp://ftp.infradead.org/pub/openconnect/$(OPENCONNECT_FILE).asc
	gpg --verify $(OPENCONNECT_FILE).asc
	test -d $(OPENCONNECT_DIR) || tar -xf $(OPENCONNECT_FILE)
	cd $(OPENCONNECT_DIR) && \
		$(CONFIG_ENV) LDFLAGS="$(LDFLAGS) -L$(LIB_DIR)" CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" \
		./configure $(CONFIG_FLAGS) && cd ..
	sed -i 's/-Werror-implicit-function-declaration//g' $(OPENCONNECT_DIR)/Makefile
	touch $@

$(XML2_DIR)/.configured: $(GMP_DIR)/.installed
	test -f $(XML2_FILE) || wget ftp://xmlsoft.org/libxml2/$(XML2_FILE)
	#test -f $(XML2_FILE).sig || wget ftp://xmlsoft.org/libxml2//$(XML2_FILE).sig
	#gpg --verify $(XML2_FILE).sig
	test -d $(XML2_DIR) || tar -xf $(XML2_FILE)
	cd $(XML2_DIR) && CFLAGS="-I$(HEADERS_DIR)" CXXFLAGS="-I$(HEADERS_DIR)" LDFLAGS="$(LDFLAGS)" $(CONFIG_ENV) ./configure $(CONFIG_FLAGS) --without-python --without-legacy --without-python --without-http --without-ftp --with-lib-path=$(LIB_DIR) && cd ..
	touch $@

$(XML2_DIR)/.installed: $(XML2_DIR)/.configured
	make -C $(XML2_DIR) $(SMP)
	make -C $(XML2_DIR) install
	touch $@

clean:
	rm -rf $(CROSS_DIR) $(XML2_DIR)/.installed $(GNUTLS_DIR)/.installed $(OPENCONNECT_DIR)/.installed $(NETTLE_DIR)/.installed $(GMP_DIR)/.installed $(P11_KIT_DIR)/.installed

dirclean:
	rm -rf $(CROSS_DIR) $(GNUTLS_DIR) $(NETTLE_DIR) $(GMP_DIR) $(P11_KIT_DIR)

