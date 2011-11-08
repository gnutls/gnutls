## Process this file with automake to produce Makefile.in

# We require automake 1.6 at least.
AUTOMAKE_OPTIONS = 1.6

# This is a blank Makefile.am for using gtk-doc.
# Copy this to your project's API docs directory and modify the variables to
# suit your project. See the GTK+ Makefiles in gtk+/docs/reference for examples
# of using the various options.

# The name of the module, e.g. 'glib'.
DOC_MODULE=$(PACKAGE)

# Uncomment for versioned docs and specify the version of the module, e.g. '2'.
#DOC_MODULE_VERSION=2


# The top-level SGML file. You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# Directories containing the source code.
# gtk-doc will search all .c and .h files beneath these paths
# for inline comments documenting functions and macros.
# e.g. DOC_SOURCE_DIR=$(top_srcdir)/gtk $(top_srcdir)/gdk
DOC_SOURCE_DIR=../../lib

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED"
SCAN_OPTIONS=--ignore-decorators=ASN1_API \
	--deprecated-guards=ASN1_DISABLE_DEPRECATED

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--xml-mode --output-format=xml
MKDB_OPTIONS=--xml-mode --output-format=xml

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# Extra options to supply to gtkdoc-mkhtml
MKHTML_OPTIONS=

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/gtk/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/gtk/*.c
HFILE_GLOB=$(top_srcdir)/lib/includes/gnutls/*.h \
	$(top_builddir)/lib/includes/gnutls/*.h
CFILE_GLOB=$(top_srcdir)/lib/*.c \
	$(top_srcdir)/lib/x509/*.c \
	$(top_srcdir)/lib/openpgp/*.c \
	$(top_srcdir)/lib/minitasn1/*.c

# Extra header to include when scanning, which are not under DOC_SOURCE_DIR
# e.g. EXTRA_HFILES=$(top_srcdir}/contrib/extra.h
EXTRA_HFILES=

# Header files or dirs to ignore when scanning. Use base file/dir names
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h private_code
IGNORE_HFILES=

# find lib -name \*.h -exec basename {} \; | grep -v -e ^abstract.h$ -e ^crypto.h$ -e ^dtls.h$ -e ^gnutls.h$ -e ^openpgp.h$ -e ^pkcs11.h$ -e ^pkcs12.h$ -e ^x509.h$ | sort | uniq | sed -e 's/^/\t/' -e 's/$/ \\/'
IGNORE_HFILES += \
	abstract_int.h \
	accelerated.h \
	aes-padlock.h \
	aes-x86.h \
	algorithms.h \
	anon.h \
	cert.h \
	cert_type.h \
	common.h \
	compat.h \
	context.h \
	crypto-backend.h \
	cryptodev.h \
	debug.h \
	dh_common.h \
	ecc.h \
	ecdh_common.h \
	egd.h \
	element.h \
	filters.h \
	gnettle.h \
	gnutls_auth.h \
	gnutls_buffers.h \
	gnutls_cipher.h \
	gnutls_cipher_int.h \
	gnutls_compress.h \
	gnutls_constate.h \
	gnutls_datum.h \
	gnutls_db.h \
	gnutls_dh.h \
	gnutls_dtls.h \
	gnutls_ecc.h \
	gnutls_errors.h \
	gnutls_extensions.h \
	gnutls_global.h \
	gnutls_handshake.h \
	gnutls_hash_int.h \
	gnutls_helper.h \
	gnutls_int.h \
	gnutls_kx.h \
	gnutls_mbuffers.h \
	gnutls_mem.h \
	gnutls_mpi.h \
	gnutls_num.h \
	gnutls_openpgp.h \
	gnutls_pk.h \
	gnutls_record.h \
	gnutls_rsa_export.h \
	gnutls_session_pack.h \
	gnutls_sig.h \
	gnutls_srp.h \
	gnutls_state.h \
	gnutls_str_array.h \
	gnutls_str.h \
	gnutls_supplemental.h \
	gnutls_v2_compat.h \
	gnutls_x509.h \
	gnutlsxx.h \
	gstr.h \
	hash.h \
	int.h \
	keydb.h \
	libtasn1.h \
	locks.h \
	main.h \
	max_record.h \
	opencdk.h \
	openpgp_int.h \
	packet.h \
	parser_aux.h \
	pbkdf2-sha1.h \
	pkcs11_int.h \
	psk.h \
	psk_passwd.h \
	random.h \
	safe_renegotiation.h \
	server_name.h \
	session_ticket.h \
	sha-padlock.h \
	signature.h \
	srp.h \
	srp_passwd.h \
	stream.h \
	structure.h \
	system.h \
	types.h \
	x509_b64.h \
	x509_int.h \
	x86.h

# Images to copy into HTML directory.
# e.g. HTML_IMAGES=$(top_srcdir)/gtk/stock-icons/stock_about_24.png
HTML_IMAGES=

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
# e.g. content_files=running.sgml building.sgml changes-2.0.sgml
content_files=

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
# These files must be listed here *and* in content_files
# e.g. expand_content_files=running.sgml
expand_content_files=

# CFLAGS and LDFLAGS for compiling gtkdoc-scangobj with your library.
# Only needed if you are using gtkdoc-scangobj to dynamically query widget
# signals and properties.
# e.g. GTKDOC_CFLAGS=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
GTKDOC_CFLAGS=
GTKDOC_LIBS=

# This includes the standard gtk-doc make rules, copied by gtkdocize.
include $(top_srcdir)/gtk-doc.make

# Other files to distribute
# e.g. EXTRA_DIST += version.xml.in
EXTRA_DIST +=

# Files not to distribute
# for --rebuild-types in $(SCAN_OPTIONS), e.g. $(DOC_MODULE).types
# for --rebuild-sections in $(SCAN_OPTIONS) e.g. $(DOC_MODULE)-sections.txt
#DISTCLEANFILES +=

# Comment this out if you want 'make check' to test you doc status
# and run some sanity checks
if ENABLE_GTK_DOC
TESTS_ENVIRONMENT = cd $(srcdir) && \
  DOC_MODULE=$(DOC_MODULE) DOC_MAIN_SGML_FILE=$(DOC_MAIN_SGML_FILE) \
  SRCDIR=$(abs_srcdir) BUILDDIR=$(abs_builddir)
#TESTS = $(GTKDOC_CHECK)
endif

-include $(top_srcdir)/git.mk
