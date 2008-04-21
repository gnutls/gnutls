## Process this file with automake to produce Makefile.in

# We require automake 1.6 at least.
AUTOMAKE_OPTIONS = 1.6

# This is a blank Makefile.am for using gtk-doc.
# Copy this to your project's API docs directory and modify the variables to
# suit your project. See the GTK+ Makefiles in gtk+/docs/reference for examples
# of using the various options.

# The name of the module, e.g. 'glib'.
DOC_MODULE=$(PACKAGE)

# The top-level SGML file. You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting the functions and macros.
# e.g. DOC_SOURCE_DIR=../../../gtk
DOC_SOURCE_DIR=../../lib --source-dir=../../libextra --source-dir=../../includes

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED"
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--sgml-mode --output-format=xml
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/gtk/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/gtk/*.c
HFILE_GLOB=$(top_srcdir)/includes/gnutls/*.h $(top_builddir)/includes/gnutls/*.h
CFILE_GLOB=$(top_srcdir)/lib/*.c \
	$(top_srcdir)/lib/x509/*.c \
	$(top_srcdir)/lib/openpgp/*.c \
	$(top_srcdir)/libextra/*.c \
	$(top_srcdir)/lib/minitasn1/*.c

# Header files to ignore when scanning.
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h
IGNORE_HFILES=debug.h gnutls_compress.h defines.h gnutls_cipher.h	\
	gnutls_buffers.h gnutls_errors.h gnutls_int.h			\
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h		\
	gnutls_dh.h gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h	\
	gnutls_db.h gnutls_compress_int.h gnutls_priority.h		\
	gnutls_auth.h auth_anon.h gnutls_extensions.h gnutls_buffer.h	\
	gnutls_auth_int.h gnutls_random.h x509_b64.h			\
	gnutls_v2_compat.h gnutls_errors_int.h gnutls_datum.h		\
	auth_cert.h gnutls_mpi.h gnutls_pk.h gnutls_record.h		\
	gnutls_cert.h gnutls_constate.h gnutls_global.h strfile.h	\
	gnutls_sig.h gnutls_mem.h gnutls_ui.h io_debug.h		\
	ext_max_record.h gnutls_session_pack.h gnutls_alert.h		\
	gnutls_str.h gnutls_state.h gnutls_x509.h ext_cert_type.h	\
	gnutls_rsa_export.h ext_server_name.h auth_dh_common.h		\
	ext_srp.h gnutls_srp.h auth_srp.h auth_srp_passwd.h auth_psk.h	\
	auth_psk_passwd.h memmem.h gnutls_helper.h			\
	ext_inner_application.h						\
									\
	der.h errors.h gstr.h parser_aux.h element.h errors_int.h	\
	int.h structure.h						\
									\
	common.h compat.h						\
									\
	openssl_compat.h						\
									\
	cipher.h context.h filters.h main.h md.h packet.h		\
	stream.h types.h						\
									\
	gnutls_openpgp.h gnutlsxx.h gnutls_extra_hooks.h		\
	gnutls_supplemental.h						\
	opencdk.h

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
# e.g. INCLUDES=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
INCLUDES=
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

# Comment this out if you want your docs-status tested during 'make check'
#TESTS = $(GTKDOC_CHECK)

