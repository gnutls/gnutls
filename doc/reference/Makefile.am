## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004 Simon Josefsson.
#
# This file is part of GNU TLS.
#
# GNU TLS is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU TLS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU TLS; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

HIGNORE = auth_anon.h auth_cert.h auth_dh_common.h auth_srp.h		\
	auth_srp_passwd.h debug.h defines.h ext_cert_type.h		\
	ext_max_record.h ext_server_name.h ext_srp.h gnutls_alert.h	\
	gnutls_algorithms.h gnutls_auth.h gnutls_auth_int.h		\
	gnutls_buffer.h gnutls_buffers.h gnutls_cert.h gnutls_cipher.h	\
	gnutls_cipher_int.h gnutls_compress.h gnutls_compress_int.h	\
	gnutls_constate.h gnutls_datum.h gnutls_db.h gnutls_dh.h	\
	gnutls_errors.h gnutls_errors_int.h gnutls_extensions.h		\
	gnutls_global.h gnutls_handshake.h gnutls_hash_int.h		\
	gnutls_int.h gnutls_kx.h gnutls_mem.h gnutls_mpi.h		\
	gnutls_num.h gnutls_pk.h gnutls_priority.h gnutls_random.h	\
	gnutls_record.h gnutls_rsa_export.h gnutls_session.h		\
	gnutls_session_pack.h gnutls_sig.h gnutls_srp.h gnutls_state.h	\
	gnutls_str.h gnutls_ui.h gnutls_v2_compat.h gnutls_x509.h	\
	io_debug.h strfile.h x509_b64.h \
	common.h compat.h crq.h dn.h dsa.h extensions.h mpi.h pkcs7.h privkey.h rfc2818.h sign.h verify.h \
	gnutls_extra.h lzoconf.h minilzo.h openssl_compat.h \
	gnutls_openpgp.h openpgp.h

HTML_OBJECTS = index.html c4.html gnutls-gnutls.html gnutls-extra.html \
	gnutls-x509.html gnutls-pkcs12.html \
	gnutls-openssl.html

EXTRA_DIST = $(PACKAGE)-docs.tmpl $(HTML_OBJECTS) $(IMAGES)
IMAGES = home.png left.png right.png up.png

all: index.html

scan.stamp: $(top_builddir)/includes/gnutls/*.h $(top_srcdir)/lib/*.c $(top_srcdir)/lib/x509/*.c $(top_srcdir)/libextra/*.c $(top_srcdir)/libextra/openpgp/*.c
	gtkdoc-scan --module=$(PACKAGE) \
		--source-dir=$(top_builddir)/includes/gnutls \
		--source-dir=$(top_srcdir)/lib \
		--source-dir=$(top_srcdir)/lib/x509 \
		--source-dir=$(top_srcdir)/libextra \
		--source-dir=$(top_srcdir)/libextra/openpgp \
		--ignore-headers="$(HIGNORE)" && touch scan.stamp

tmpl.stamp: scan.stamp
	gtkdoc-mktmpl --module=$(PACKAGE) --output-dir=.

sgml.stamp: tmpl.stamp
	gtkdoc-mkdb --module=$(PACKAGE) --source-dir=$(top_srcdir)/lib \
		--tmpl-dir=. --output-dir=. \
		--main-sgml-file=$(srcdir)/$(PACKAGE)-docs.tmpl

index.html: sgml.stamp
	cp $(srcdir)/$(PACKAGE)-docs.tmpl $(PACKAGE)-docs.sgml
	gtkdoc-mkhtml $(PACKAGE) $(PACKAGE)-docs.sgml
	rm -f $(PACKAGE)-docs.sgml ../html.stamp
	gtkdoc-fixxref --module-dir=. --html-dir=$(HTML_DIR)

clean-local:
	rm -f *.bak scan.stamp tmpl.stamp sgml.stamp *.txt *.sgml \
		$(PACKAGE)-doc.bottom $(PACKAGE)-doc.top \
		$(HTML_OBJECTS) $(IMAGES) style.css
