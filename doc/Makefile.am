EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg
SUBDIRS = tex examples scripts manpages

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi fdl.texi error_codes.texi

error_codes.texi: ../lib/gnutls_errors_int.h ../lib/gnutls_errors.c ../src/errcodes.c
	-../src/errcodes > error_codes.texi
