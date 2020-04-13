#!/bin/sh

# This script copies the Curve448 and Ed448, GOST 34.10 implementation from the
# nettle upstream, with necessary adjustments for bundling in GnuTLS.

set +e

: ${srcdir=.}
SRC=$srcdir/devel/nettle
DST=$srcdir/lib/nettle/curve448

IMPORTS="
cnd-copy.c
curve448-eh-to-x.c
curve448.h
curve448-mul.c
curve448-mul-g.c
eccdata.c
ecc-curve448.c
ecc-add-eh.c
ecc-add-ehh.c
ecc-add-jja.c
ecc-add-jjj.c
ecc-a-to-j.c
ecc-dup-eh.c
ecc-dup-jj.c
ecc-eh-to-a.c
ecc-gost-gc256b.c
ecc-gost-gc512a.c
ecc-gostdsa-sign.c
ecc-gostdsa-verify.c
ecc-internal.h
ecc-j-to-a.c
ecc-mod-arith.c
ecc-mod.c
ecc-mod-inv.c
ecc-mul-a.c
ecc-mul-a-eh.c
ecc-mul-g.c
ecc-mul-g-eh.c
ecc-mul-m.c
ecc-random.c
ed448-shake256.c
ed448-shake256-pubkey.c
ed448-shake256-sign.c
ed448-shake256-verify.c
eddsa-compress.c
eddsa-decompress.c
eddsa-expand.c
eddsa.h
eddsa-hash.c
eddsa-internal.h
eddsa-pubkey.c
eddsa-sign.c
eddsa-verify.c
gostdsa.h
gostdsa-sign.c
gostdsa-verify.c
gmp-glue.h
gmp-glue.c
nettle-write.h
sec-add-1.c
sec-tabselect.c
sha3.c
sha3.h
sha3-256.c
sha3-internal.h
sha3-permute.c
shake256.c
write-le64.c
"

PUBLIC="
bignum.h
dsa.h
ecc-curve.h
ecc.h
ecdsa.h
macros.h
memxor.h
nettle-meta.h
nettle-types.h
"

test -d $DST || mkdir $DST

for f in $IMPORTS; do
  src=$SRC/$f
  dst=$DST/$f
  if test -f $src; then
    if test -f $dst; then
      echo "Replacing $dst (existing file backed up in $dst~)"
      mv $dst $dst~
    else
      echo "Copying file $dst"
    fi
    cp $src $dst
    # Use <nettle/*.h> for public headers.
    for h in $PUBLIC; do
      p=$(echo $h | sed 's/\./\\./g')
      if grep '^#include "'$p'"' $dst 2>&1 >/dev/null; then
	sed 's!^#include "'$p'"!#include <nettle/'$h'>!' $dst > $dst-t && \
	  mv $dst-t $dst
      fi
    done
    # Remove unused <assert.h>.
    if grep '^#include <assert\.h>' $dst 2>&1 >/dev/null; then
      if ! grep 'assert *(' $dst 2>&1 >/dev/null; then
	sed '/^#include <assert\.h>/d' $dst > $dst-t && mv $dst-t $dst
      fi
    fi
    case $dst in
      *.h)
	# Rename header guard so as not to conflict with the public ones.
	if grep '^#ifndef NETTLE_.*_H\(_INCLUDED\)*' $dst 2>&1 >/dev/null; then
	  g=$(sed -n 's/^#ifndef NETTLE_\(.*_H\(_INCLUDED\)*\)/\1/p' $dst)
	  sed 's/\(NETTLE_'$g'\)/GNUTLS_LIB_NETTLE_CURVE448_\1/' $dst > $dst-t && \
	    mv $dst-t $dst
	fi
	# Add prefix to function symbols avoid clashing with the public ones.
	sed -e 's/^#define \(.*\) nettle_\1/#define \1 gnutls_nettle_curve448_\1/' \
	    -e 's/^#define \(.*\) _nettle_\1/#define \1 _gnutls_nettle_curve448_\1/' \
	    -e 's/^#define _\(.*\) _nettle_\1/#define _\1 _gnutls_nettle_curve448_\1/' \
	    -e 's/^_nettle_\(.*\)(.*/#define _nettle_\1 _gnutls_nettle_curve448_\1\n\0/' \
	    -e 's/^extern const struct ecc_curve _nettle_\(.*\);/#define _nettle_\1 _gnutls_nettle_curve448_\1\n\0/' \
	    -e 's/^extern const struct ecc_eddsa _nettle_\(.*\);/#define _nettle_\1 _gnutls_nettle_curve448_\1\n\0/' \
	    $dst > $dst-t && \
	  mv $dst-t $dst
      ;;
      */eccdata.c)
	sed 's/^#include "mini-gmp.c"/#include <gmp.h>/' $dst > $dst-t && \
	  mv $dst-t $dst
	;;
      */ecc-curve448.c)
	# The generated file is arch dependent, conditionalize the
	# inclusion.
	sed '/^#include "ecc-curve448\.h"/ { i\
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)\
# pragma GCC diagnostic ignored "-Wunused-const-variable"\
#endif\
#if GMP_NUMB_BITS == 32\
#include "curve448/ecc-curve448-32.h"\
#elif GMP_NUMB_BITS == 64\
#include "curve448/ecc-curve448-64.h"\
#else\
#error unsupported configuration\
#endif
; d
}' $dst > $dst-t && mv $dst-t $dst
	;;
      */ecc-gost-gc256b.c)
	# The generated file is arch dependent, conditionalize the
	# inclusion.
	sed '/^#include "ecc-gost-gc256b\.h"/ { i\
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)\
# pragma GCC diagnostic ignored "-Wunused-const-variable"\
#endif\
#if GMP_NUMB_BITS == 32\
#include "curve448/ecc-gost-gc256b-32.h"\
#elif GMP_NUMB_BITS == 64\
#include "curve448/ecc-gost-gc256b-64.h"\
#else\
#error unsupported configuration\
#endif
; d
}' $dst | sed -e 's/#include "ecc-internal.h"/\0\n#include "ecc-gost-curve.h"/' > $dst-t && mv $dst-t $dst
	;;
      */ecc-gost-gc512a.c)
	# The generated file is arch dependent, conditionalize the
	# inclusion.
	sed '/^#include "ecc-gost-gc512a\.h"/ { i\
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)\
# pragma GCC diagnostic ignored "-Wunused-const-variable"\
#endif\
#if GMP_NUMB_BITS == 32\
#include "curve448/ecc-gost-gc512a-32.h"\
#elif GMP_NUMB_BITS == 64\
#include "curve448/ecc-gost-gc512a-64.h"\
#else\
#error unsupported configuration\
#endif
; d
}' $dst | sed -e 's/#include "ecc-internal.h"/\0\n#include "ecc-gost-curve.h"/' > $dst-t && mv $dst-t $dst
	;;
      */eddsa-hash.c)
	# Known to be unnecessary.
	sed '/^#include "nettle-internal\.h"/d' $dst > $dst-t && mv $dst-t $dst
	;;
      */ecc-add-eh*.c)
	# Suppress whitespace errors in 'make syntax-check'.
	sed 's/ *	/		/g' $dst > $dst-t && mv $dst-t $dst
	;;
      */ecc-random.c|*/gostdsa-sign.c)
	sed 's/"nettle-internal\.h"/"nettle-alloca.h"/' $dst > $dst-t && mv $dst-t $dst
	;;
    esac
  else
    echo "Error: $src not found" 1>&2
    exit 1
  fi
done
