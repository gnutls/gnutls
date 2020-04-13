#!/bin/sh

# This script copies the ChaCha20 implementation from the
# nettle upstream, with necessary adjustments for bundling in GnuTLS.

set +e

: ${srcdir=.}
SRC=$srcdir/devel/nettle
DST=$srcdir/lib/nettle/chacha

IMPORTS="
chacha-core-internal.c
chacha-crypt.c
chacha-internal.h
chacha-poly1305.c
chacha-poly1305.h
chacha-set-key.c
chacha-set-nonce.c
chacha.h
"

PUBLIC="
bignum.h
ecc-curve.h
ecc.h
macros.h
memxor.h
nettle-meta.h
nettle-types.h
poly1305.h
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
	  sed 's/\(NETTLE_'$g'\)/GNUTLS_LIB_NETTLE_CHACHA_\1/' $dst > $dst-t && \
	    mv $dst-t $dst
	fi
	;;
    esac
    case $dst in
      *.h)
	# Add prefix to function symbols avoid clashing with the public ones.
	sed -e 's/^#define \(.*\) nettle_\1/#define \1 gnutls_nettle_chacha_\1/' \
	    -e 's/^#define _\(.*\) _nettle_\1/#define _\1 _gnutls_nettle_chacha_\1/' \
	    -e 's/^#define \(.*\) _nettle_\1/#define \1 _gnutls_nettle_chacha_\1/' \
	    $dst > $dst-t && \
	  mv $dst-t $dst
      ;;
    esac
  else
    echo "Error: $src not found" 1>&2
    exit 1
  fi
done
