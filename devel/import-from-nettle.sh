#!/bin/sh

# This script copies files from the nettle upstream, with necessary
# adjustments for bundling in GnuTLS.

set +e

: ${srcdir=.}
SRC=$srcdir/devel/nettle
DST=$srcdir/lib/nettle/backport

IMPORTS="
block-internal.h
bswap-internal.h
ctr-internal.h
ctr.h
ctr16.c
ghash-internal.h
ghash-set-key.c
ghash-update.c
gmp-glue.c
gmp-glue.h
oaep.c
oaep.h
pss-mgf1.h
pss-mgf1.c
rsa-internal.h
rsa-oaep-encrypt.c
rsa-oaep-decrypt.c
rsa-sec-compute-root.c
rsa-sign-tr.c
siv-gcm-aes128.c
siv-gcm-aes256.c
siv-gcm.c
siv-gcm.h
siv-ghash-set-key.c
siv-ghash-update.c
"

PUBLIC="
aes.h
bignum.h
ctr.h
des.h
ecc-curve.h
ecc.h
gcm.h
macros.h
md5.h
memops.h
memxor.h
nettle-meta.h
nettle-types.h
rsa.h
sha1.h
sha2.h
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
	  sed 's/\(NETTLE_'$g'\)/GNUTLS_LIB_NETTLE_BACKPORT_\1/' $dst > $dst-t && \
	    mv $dst-t $dst
	fi
	;;
    esac
    case $dst in
      *.h)
	# Add prefix to function symbols avoid clashing with the public ones.
	sed -e 's/^#define \(.*\) nettle_\1/#define \1 gnutls_nettle_backport_\1/' \
	    -e 's/^#define _\(.*\) _nettle_\1/#define _\1 _gnutls_nettle_backport_\1/' \
	    -e 's/^#define \(.*\) _nettle_\1/#define \1 _gnutls_nettle_backport_\1/' \
	    $dst > $dst-t && \
	  mv $dst-t $dst
      ;;
    esac
    case $dst in
      */*.[ch])
	sed \
	  -e '/^#include <nettle\/nettle-types\.h>/a\
#include "block8.h"
' \
	  $dst > $dst-t && mv $dst-t $dst
	;;
    esac
    case $dst in
      */rsa-oaep-*.c)
	sed \
	  -e '/^#include <nettle\/rsa\.h>/a\
#include "int/rsa-oaep.h"
' \
	  $dst > $dst-t && mv $dst-t $dst
	;;
    esac
    # Avoid -Wcast-align=strict warnings
    case $dst in
      */ctr16.c)
	sed \
	  -e 's/\((union nettle_block16 \*) \)\(dst\)/\1(void *) \2/' \
	  $dst > $dst-t && mv $dst-t $dst
	;;
    esac
  else
    echo "Error: $src not found" 1>&2
    exit 1
  fi
done
