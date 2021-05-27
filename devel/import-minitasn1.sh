#!/bin/sh

# This script copies files from the libtasn1 upstream, with necessary
# adjustments for bundling in GnuTLS.

set +e

: ${srcdir=.}
DIR=$srcdir/devel/libtasn1
SRC=$DIR/lib
DST=$srcdir/lib/minitasn1

IMPORTS="
coding.c
decoding.c
element.c
element.h
errors.c
gstr.c
gstr.h
int.h
parser_aux.c
parser_aux.h
structure.c
structure.h
version.c
libtasn1.h
"

test -d $DST || mkdir $DST

ASN1_VERSION=`git --git-dir $DIR/.git describe | sed 's/^v\([0-9]*\.[0-9]*\.[0-9]\)*.*/\1/'`
ASN1_VERSION_MAJOR=`echo ${ASN1_VERSION} | cut -d . -f 1`
ASN1_VERSION_MINOR=`echo ${ASN1_VERSION} | cut -d . -f 2`
ASN1_VERSION_PATCH=`echo ${ASN1_VERSION} | cut -d . -f 3`
ASN1_VERSION_NUMBER=`printf '0x%02x%02x%02x' $ASN1_VERSION_MAJOR $ASN1_VERSION_MINOR $ASN1_VERSION_PATCH`

for f in $IMPORTS; do
  src=$SRC/$f
  dst=$DST/$f
  if test "$f" = "libtasn1.h"; then
    src=$SRC/includes/$f.in
  fi
  if test -f $src; then
    if test -f $dst; then
      echo "Replacing $dst (existing file backed up in $dst~)"
      mv $dst $dst~
    else
      echo "Copying file $dst"
    fi
    cp $src $dst
    case $dst in
      */libtasn1.h)
	sed \
	  -e 's/@VERSION@/'${ASN1_VERSION}'/g' \
	  -e 's/@ASN1_VERSION_MAJOR@/'${ASN1_VERSION_MAJOR}'/g' \
	  -e 's/@ASN1_VERSION_MINOR@/'${ASN1_VERSION_MINOR}'/g' \
	  -e 's/@ASN1_VERSION_PATCH@/'${ASN1_VERSION_PATCH}'/g' \
	  -e 's/@ASN1_VERSION_NUMBER@/'${ASN1_VERSION_NUMBER}'/g' \
	  $dst > $dst-t && \
	mv $dst-t $dst
	;;
    esac
  else
    echo "Error: $src not found" 1>&2
    exit 1
  fi
done
