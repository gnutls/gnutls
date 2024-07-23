#!/bin/sh

# This script generates dlopen stubs for optional libraries using dlwrap tool:
# https://crates.io/crates/dlwrap

# Copyright (c) 2023 Daiki Ueno
# License: GPLv3+ <http://gnu.org/licenses/gpl.html>

set +e

: ${srcdir=.}
: ${DLWRAP=dlwrap}

if ! "$DLWRAP" -V >& /dev/null; then
    echo 1>&2 "$0: "$DLWRAP" is missing"
    exit 77
fi

SRC="$srcdir/devel/$DLWRAP"
DST="$srcdir/lib/$DLWRAP"

echo "Generating $DST/zlib.h"

"$DLWRAP" --input /usr/include/zlib.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/z.syms" --license-file "$SRC/z.license" --soname Z_LIBRARY_SONAME_UNUSED --prefix gnutls_zlib --header-guard GNUTLS_LIB_DLWRAP_ZLIB_H_ --include "<zlib.h>"

echo "Generating $DST/zstd.h"

"$DLWRAP" --input /usr/include/zstd.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/zstd.syms" --license-file "$SRC/zstd.license" --soname ZSTD_LIBRARY_SONAME_UNUSED --prefix gnutls_zstd --header-guard GNUTLS_LIB_DLWRAP_ZSTD_H_ --include "<zstd.h>"

echo "Generating $DST/brotlienc.h"

"$DLWRAP" --input /usr/include/brotli/encode.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/brotlienc.syms" --license-file "$SRC/brotli.license" --soname BROTLIENC_LIBRARY_SONAME_UNUSED --prefix gnutls_brotlienc --loader-basename brotlienc --header-guard GNUTLS_LIB_DLWRAP_BROTLIENC_H_ --include "<brotli/encode.h>"

echo "Generating $DST/brotlidec.h"

"$DLWRAP" --input /usr/include/brotli/decode.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/brotlidec.syms" --license-file "$SRC/brotli.license" --soname BROTLIDEC_LIBRARY_SONAME_UNUSED --prefix gnutls_brotlidec --loader-basename brotlidec --header-guard GNUTLS_LIB_DLWRAP_BROTLIDEC_H_ --include "<brotli/decode.h>"

echo "Generating $DST/oqs.h"

"$DLWRAP" --input /usr/include/oqs/oqs.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/oqs.syms" --license "SPDX-License-Identifier: MIT" --soname OQS_LIBRARY_SONAME_UNUSED --prefix gnutls_oqs --header-guard GNUTLS_LIB_DLWRAP_OQS_H_ --include "<oqs/oqs.h>"

sed -i '/^#include <oqs\/oqs.h>/i\
/* Local modification: remove this once liboqs 0.10.2 is released */\
#include "config.h"\
#if !HAVE_DECL_OQS_SHA3_SET_CALLBACKS\
#include "liboqs/backport/sha3_ops.h"\
#endif\
' "$DST/oqs.h"

echo "Generating $DST/tss2_esys.h"

"$DLWRAP" --input /usr/include/tss2/tss2_esys.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/tss2-esys.syms" --license "SPDX-License-Identifier: BSD-2-Clause" --soname TSS2_ESYS_LIBRARY_SONAME_UNUSED --prefix gnutls_tss2_esys --header-guard GNUTLS_LIB_DLWRAP_TSS2_ESYS_H_ --include "<tss2/tss2_esys.h>"

echo "Generating $DST/tss2_mu.h"

"$DLWRAP" --input /usr/include/tss2/tss2_mu.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/tss2-mu.syms" --license "SPDX-License-Identifier: BSD-2-Clause" --soname TSS2_MU_LIBRARY_SONAME_UNUSED --prefix gnutls_tss2_mu --header-guard GNUTLS_LIB_DLWRAP_TSS2_MU_H_ --include "<tss2/tss2_mu.h>"

echo "Generating $DST/tss2_tctildr.h"

"$DLWRAP" --input /usr/include/tss2/tss2_tctildr.h -o "$DST" --clang-resource-dir $(clang -print-resource-dir) --symbol-file "$SRC/tss2-tctildr.syms" --license "SPDX-License-Identifier: BSD-2-Clause" --soname TSS2_TCTILDR_LIBRARY_SONAME_UNUSED --prefix gnutls_tss2_tctildr --header-guard GNUTLS_LIB_DLWRAP_TSS2_TCTILDR_H_ --include "<tss2/tss2_tctildr.h>"
