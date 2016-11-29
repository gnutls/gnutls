#!/bin/sh

# Copyright (C) 2006, 2008, 2010, 2012 Free Software Foundation, Inc.
#
# Author: Simon Josefsson
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

set -e

srcdir="${srcdir:-.}"
CERTTOOL="${CERTTOOL:-../src/certtool${EXEEXT}}"
TMPFILE1=rsa-md5.$$.tmp
TMPFILE2=rsa-md5-2.$$.tmp

. ${srcdir}/scripts/common.sh
check_for_datefudge

"${CERTTOOL}" --inder --certificate-info \
	--infile "${srcdir}/rsa-md5-collision/TargetCollidingCertificate1.cer" > $TMPFILE1
"${CERTTOOL}" --inder --certificate-info \
	--infile "${srcdir}/rsa-md5-collision/TargetCollidingCertificate2.cer" > $TMPFILE2

"${CERTTOOL}" --inder --certificate-info \
	--infile "${srcdir}/rsa-md5-collision/MD5CollisionCA.cer" >> $TMPFILE1
"${CERTTOOL}" --inder --certificate-info \
	--infile "${srcdir}/rsa-md5-collision/MD5CollisionCA.cer" >> $TMPFILE2

datefudge -s "2016-10-1" \
"${CERTTOOL}" --verify-chain < $TMPFILE1 | \
	grep 'Not verified.' | grep 'insecure algorithm' >/dev/null
datefudge -s "2016-10-1" \
"${CERTTOOL}" --verify-chain < $TMPFILE2 | \
	grep 'Not verified.' | grep 'insecure algorithm' >/dev/null

rm -f $TMPFILE1 $TMPFILE2

# We're done.
exit 0
