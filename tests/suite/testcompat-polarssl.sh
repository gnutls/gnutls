#!/bin/sh

# Copyright (c) 2010-2015, Free Software Foundation, Inc.
# Copyright (c) 2012-2015, Nikos Mavrogiannopoulos
# All rights reserved.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this 
# list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors may
# be used to endorse or promote products derived from this software without specific
# prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

srcdir="${srcdir:-.}"

export TZ="UTC"

if test "${GNUTLS_FORCE_FIPS_MODE}" = 1;then
	echo "Cannot run in FIPS140-2 mode"
	exit 77
fi

# Check for datefudge
. "${srcdir}/../scripts/common.sh"

check_for_datefudge

cat /proc/cpuinfo|grep "model name"|grep "VIA Esther" >/dev/null 2>&1
if test $? = 0; then
	echo "PolarSSL is broken on VIA processors"
	exit 77
fi

timeout 1800 datefudge "2012-09-2" "${srcdir}/testcompat-main-polarssl"

ret=$?
test $ret = 124 && exit 77

exit $ret
