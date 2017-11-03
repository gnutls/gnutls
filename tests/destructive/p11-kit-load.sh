#!/bin/sh

# Copyright (C) 2017 Red Hat, Inc.
#
# This file is part of p11-kit.
#
# p11-kit is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# p11-kit is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

#set -e

srcdir="${srcdir:-.}"
builddir="${builddir:-.}"
P11TOOL="${P11TOOL:-../src/p11tool${EXEEXT}}"
CERTTOOL="${CERTTOOL:-../src/certtool${EXEEXT}}"
DIFF="${DIFF:-diff}"
PKGCONFIG="${PKG_CONFIG:-$(which pkg-config)}"

for lib in ${libdir} ${libdir}/pkcs11 /usr/lib64/pkcs11/ /usr/lib/pkcs11/ /usr/lib/x86_64-linux-gnu/pkcs11/;do
	if test -f "${lib}/p11-kit-trust.so"; then
		TRUST_MODULE="${lib}/p11-kit-trust.so"
		echo "located ${MODULE}"
		break
	fi
done

for lib in ${libdir} ${libdir}/pkcs11 /usr/lib64/pkcs11/ /usr/lib/pkcs11/ /usr/lib/x86_64-linux-gnu/pkcs11/;do
	if test -f "${lib}/libsofthsm2.so"; then
		SOFTHSM_MODULE="${lib}/libsofthsm2.so"
		echo "located ${MODULE}"
		break
	fi
done

${PKGCONFIG} --version >/dev/null || exit 77

if ! test -x "${P11TOOL}"; then
	echo "p11tool was not found"
	exit 77
fi

if ! test -f "${TRUST_MODULE}"; then
	echo "p11-kit trust module was not found"
	exit 77
fi

if ! test -f "${SOFTHSM_MODULE}"; then
	echo "softhsm module was not found"
	exit 77
fi

# Create pkcs11.conf with two modules, a trusted (p11-kit-trust)
# and softhsm (not trusted)
DIR=$(${PKGCONFIG} --var=p11_system_config_modules p11-kit-1)
rm -f ${DIR}/*

cat <<_EOF_ >${DIR}/p11-kit-trust.module
module: p11-kit-trust.so
trust-policy: yes
_EOF_

cat <<_EOF_ >${DIR}/softhsm.module
module: libsofthsm2.so
_EOF_

# Check whether p11tool would list them both

nr=$(${P11TOOL} --list-tokens|grep -c ^Token)
if test "$nr" != 2;then
	echo "Error: did not find 2 modules"
	${P11TOOL} --list-tokens
fi

# Check whether p11tool with a specific provider would list only that

nr=$(${P11TOOL} --provider "${SOFTHSM_MODULE}" --list-tokens|grep -c ^Token)
if test "$nr" != 1;then
	echo "Error: did not find softhsm modules"
	${P11TOOL} --list-tokens --provider "${SOFTHSM_MODULE}"
fi


# Check whether p11tool will list the trust module
# if we only load softhsm (it should as trust modules
# are always loaded).ould list them both

nr=$(${P11TOOL} --list-tokens|grep -c ^Token)
if test "$nr" != 2;then
	echo "Error: did not find 2 modules"
	${P11TOOL} --list-tokens
fi


# Check whether both modules are found when gnutls_pkcs11_init
# is not called but a pkcs11 operation is called.
${builddir}/pkcs11/list-tokens -d|wc -l
if test "$nr" != 2;then
	echo "Error in test 1: did not find 2 modules"
	${builddir}/pkcs11/list-tokens -d
fi

# Check whether both modules are found when gnutls_pkcs11_init 
# is called with the auto flag
${builddir}/pkcs11/list-tokens -a|wc -l
if test "$nr" != 2;then
	echo "Error in test 2: did not find 2 modules"
	${builddir}/pkcs11/list-tokens -a
fi

# Check whether only trusted modules are listed when the
# trusted flag is given to gnutls_pkcs11_init().
${builddir}/pkcs11/list-tokens -t|wc -l
if test "$nr" != 1;then
	echo "Error in test 3: did not find the trusted module"
	${builddir}/pkcs11/list-tokens -t
fi

# Check whether only trusted is listed after certificate verification
# is performed.
${builddir}/pkcs11/list-tokens -v|wc -l
if test "$nr" != 1;then
	echo "Error in test 4: did not find 1 module"
	${builddir}/pkcs11/list-tokens -v
fi

# Check whether only trusted is listed when gnutls_pkcs11_init
# is called with manual flag and a certificate verification is performed.
${builddir}/pkcs11/list-tokens -m -v|wc -l
if test "$nr" != 1;then
	echo "Error in test 5: did not find 1 module"
	${builddir}/pkcs11/list-tokens -m -v
fi

# Check whether all modules are listed after certificate verification
# is performed then a PKCS#11 function is called.
${builddir}/pkcs11/list-tokens -v -d|wc -l
if test "$nr" != 2;then
	echo "Error in test 6: did not find all modules"
	${builddir}/pkcs11/list-tokens -v
fi

exit 0
