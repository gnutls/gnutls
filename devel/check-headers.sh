#!/bin/sh

# Copyright (c) 2023 Daiki Ueno
# License: GPLv3+ <http://gnu.org/licenses/gpl.html>

# This script checks that local header files under lib/ are
# consistently included with #include "foo.h" instead of #include
# <foo.h>.

: ${top_srcdir=.}

progname="$0"

test -d "$top_srcdir"/lib || {
    echo "Run this script from the top-level directory" 1>&2
    exit 1
}

mode=check

while test $# -gt 0; do
    case "$1" in
	--format )
	    mode=format
	    shift ;;
	--help )
	    echo "Usage: $progname [--parallel=MAX-PROCS] [--format]"
            exit ;;
	-* )
            echo "$progname: unknown option $1" 1>&2
            echo "Try '$progname --help' for more information." 1>&2
            exit 1 ;;
	* )
            break ;;
    esac
done

lib_quoted='config\.h'
lib_dirs=

for i in 1 2 3; do
    lib_quoted1=$(git ls-files "$top_srcdir"/lib | grep -v '^lib/includes' | grep '\.h$' | sed -n 's!^lib/'"$lib_dirs"'!!p' | paste -s -d'|' | sed -e 's!\.!\\.!g' -e 's!|!\\|!g')
    lib_quoted="$lib_quoted\|$lib_quoted1"
    lib_dirs="$lib_dirs[^/]*/"
done

src_quoted='config\.h'

src_quoted1=$(git ls-files "$top_srcdir"/src | grep '\.h$' | sed -n 's!^src/!!p' | paste -s -d'|' | sed -e 's!\.!\\.!g' -e 's!|!\\|!g')
src_quoted="$src_quoted\|$src_quoted1"

tests_quoted='config\.h'
tests_dirs=

for i in 1 2; do
    tests_quoted1=$(git ls-files "$top_srcdir"/tests | grep -v '^lib/includes' | grep '\.h$' | sed -n 's!^tests/'"$tests_dirs"'!!p' | paste -s -d'|' | sed -e 's!\.!\\.!g' -e 's!|!\\|!g')
    tests_quoted="$tests_quoted\|$tests_quoted1"
    tests_dirs="$tests_dirs[^/]*/"
done

lib_pattern="\(# *include *\)<\($lib_quoted\)>"
src_pattern="\(# *include *\)<\($src_quoted\)>"
tests_pattern="\(# *include *\)<\($tests_quoted\)>"

case $mode in
    check )
	grep "$lib_pattern" $(git ls-files "$top_srcdir"/lib | grep -v '^lib/includes' | grep '\.[ch]$') && exit 1
	grep "$src_pattern" $(git ls-files "$top_srcdir"/src | grep '\.[ch]$') && exit 1
	grep "$tests_pattern" $(git ls-files "$top_srcdir"/tests | grep '\.[ch]$') && exit 1
	exit 0
	;;
    format )
	sed -i 's!'"$lib_pattern"'!\1"\2"!' $(git ls-files "$top_srcdir"/lib | grep -v '^lib/includes' | grep '\.[ch]$')
	sed -i 's!'"$src_pattern"'!\1"\2"!' $(git ls-files "$top_srcdir"/src | grep '\.[ch]$')
	sed -i 's!'"$tests_pattern"'!\1"\2"!' $(git ls-files "$top_srcdir"/tests | grep '\.[ch]$')
	;;
esac
