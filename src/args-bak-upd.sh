#!/bin/sh

# Copyright (C) 2018 Dmitry Eremin-Solenikov
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Usage: args-bak-upd.sh file.stamp srcdir

# update_file file srcdir
update_file() {
	if ! test -h "$1"
	then
		if test "$2" = "."
		then
			cp "$1" "$1".bak
		else
			sed -e "s!$2/!!g" "$1" > "$2"/"$1".bak
		fi
	fi
}

BASENAME="`basename "$1" .stamp`"
update_file "${BASENAME}.c" "$2"
update_file "${BASENAME}.c" "$2"
