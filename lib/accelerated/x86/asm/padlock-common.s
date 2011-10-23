#
# Copyright (C) 2011 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# The GnuTLS is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

.file	"padlock-common.s"
.text
.globl	is_padlock_nano
.type	is_padlock_nano,@function
.align	16
is_padlock_nano:
	pusha
	xorl	%eax,%eax
	cpuid
	movl    $1,%eax
	cpuid
	or      $0x000f,%eax
        cmp     $0x06ff,%eax
	jne     .Lno_nano
	popa
	mov     $1,%eax
        ret
.Lno_nano:
	popa
	xorl	%eax,%eax
        ret
.size	is_padlock_nano,.-is_padlock_nano

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
