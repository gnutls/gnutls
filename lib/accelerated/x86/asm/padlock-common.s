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
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rbx
	xorq	%rax,%rax
	cpuid
	movq    $1,%rax
	cpuid
	or      $0x000f,%rax
        cmp     $0x06ff,%rax
	jne     .Lno_nano
	popq    %rbx
	mov     $1,%rax
	popq	%rbx
	leave
        ret
.Lno_nano:
	popq	%rbx
	xorq	%rax,%rax
	popq	%rbx
	leave
        ret
.size	is_padlock_nano,.-is_padlock_nano

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
