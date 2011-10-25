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

	.file "cpuid.asm"
        
	.text
.globl __gnutls_cpuid
.def   __gnutls_cpuid;	.scl	2;	.type	32;	.endef
.align 16
__gnutls_cpuid:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$12, %esp
	movl	%ebx, (%esp)
	movl	8(%ebp), %eax
	movl	%esi, 4(%esp)
	movl	%edi, 8(%esp)
	pushl %ebx
	cpuid
	movl %ebx, %edi
	popl %ebx
	movl	%edx, %esi
	movl	12(%ebp), %edx
	movl	%eax, (%edx)
	movl	16(%ebp), %eax
	movl	%edi, (%eax)
	movl	20(%ebp), %eax
	movl	%ecx, (%eax)
	movl	24(%ebp), %eax
	movl	%esi, (%eax)
	movl	(%esp), %ebx
	movl	4(%esp), %esi
	movl	8(%esp), %edi
	movl	%ebp, %esp
	popl	%ebp
	ret

.globl	__gnutls_have_cpuid
.def	__gnutls_have_cpuid;	.scl	2;	.type	32;	.endef
.align	16
__gnutls_have_cpuid:
	pushfl	
	pop %eax	
	orl $0x200000, %eax	
	push %eax	
	popfl	
	pushfl	
	pop %eax	
	andl $0x200000, %eax	
	ret
