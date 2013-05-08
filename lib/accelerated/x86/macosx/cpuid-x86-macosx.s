/*
# Copyright (c) 2011-2012, Andy Polyakov <appro@openssl.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
#     * Redistributions of source code must retain copyright notices,
#      this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
#     * Neither the name of the Andy Polyakov nor the names of its
#      copyright holder and contributors may be used to endorse or
#      promote products derived from this software without specific
#      prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL), in which case the provisions of the GPL apply INSTEAD OF
# those given above.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# *** This file is auto-generated ***
#
*/
.file	"devel/perlasm/cpuid-x86.s"
.text
.globl	_gnutls_cpuid
.align	4
_gnutls_cpuid:
L_gnutls_cpuid_begin:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$12,%esp
	movl	%ebx,(%esp)
	movl	8(%ebp),%eax
	movl	%esi,4(%esp)
	movl	%edi,8(%esp)
	pushl	%ebx
	.byte	0x0f,0xa2
	movl	%ebx,%edi
	popl	%ebx
	movl	%edx,%esi
	movl	12(%ebp),%edx
	movl	%eax,(%edx)
	movl	16(%ebp),%eax
	movl	%edi,(%eax)
	movl	20(%ebp),%eax
	movl	%ecx,(%eax)
	movl	24(%ebp),%eax
	movl	%esi,(%eax)
	movl	(%esp),%ebx
	movl	4(%esp),%esi
	movl	8(%esp),%edi
	movl	%ebp,%esp
	popl	%ebp
	ret
.globl	_gnutls_have_cpuid
.align	4
_gnutls_have_cpuid:
L_gnutls_have_cpuid_begin:
	pushfl
	popl	%eax
	orl	$2097152,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	andl	$2097152,%eax
	ret
.byte	67,80,85,73,68,32,102,111,114,32,120,56,54,0
