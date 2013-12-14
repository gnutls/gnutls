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
.text	



.globl	sha256_multi_block
.def	sha256_multi_block;	.scl 2;	.type 32;	.endef
.p2align	5
sha256_multi_block:
	movq	%rdi,8(%rsp)
	movq	%rsi,16(%rsp)
	movq	%rsp,%rax
.LSEH_begin_sha256_multi_block:
	movq	%rcx,%rdi
	movq	%rdx,%rsi
	movq	%r8,%rdx

	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	leaq	-168(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,16(%rsp)
	movaps	%xmm8,32(%rsp)
	movaps	%xmm9,48(%rsp)
	movaps	%xmm10,-120(%rax)
	movaps	%xmm11,-104(%rax)
	movaps	%xmm12,-88(%rax)
	movaps	%xmm13,-72(%rax)
	movaps	%xmm14,-56(%rax)
	movaps	%xmm15,-40(%rax)
	subq	$288,%rsp
	andq	$-256,%rsp
	movq	%rax,272(%rsp)
	leaq	K256+128(%rip),%rbp
	leaq	256(%rsp),%rbx
	leaq	128(%rdi),%rdi

.Loop_grande:
	movl	%edx,280(%rsp)
	xorl	%edx,%edx
	movq	0(%rsi),%r8
	movl	8(%rsi),%ecx
	cmpl	%edx,%ecx
	cmovgl	%ecx,%edx
	testl	%ecx,%ecx
	movl	%ecx,0(%rbx)
	cmovleq	%rbp,%r8
	movq	16(%rsi),%r9
	movl	24(%rsi),%ecx
	cmpl	%edx,%ecx
	cmovgl	%ecx,%edx
	testl	%ecx,%ecx
	movl	%ecx,4(%rbx)
	cmovleq	%rbp,%r9
	movq	32(%rsi),%r10
	movl	40(%rsi),%ecx
	cmpl	%edx,%ecx
	cmovgl	%ecx,%edx
	testl	%ecx,%ecx
	movl	%ecx,8(%rbx)
	cmovleq	%rbp,%r10
	movq	48(%rsi),%r11
	movl	56(%rsi),%ecx
	cmpl	%edx,%ecx
	cmovgl	%ecx,%edx
	testl	%ecx,%ecx
	movl	%ecx,12(%rbx)
	cmovleq	%rbp,%r11
	testl	%edx,%edx
	jz	.Ldone

	movdqu	0-128(%rdi),%xmm8
	leaq	128(%rsp),%rax
	movdqu	32-128(%rdi),%xmm9
	movdqu	64-128(%rdi),%xmm10
	movdqu	96-128(%rdi),%xmm11
	movdqu	128-128(%rdi),%xmm12
	movdqu	160-128(%rdi),%xmm13
	movdqu	192-128(%rdi),%xmm14
	movdqu	224-128(%rdi),%xmm15
	movdqu	.Lpbswap(%rip),%xmm6
	jmp	.Loop

.p2align	5
.Loop:
	movdqa	%xmm10,%xmm4
	pxor	%xmm9,%xmm4
	movd	0(%r8),%xmm5
	movd	0(%r9),%xmm0
	movd	0(%r10),%xmm1
	movd	0(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm12,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm12,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,0-128(%rax)
	paddd	%xmm15,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-128(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm12,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm14,%xmm0
	pand	%xmm13,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm8,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm9,%xmm3
	movdqa	%xmm8,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm8,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm9,%xmm15
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm15
	paddd	%xmm5,%xmm11
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm15
	paddd	%xmm7,%xmm15
	movd	4(%r8),%xmm5
	movd	4(%r9),%xmm0
	movd	4(%r10),%xmm1
	movd	4(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm11,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm11,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,16-128(%rax)
	paddd	%xmm14,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-96(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm11,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm13,%xmm0
	pand	%xmm12,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm15,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm8,%xmm4
	movdqa	%xmm15,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm15,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm8,%xmm14
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm14
	paddd	%xmm5,%xmm10
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm14
	paddd	%xmm7,%xmm14
	movd	8(%r8),%xmm5
	movd	8(%r9),%xmm0
	movd	8(%r10),%xmm1
	movd	8(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm10,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm10,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,32-128(%rax)
	paddd	%xmm13,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm10,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm12,%xmm0
	pand	%xmm11,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm14,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm15,%xmm3
	movdqa	%xmm14,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm14,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm15,%xmm13
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm13
	paddd	%xmm5,%xmm9
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm13
	paddd	%xmm7,%xmm13
	movd	12(%r8),%xmm5
	movd	12(%r9),%xmm0
	movd	12(%r10),%xmm1
	movd	12(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm9,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm9,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,48-128(%rax)
	paddd	%xmm12,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-32(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm9,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm11,%xmm0
	pand	%xmm10,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm13,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm14,%xmm4
	movdqa	%xmm13,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm13,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm14,%xmm12
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm12
	paddd	%xmm5,%xmm8
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm12
	paddd	%xmm7,%xmm12
	movd	16(%r8),%xmm5
	movd	16(%r9),%xmm0
	movd	16(%r10),%xmm1
	movd	16(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm8,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm8,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,64-128(%rax)
	paddd	%xmm11,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	0(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm8,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm10,%xmm0
	pand	%xmm9,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm12,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm13,%xmm3
	movdqa	%xmm12,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm12,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm13,%xmm11
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm11
	paddd	%xmm5,%xmm15
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm11
	paddd	%xmm7,%xmm11
	movd	20(%r8),%xmm5
	movd	20(%r9),%xmm0
	movd	20(%r10),%xmm1
	movd	20(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm15,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm15,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,80-128(%rax)
	paddd	%xmm10,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	32(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm15,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm9,%xmm0
	pand	%xmm8,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm11,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm12,%xmm4
	movdqa	%xmm11,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm11,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm12,%xmm10
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm10
	paddd	%xmm5,%xmm14
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm10
	paddd	%xmm7,%xmm10
	movd	24(%r8),%xmm5
	movd	24(%r9),%xmm0
	movd	24(%r10),%xmm1
	movd	24(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm14,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm14,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,96-128(%rax)
	paddd	%xmm9,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm14,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm8,%xmm0
	pand	%xmm15,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm10,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm11,%xmm3
	movdqa	%xmm10,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm10,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm11,%xmm9
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm9
	paddd	%xmm5,%xmm13
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm9
	paddd	%xmm7,%xmm9
	movd	28(%r8),%xmm5
	movd	28(%r9),%xmm0
	movd	28(%r10),%xmm1
	movd	28(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm13,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm13,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,112-128(%rax)
	paddd	%xmm8,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	96(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm13,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm15,%xmm0
	pand	%xmm14,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm9,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm10,%xmm4
	movdqa	%xmm9,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm9,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm10,%xmm8
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm8
	paddd	%xmm5,%xmm12
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm8
	paddd	%xmm7,%xmm8
	leaq	256(%rbp),%rbp
	movd	32(%r8),%xmm5
	movd	32(%r9),%xmm0
	movd	32(%r10),%xmm1
	movd	32(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm12,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm12,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,128-128(%rax)
	paddd	%xmm15,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-128(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm12,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm14,%xmm0
	pand	%xmm13,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm8,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm9,%xmm3
	movdqa	%xmm8,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm8,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm9,%xmm15
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm15
	paddd	%xmm5,%xmm11
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm15
	paddd	%xmm7,%xmm15
	movd	36(%r8),%xmm5
	movd	36(%r9),%xmm0
	movd	36(%r10),%xmm1
	movd	36(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm11,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm11,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,144-128(%rax)
	paddd	%xmm14,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-96(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm11,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm13,%xmm0
	pand	%xmm12,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm15,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm8,%xmm4
	movdqa	%xmm15,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm15,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm8,%xmm14
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm14
	paddd	%xmm5,%xmm10
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm14
	paddd	%xmm7,%xmm14
	movd	40(%r8),%xmm5
	movd	40(%r9),%xmm0
	movd	40(%r10),%xmm1
	movd	40(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm10,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm10,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,160-128(%rax)
	paddd	%xmm13,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm10,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm12,%xmm0
	pand	%xmm11,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm14,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm15,%xmm3
	movdqa	%xmm14,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm14,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm15,%xmm13
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm13
	paddd	%xmm5,%xmm9
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm13
	paddd	%xmm7,%xmm13
	movd	44(%r8),%xmm5
	movd	44(%r9),%xmm0
	movd	44(%r10),%xmm1
	movd	44(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm9,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm9,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,176-128(%rax)
	paddd	%xmm12,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-32(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm9,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm11,%xmm0
	pand	%xmm10,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm13,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm14,%xmm4
	movdqa	%xmm13,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm13,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm14,%xmm12
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm12
	paddd	%xmm5,%xmm8
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm12
	paddd	%xmm7,%xmm12
	movd	48(%r8),%xmm5
	movd	48(%r9),%xmm0
	movd	48(%r10),%xmm1
	movd	48(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm8,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm8,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,192-128(%rax)
	paddd	%xmm11,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	0(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm8,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm10,%xmm0
	pand	%xmm9,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm12,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm13,%xmm3
	movdqa	%xmm12,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm12,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm13,%xmm11
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm11
	paddd	%xmm5,%xmm15
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm11
	paddd	%xmm7,%xmm11
	movd	52(%r8),%xmm5
	movd	52(%r9),%xmm0
	movd	52(%r10),%xmm1
	movd	52(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm15,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm15,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,208-128(%rax)
	paddd	%xmm10,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	32(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm15,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm9,%xmm0
	pand	%xmm8,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm11,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm12,%xmm4
	movdqa	%xmm11,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm11,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm12,%xmm10
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm10
	paddd	%xmm5,%xmm14
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm10
	paddd	%xmm7,%xmm10
	movd	56(%r8),%xmm5
	movd	56(%r9),%xmm0
	movd	56(%r10),%xmm1
	movd	56(%r11),%xmm2
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm14,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm14,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,224-128(%rax)
	paddd	%xmm9,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm14,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm8,%xmm0
	pand	%xmm15,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm10,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm11,%xmm3
	movdqa	%xmm10,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm10,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm11,%xmm9
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm9
	paddd	%xmm5,%xmm13
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm9
	paddd	%xmm7,%xmm9
	movd	60(%r8),%xmm5
	leaq	64(%r8),%r8
	movd	60(%r9),%xmm0
	leaq	64(%r9),%r9
	movd	60(%r10),%xmm1
	leaq	64(%r10),%r10
	movd	60(%r11),%xmm2
	leaq	64(%r11),%r11
	punpckldq	%xmm1,%xmm5
	punpckldq	%xmm2,%xmm0
	punpckldq	%xmm0,%xmm5
.byte	102,15,56,0,238
	movdqa	%xmm13,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm13,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,240-128(%rax)
	paddd	%xmm8,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	96(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm13,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm15,%xmm0
	pand	%xmm14,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm9,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	%xmm10,%xmm4
	movdqa	%xmm9,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm9,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm10,%xmm8
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm8
	paddd	%xmm5,%xmm12
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm8
	paddd	%xmm7,%xmm8
	leaq	256(%rbp),%rbp
	movdqu	0-128(%rax),%xmm5
	movl	$3,%ecx
	jmp	.Loop_16_xx
.p2align	5
.Loop_16_xx:
	movdqa	16-128(%rax),%xmm6
	paddd	144-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	224-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm12,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm12,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,0-128(%rax)
	paddd	%xmm15,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-128(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm12,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm14,%xmm0
	pand	%xmm13,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm8,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm9,%xmm3
	movdqa	%xmm8,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm8,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm9,%xmm15
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm15
	paddd	%xmm5,%xmm11
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm15
	paddd	%xmm7,%xmm15
	movdqa	32-128(%rax),%xmm5
	paddd	160-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	240-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm11,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm11,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,16-128(%rax)
	paddd	%xmm14,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-96(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm11,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm13,%xmm0
	pand	%xmm12,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm15,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm8,%xmm4
	movdqa	%xmm15,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm15,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm8,%xmm14
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm14
	paddd	%xmm6,%xmm10
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm14
	paddd	%xmm7,%xmm14
	movdqa	48-128(%rax),%xmm6
	paddd	176-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	0-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm10,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm10,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,32-128(%rax)
	paddd	%xmm13,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm10,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm12,%xmm0
	pand	%xmm11,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm14,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm15,%xmm3
	movdqa	%xmm14,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm14,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm15,%xmm13
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm13
	paddd	%xmm5,%xmm9
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm13
	paddd	%xmm7,%xmm13
	movdqa	64-128(%rax),%xmm5
	paddd	192-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	16-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm9,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm9,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,48-128(%rax)
	paddd	%xmm12,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-32(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm9,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm11,%xmm0
	pand	%xmm10,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm13,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm14,%xmm4
	movdqa	%xmm13,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm13,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm14,%xmm12
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm12
	paddd	%xmm6,%xmm8
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm12
	paddd	%xmm7,%xmm12
	movdqa	80-128(%rax),%xmm6
	paddd	208-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	32-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm8,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm8,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,64-128(%rax)
	paddd	%xmm11,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	0(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm8,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm10,%xmm0
	pand	%xmm9,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm12,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm13,%xmm3
	movdqa	%xmm12,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm12,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm13,%xmm11
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm11
	paddd	%xmm5,%xmm15
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm11
	paddd	%xmm7,%xmm11
	movdqa	96-128(%rax),%xmm5
	paddd	224-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	48-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm15,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm15,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,80-128(%rax)
	paddd	%xmm10,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	32(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm15,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm9,%xmm0
	pand	%xmm8,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm11,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm12,%xmm4
	movdqa	%xmm11,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm11,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm12,%xmm10
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm10
	paddd	%xmm6,%xmm14
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm10
	paddd	%xmm7,%xmm10
	movdqa	112-128(%rax),%xmm6
	paddd	240-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	64-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm14,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm14,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,96-128(%rax)
	paddd	%xmm9,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm14,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm8,%xmm0
	pand	%xmm15,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm10,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm11,%xmm3
	movdqa	%xmm10,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm10,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm11,%xmm9
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm9
	paddd	%xmm5,%xmm13
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm9
	paddd	%xmm7,%xmm9
	movdqa	128-128(%rax),%xmm5
	paddd	0-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	80-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm13,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm13,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,112-128(%rax)
	paddd	%xmm8,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	96(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm13,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm15,%xmm0
	pand	%xmm14,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm9,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm10,%xmm4
	movdqa	%xmm9,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm9,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm10,%xmm8
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm8
	paddd	%xmm6,%xmm12
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm8
	paddd	%xmm7,%xmm8
	leaq	256(%rbp),%rbp
	movdqa	144-128(%rax),%xmm6
	paddd	16-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	96-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm12,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm12,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,128-128(%rax)
	paddd	%xmm15,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-128(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm12,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm14,%xmm0
	pand	%xmm13,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm8,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm9,%xmm3
	movdqa	%xmm8,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm8,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm9,%xmm15
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm15
	paddd	%xmm5,%xmm11
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm15
	paddd	%xmm7,%xmm15
	movdqa	160-128(%rax),%xmm5
	paddd	32-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	112-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm11,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm11,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,144-128(%rax)
	paddd	%xmm14,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-96(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm11,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm13,%xmm0
	pand	%xmm12,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm15,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm8,%xmm4
	movdqa	%xmm15,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm15,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm8,%xmm14
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm14
	paddd	%xmm6,%xmm10
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm14
	paddd	%xmm7,%xmm14
	movdqa	176-128(%rax),%xmm6
	paddd	48-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	128-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm10,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm10,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,160-128(%rax)
	paddd	%xmm13,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm10,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm12,%xmm0
	pand	%xmm11,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm14,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm15,%xmm3
	movdqa	%xmm14,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm14,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm15,%xmm13
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm13
	paddd	%xmm5,%xmm9
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm13
	paddd	%xmm7,%xmm13
	movdqa	192-128(%rax),%xmm5
	paddd	64-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	144-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm9,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm9,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,176-128(%rax)
	paddd	%xmm12,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	-32(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm9,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm11,%xmm0
	pand	%xmm10,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm13,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm14,%xmm4
	movdqa	%xmm13,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm13,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm14,%xmm12
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm12
	paddd	%xmm6,%xmm8
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm12
	paddd	%xmm7,%xmm12
	movdqa	208-128(%rax),%xmm6
	paddd	80-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	160-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm8,%xmm7
	movdqa	%xmm8,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm8,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,192-128(%rax)
	paddd	%xmm11,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	0(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm8,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm8,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm10,%xmm0
	pand	%xmm9,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm12,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm12,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm13,%xmm3
	movdqa	%xmm12,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm12,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm13,%xmm11
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm11
	paddd	%xmm5,%xmm15
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm11
	paddd	%xmm7,%xmm11
	movdqa	224-128(%rax),%xmm5
	paddd	96-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	176-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm15,%xmm7
	movdqa	%xmm15,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm15,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,208-128(%rax)
	paddd	%xmm10,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	32(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm15,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm15,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm9,%xmm0
	pand	%xmm8,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm11,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm11,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm12,%xmm4
	movdqa	%xmm11,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm11,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm12,%xmm10
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm10
	paddd	%xmm6,%xmm14
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm10
	paddd	%xmm7,%xmm10
	movdqa	240-128(%rax),%xmm6
	paddd	112-128(%rax),%xmm5

	movdqa	%xmm6,%xmm7
	movdqa	%xmm6,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm6,%xmm2

	psrld	$7,%xmm1
	movdqa	192-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm3,%xmm1

	psrld	$17,%xmm3
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	psrld	$19-17,%xmm3
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm3,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm5
	movdqa	%xmm14,%xmm7
	movdqa	%xmm14,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm14,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm5,224-128(%rax)
	paddd	%xmm9,%xmm5

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	64(%rbp),%xmm5
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm14,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm14,%xmm3
	pslld	$26-21,%xmm2
	pandn	%xmm8,%xmm0
	pand	%xmm15,%xmm3
	pxor	%xmm1,%xmm7

	movdqa	%xmm10,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm10,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm5
	pxor	%xmm3,%xmm0
	movdqa	%xmm11,%xmm3
	movdqa	%xmm10,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm10,%xmm3

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm5
	pslld	$19-10,%xmm2
	pand	%xmm3,%xmm4
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm11,%xmm9
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm4,%xmm9
	paddd	%xmm5,%xmm13
	pxor	%xmm2,%xmm7

	paddd	%xmm5,%xmm9
	paddd	%xmm7,%xmm9
	movdqa	0-128(%rax),%xmm5
	paddd	128-128(%rax),%xmm6

	movdqa	%xmm5,%xmm7
	movdqa	%xmm5,%xmm1
	psrld	$3,%xmm7
	movdqa	%xmm5,%xmm2

	psrld	$7,%xmm1
	movdqa	208-128(%rax),%xmm0
	pslld	$14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$18-7,%xmm1
	movdqa	%xmm0,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$25-14,%xmm2
	pxor	%xmm1,%xmm7
	psrld	$10,%xmm0
	movdqa	%xmm4,%xmm1

	psrld	$17,%xmm4
	pxor	%xmm2,%xmm7
	pslld	$13,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	psrld	$19-17,%xmm4
	pxor	%xmm1,%xmm0
	pslld	$15-13,%xmm1
	pxor	%xmm4,%xmm0
	pxor	%xmm1,%xmm0
	paddd	%xmm0,%xmm6
	movdqa	%xmm13,%xmm7
	movdqa	%xmm13,%xmm2
	psrld	$6,%xmm7
	movdqa	%xmm13,%xmm1
	pslld	$7,%xmm2
	movdqa	%xmm6,240-128(%rax)
	paddd	%xmm8,%xmm6

	psrld	$11,%xmm1
	pxor	%xmm2,%xmm7
	pslld	$21-7,%xmm2
	paddd	96(%rbp),%xmm6
	pxor	%xmm1,%xmm7

	psrld	$25-11,%xmm1
	movdqa	%xmm13,%xmm0
	pxor	%xmm2,%xmm7
	movdqa	%xmm13,%xmm4
	pslld	$26-21,%xmm2
	pandn	%xmm15,%xmm0
	pand	%xmm14,%xmm4
	pxor	%xmm1,%xmm7

	movdqa	%xmm9,%xmm1
	pxor	%xmm2,%xmm7
	movdqa	%xmm9,%xmm2
	psrld	$2,%xmm1
	paddd	%xmm7,%xmm6
	pxor	%xmm4,%xmm0
	movdqa	%xmm10,%xmm4
	movdqa	%xmm9,%xmm7
	pslld	$10,%xmm2
	pxor	%xmm9,%xmm4

	psrld	$13,%xmm7
	pxor	%xmm2,%xmm1
	paddd	%xmm0,%xmm6
	pslld	$19-10,%xmm2
	pand	%xmm4,%xmm3
	pxor	%xmm7,%xmm1

	psrld	$22-13,%xmm7
	pxor	%xmm2,%xmm1
	movdqa	%xmm10,%xmm8
	pslld	$30-19,%xmm2
	pxor	%xmm1,%xmm7
	pxor	%xmm3,%xmm8
	paddd	%xmm6,%xmm12
	pxor	%xmm2,%xmm7

	paddd	%xmm6,%xmm8
	paddd	%xmm7,%xmm8
	leaq	256(%rbp),%rbp
	decl	%ecx
	jnz	.Loop_16_xx

	movl	$1,%ecx
	leaq	K256+128(%rip),%rbp

	movdqa	(%rbx),%xmm7
	cmpl	0(%rbx),%ecx
	pxor	%xmm0,%xmm0
	cmovgeq	%rbp,%r8
	cmpl	4(%rbx),%ecx
	movdqa	%xmm7,%xmm6
	cmovgeq	%rbp,%r9
	cmpl	8(%rbx),%ecx
	pcmpgtd	%xmm0,%xmm6
	cmovgeq	%rbp,%r10
	cmpl	12(%rbx),%ecx
	paddd	%xmm6,%xmm7
	cmovgeq	%rbp,%r11

	movdqu	0-128(%rdi),%xmm0
	pand	%xmm6,%xmm8
	movdqu	32-128(%rdi),%xmm1
	pand	%xmm6,%xmm9
	movdqu	64-128(%rdi),%xmm2
	pand	%xmm6,%xmm10
	movdqu	96-128(%rdi),%xmm5
	pand	%xmm6,%xmm11
	paddd	%xmm0,%xmm8
	movdqu	128-128(%rdi),%xmm0
	pand	%xmm6,%xmm12
	paddd	%xmm1,%xmm9
	movdqu	160-128(%rdi),%xmm1
	pand	%xmm6,%xmm13
	paddd	%xmm2,%xmm10
	movdqu	192-128(%rdi),%xmm2
	pand	%xmm6,%xmm14
	paddd	%xmm5,%xmm11
	movdqu	224-128(%rdi),%xmm5
	pand	%xmm6,%xmm15
	paddd	%xmm0,%xmm12
	paddd	%xmm1,%xmm13
	movdqu	%xmm8,0-128(%rdi)
	paddd	%xmm2,%xmm14
	movdqu	%xmm9,32-128(%rdi)
	paddd	%xmm5,%xmm15
	movdqu	%xmm10,64-128(%rdi)
	movdqu	%xmm11,96-128(%rdi)
	movdqu	%xmm12,128-128(%rdi)
	movdqu	%xmm13,160-128(%rdi)
	movdqu	%xmm14,192-128(%rdi)
	movdqu	%xmm15,224-128(%rdi)

	movdqa	%xmm7,(%rbx)
	movdqa	.Lpbswap(%rip),%xmm6
	decl	%edx
	jnz	.Loop

	movl	280(%rsp),%edx
	leaq	16(%rdi),%rdi
	leaq	64(%rsi),%rsi
	decl	%edx
	jnz	.Loop_grande

.Ldone:
	movq	272(%rsp),%rax
	movaps	-184(%rax),%xmm6
	movaps	-168(%rax),%xmm7
	movaps	-152(%rax),%xmm8
	movaps	-136(%rax),%xmm9
	movaps	-120(%rax),%xmm10
	movaps	-104(%rax),%xmm11
	movaps	-88(%rax),%xmm12
	movaps	-72(%rax),%xmm13
	movaps	-56(%rax),%xmm14
	movaps	-40(%rax),%xmm15
	movq	-16(%rax),%rbp
	movq	-8(%rax),%rbx
	leaq	(%rax),%rsp
	movq	8(%rsp),%rdi
	movq	16(%rsp),%rsi
	.byte	0xf3,0xc3
.LSEH_end_sha256_multi_block:
.p2align	8
K256:
.long	1116352408,1116352408,1116352408,1116352408
.long	1116352408,1116352408,1116352408,1116352408
.long	1899447441,1899447441,1899447441,1899447441
.long	1899447441,1899447441,1899447441,1899447441
.long	3049323471,3049323471,3049323471,3049323471
.long	3049323471,3049323471,3049323471,3049323471
.long	3921009573,3921009573,3921009573,3921009573
.long	3921009573,3921009573,3921009573,3921009573
.long	961987163,961987163,961987163,961987163
.long	961987163,961987163,961987163,961987163
.long	1508970993,1508970993,1508970993,1508970993
.long	1508970993,1508970993,1508970993,1508970993
.long	2453635748,2453635748,2453635748,2453635748
.long	2453635748,2453635748,2453635748,2453635748
.long	2870763221,2870763221,2870763221,2870763221
.long	2870763221,2870763221,2870763221,2870763221
.long	3624381080,3624381080,3624381080,3624381080
.long	3624381080,3624381080,3624381080,3624381080
.long	310598401,310598401,310598401,310598401
.long	310598401,310598401,310598401,310598401
.long	607225278,607225278,607225278,607225278
.long	607225278,607225278,607225278,607225278
.long	1426881987,1426881987,1426881987,1426881987
.long	1426881987,1426881987,1426881987,1426881987
.long	1925078388,1925078388,1925078388,1925078388
.long	1925078388,1925078388,1925078388,1925078388
.long	2162078206,2162078206,2162078206,2162078206
.long	2162078206,2162078206,2162078206,2162078206
.long	2614888103,2614888103,2614888103,2614888103
.long	2614888103,2614888103,2614888103,2614888103
.long	3248222580,3248222580,3248222580,3248222580
.long	3248222580,3248222580,3248222580,3248222580
.long	3835390401,3835390401,3835390401,3835390401
.long	3835390401,3835390401,3835390401,3835390401
.long	4022224774,4022224774,4022224774,4022224774
.long	4022224774,4022224774,4022224774,4022224774
.long	264347078,264347078,264347078,264347078
.long	264347078,264347078,264347078,264347078
.long	604807628,604807628,604807628,604807628
.long	604807628,604807628,604807628,604807628
.long	770255983,770255983,770255983,770255983
.long	770255983,770255983,770255983,770255983
.long	1249150122,1249150122,1249150122,1249150122
.long	1249150122,1249150122,1249150122,1249150122
.long	1555081692,1555081692,1555081692,1555081692
.long	1555081692,1555081692,1555081692,1555081692
.long	1996064986,1996064986,1996064986,1996064986
.long	1996064986,1996064986,1996064986,1996064986
.long	2554220882,2554220882,2554220882,2554220882
.long	2554220882,2554220882,2554220882,2554220882
.long	2821834349,2821834349,2821834349,2821834349
.long	2821834349,2821834349,2821834349,2821834349
.long	2952996808,2952996808,2952996808,2952996808
.long	2952996808,2952996808,2952996808,2952996808
.long	3210313671,3210313671,3210313671,3210313671
.long	3210313671,3210313671,3210313671,3210313671
.long	3336571891,3336571891,3336571891,3336571891
.long	3336571891,3336571891,3336571891,3336571891
.long	3584528711,3584528711,3584528711,3584528711
.long	3584528711,3584528711,3584528711,3584528711
.long	113926993,113926993,113926993,113926993
.long	113926993,113926993,113926993,113926993
.long	338241895,338241895,338241895,338241895
.long	338241895,338241895,338241895,338241895
.long	666307205,666307205,666307205,666307205
.long	666307205,666307205,666307205,666307205
.long	773529912,773529912,773529912,773529912
.long	773529912,773529912,773529912,773529912
.long	1294757372,1294757372,1294757372,1294757372
.long	1294757372,1294757372,1294757372,1294757372
.long	1396182291,1396182291,1396182291,1396182291
.long	1396182291,1396182291,1396182291,1396182291
.long	1695183700,1695183700,1695183700,1695183700
.long	1695183700,1695183700,1695183700,1695183700
.long	1986661051,1986661051,1986661051,1986661051
.long	1986661051,1986661051,1986661051,1986661051
.long	2177026350,2177026350,2177026350,2177026350
.long	2177026350,2177026350,2177026350,2177026350
.long	2456956037,2456956037,2456956037,2456956037
.long	2456956037,2456956037,2456956037,2456956037
.long	2730485921,2730485921,2730485921,2730485921
.long	2730485921,2730485921,2730485921,2730485921
.long	2820302411,2820302411,2820302411,2820302411
.long	2820302411,2820302411,2820302411,2820302411
.long	3259730800,3259730800,3259730800,3259730800
.long	3259730800,3259730800,3259730800,3259730800
.long	3345764771,3345764771,3345764771,3345764771
.long	3345764771,3345764771,3345764771,3345764771
.long	3516065817,3516065817,3516065817,3516065817
.long	3516065817,3516065817,3516065817,3516065817
.long	3600352804,3600352804,3600352804,3600352804
.long	3600352804,3600352804,3600352804,3600352804
.long	4094571909,4094571909,4094571909,4094571909
.long	4094571909,4094571909,4094571909,4094571909
.long	275423344,275423344,275423344,275423344
.long	275423344,275423344,275423344,275423344
.long	430227734,430227734,430227734,430227734
.long	430227734,430227734,430227734,430227734
.long	506948616,506948616,506948616,506948616
.long	506948616,506948616,506948616,506948616
.long	659060556,659060556,659060556,659060556
.long	659060556,659060556,659060556,659060556
.long	883997877,883997877,883997877,883997877
.long	883997877,883997877,883997877,883997877
.long	958139571,958139571,958139571,958139571
.long	958139571,958139571,958139571,958139571
.long	1322822218,1322822218,1322822218,1322822218
.long	1322822218,1322822218,1322822218,1322822218
.long	1537002063,1537002063,1537002063,1537002063
.long	1537002063,1537002063,1537002063,1537002063
.long	1747873779,1747873779,1747873779,1747873779
.long	1747873779,1747873779,1747873779,1747873779
.long	1955562222,1955562222,1955562222,1955562222
.long	1955562222,1955562222,1955562222,1955562222
.long	2024104815,2024104815,2024104815,2024104815
.long	2024104815,2024104815,2024104815,2024104815
.long	2227730452,2227730452,2227730452,2227730452
.long	2227730452,2227730452,2227730452,2227730452
.long	2361852424,2361852424,2361852424,2361852424
.long	2361852424,2361852424,2361852424,2361852424
.long	2428436474,2428436474,2428436474,2428436474
.long	2428436474,2428436474,2428436474,2428436474
.long	2756734187,2756734187,2756734187,2756734187
.long	2756734187,2756734187,2756734187,2756734187
.long	3204031479,3204031479,3204031479,3204031479
.long	3204031479,3204031479,3204031479,3204031479
.long	3329325298,3329325298,3329325298,3329325298
.long	3329325298,3329325298,3329325298,3329325298
.Lpbswap:
.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	
.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	

.section .note.GNU-stack,"",%progbits
