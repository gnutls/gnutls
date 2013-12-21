# Copyright (c) 2011-2013, Andy Polyakov <appro@openssl.org>
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
.globl	_padlock_capability

.p2align	4
_padlock_capability:
	movq	%rbx,%r8
	xorl	%eax,%eax
	cpuid
	xorl	%eax,%eax
	cmpl	$1953391939,%ebx
	jne	L$noluck
	cmpl	$1215460705,%edx
	jne	L$noluck
	cmpl	$1936487777,%ecx
	jne	L$noluck
	movl	$3221225472,%eax
	cpuid
	movl	%eax,%edx
	xorl	%eax,%eax
	cmpl	$3221225473,%edx
	jb	L$noluck
	movl	$3221225473,%eax
	cpuid
	movl	%edx,%eax
	andl	$4294967279,%eax
	orl	$16,%eax
L$noluck:
	movq	%r8,%rbx
	.byte	0xf3,0xc3


.globl	_padlock_key_bswap

.p2align	4
_padlock_key_bswap:
	movl	240(%rdi),%edx
L$bswap_loop:
	movl	(%rdi),%eax
	bswapl	%eax
	movl	%eax,(%rdi)
	leaq	4(%rdi),%rdi
	subl	$1,%edx
	jnz	L$bswap_loop
	.byte	0xf3,0xc3


.globl	_padlock_verify_context

.p2align	4
_padlock_verify_context:
	movq	%rdi,%rdx
	pushf
	leaq	L$padlock_saved_context(%rip),%rax
	call	_padlock_verify_ctx
	leaq	8(%rsp),%rsp
	.byte	0xf3,0xc3



.p2align	4
_padlock_verify_ctx:
	movq	8(%rsp),%r8
	btq	$30,%r8
	jnc	L$verified
	cmpq	(%rax),%rdx
	je	L$verified
	pushf
	popf
L$verified:
	movq	%rdx,(%rax)
	.byte	0xf3,0xc3


.globl	_padlock_reload_key

.p2align	4
_padlock_reload_key:
	pushf
	popf
	.byte	0xf3,0xc3


.globl	_padlock_aes_block

.p2align	4
_padlock_aes_block:
	movq	%rbx,%r8
	movq	$1,%rcx
	leaq	32(%rdx),%rbx
	leaq	16(%rdx),%rdx
.byte	0xf3,0x0f,0xa7,0xc8	
	movq	%r8,%rbx
	.byte	0xf3,0xc3


.globl	_padlock_xstore

.p2align	4
_padlock_xstore:
	movl	%esi,%edx
.byte	0x0f,0xa7,0xc0		
	.byte	0xf3,0xc3


.globl	_padlock_sha1_oneshot

.p2align	4
_padlock_sha1_oneshot:
	movq	%rdx,%rcx
	movq	%rdi,%rdx
	movups	(%rdi),%xmm0
	subq	$128+8,%rsp
	movl	16(%rdi),%eax
	movaps	%xmm0,(%rsp)
	movq	%rsp,%rdi
	movl	%eax,16(%rsp)
	xorq	%rax,%rax
.byte	0xf3,0x0f,0xa6,0xc8	
	movaps	(%rsp),%xmm0
	movl	16(%rsp),%eax
	addq	$128+8,%rsp
	movups	%xmm0,(%rdx)
	movl	%eax,16(%rdx)
	.byte	0xf3,0xc3


.globl	_padlock_sha1_blocks

.p2align	4
_padlock_sha1_blocks:
	movq	%rdx,%rcx
	movq	%rdi,%rdx
	movups	(%rdi),%xmm0
	subq	$128+8,%rsp
	movl	16(%rdi),%eax
	movaps	%xmm0,(%rsp)
	movq	%rsp,%rdi
	movl	%eax,16(%rsp)
	movq	$-1,%rax
.byte	0xf3,0x0f,0xa6,0xc8	
	movaps	(%rsp),%xmm0
	movl	16(%rsp),%eax
	addq	$128+8,%rsp
	movups	%xmm0,(%rdx)
	movl	%eax,16(%rdx)
	.byte	0xf3,0xc3


.globl	_padlock_sha256_oneshot

.p2align	4
_padlock_sha256_oneshot:
	movq	%rdx,%rcx
	movq	%rdi,%rdx
	movups	(%rdi),%xmm0
	subq	$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	movq	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	xorq	%rax,%rax
.byte	0xf3,0x0f,0xa6,0xd0	
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	addq	$128+8,%rsp
	movups	%xmm0,(%rdx)
	movups	%xmm1,16(%rdx)
	.byte	0xf3,0xc3


.globl	_padlock_sha256_blocks

.p2align	4
_padlock_sha256_blocks:
	movq	%rdx,%rcx
	movq	%rdi,%rdx
	movups	(%rdi),%xmm0
	subq	$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	movq	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	movq	$-1,%rax
.byte	0xf3,0x0f,0xa6,0xd0	
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	addq	$128+8,%rsp
	movups	%xmm0,(%rdx)
	movups	%xmm1,16(%rdx)
	.byte	0xf3,0xc3


.globl	_padlock_sha512_blocks

.p2align	4
_padlock_sha512_blocks:
	movq	%rdx,%rcx
	movq	%rdi,%rdx
	movups	(%rdi),%xmm0
	subq	$128+8,%rsp
	movups	16(%rdi),%xmm1
	movups	32(%rdi),%xmm2
	movups	48(%rdi),%xmm3
	movaps	%xmm0,(%rsp)
	movq	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	movaps	%xmm2,32(%rsp)
	movaps	%xmm3,48(%rsp)
.byte	0xf3,0x0f,0xa6,0xe0	
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	movaps	32(%rsp),%xmm2
	movaps	48(%rsp),%xmm3
	addq	$128+8,%rsp
	movups	%xmm0,(%rdx)
	movups	%xmm1,16(%rdx)
	movups	%xmm2,32(%rdx)
	movups	%xmm3,48(%rdx)
	.byte	0xf3,0xc3

.globl	_padlock_ecb_encrypt

.p2align	4
_padlock_ecb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	L$ecb_abort
	testq	$15,%rcx
	jnz	L$ecb_abort
	leaq	L$padlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpq	$128,%rcx
	jbe	L$ecb_short
	testl	$32,(%rdx)
	jnz	L$ecb_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	L$ecb_aligned
	negq	%rax
	movq	$512,%rbx
	notq	%rax
	leaq	(%rsp),%rbp
	cmpq	%rbx,%rcx
	cmovcq	%rcx,%rbx
	andq	%rbx,%rax
	movq	%rcx,%rbx
	negq	%rax
	andq	$512-1,%rbx
	leaq	(%rax,%rbp,1),%rsp
	jmp	L$ecb_loop
.p2align	4
L$ecb_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	L$ecb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
L$ecb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,200	
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	L$ecb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
L$ecb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	L$ecb_loop

	cmpq	%rsp,%rbp
	je	L$ecb_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
L$ecb_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	L$ecb_bzero

L$ecb_done:
	leaq	(%rbp),%rsp
	jmp	L$ecb_exit
.p2align	4
L$ecb_short:
	movq	%rsp,%rbp
	subq	%rcx,%rsp
	xorq	%rbx,%rbx
L$ecb_short_copy:
	movups	(%rsi,%rbx,1),%xmm0
	leaq	16(%rbx),%rbx
	cmpq	%rbx,%rcx
	movaps	%xmm0,-16(%rsp,%rbx,1)
	ja	L$ecb_short_copy
	movq	%rsp,%rsi
	movq	%rcx,%rbx
	jmp	L$ecb_loop
.p2align	4
L$ecb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,200	
L$ecb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
L$ecb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3

.globl	_padlock_cbc_encrypt

.p2align	4
_padlock_cbc_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	L$cbc_abort
	testq	$15,%rcx
	jnz	L$cbc_abort
	leaq	L$padlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpq	$64,%rcx
	jbe	L$cbc_short
	testl	$32,(%rdx)
	jnz	L$cbc_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	L$cbc_aligned
	negq	%rax
	movq	$512,%rbx
	notq	%rax
	leaq	(%rsp),%rbp
	cmpq	%rbx,%rcx
	cmovcq	%rcx,%rbx
	andq	%rbx,%rax
	movq	%rcx,%rbx
	negq	%rax
	andq	$512-1,%rbx
	leaq	(%rax,%rbp,1),%rsp
	jmp	L$cbc_loop
.p2align	4
L$cbc_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	L$cbc_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
L$cbc_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,208	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	L$cbc_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
L$cbc_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	L$cbc_loop

	cmpq	%rsp,%rbp
	je	L$cbc_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
L$cbc_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	L$cbc_bzero

L$cbc_done:
	leaq	(%rbp),%rsp
	jmp	L$cbc_exit
.p2align	4
L$cbc_short:
	movq	%rsp,%rbp
	subq	%rcx,%rsp
	xorq	%rbx,%rbx
L$cbc_short_copy:
	movups	(%rsi,%rbx,1),%xmm0
	leaq	16(%rbx),%rbx
	cmpq	%rbx,%rcx
	movaps	%xmm0,-16(%rsp,%rbx,1)
	ja	L$cbc_short_copy
	movq	%rsp,%rsi
	movq	%rcx,%rbx
	jmp	L$cbc_loop
.p2align	4
L$cbc_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,208	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
L$cbc_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
L$cbc_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3

.globl	_padlock_cfb_encrypt

.p2align	4
_padlock_cfb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	L$cfb_abort
	testq	$15,%rcx
	jnz	L$cfb_abort
	leaq	L$padlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	testl	$32,(%rdx)
	jnz	L$cfb_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	L$cfb_aligned
	negq	%rax
	movq	$512,%rbx
	notq	%rax
	leaq	(%rsp),%rbp
	cmpq	%rbx,%rcx
	cmovcq	%rcx,%rbx
	andq	%rbx,%rax
	movq	%rcx,%rbx
	negq	%rax
	andq	$512-1,%rbx
	leaq	(%rax,%rbp,1),%rsp
	jmp	L$cfb_loop
.p2align	4
L$cfb_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	L$cfb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
L$cfb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,224	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	L$cfb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
L$cfb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	L$cfb_loop

	cmpq	%rsp,%rbp
	je	L$cfb_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
L$cfb_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	L$cfb_bzero

L$cfb_done:
	leaq	(%rbp),%rsp
	jmp	L$cfb_exit
.p2align	4
L$cfb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,224	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
L$cfb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
L$cfb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3

.globl	_padlock_ofb_encrypt

.p2align	4
_padlock_ofb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	L$ofb_abort
	testq	$15,%rcx
	jnz	L$ofb_abort
	leaq	L$padlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	testl	$32,(%rdx)
	jnz	L$ofb_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	L$ofb_aligned
	negq	%rax
	movq	$512,%rbx
	notq	%rax
	leaq	(%rsp),%rbp
	cmpq	%rbx,%rcx
	cmovcq	%rcx,%rbx
	andq	%rbx,%rax
	movq	%rcx,%rbx
	negq	%rax
	andq	$512-1,%rbx
	leaq	(%rax,%rbp,1),%rsp
	jmp	L$ofb_loop
.p2align	4
L$ofb_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	L$ofb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
L$ofb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,232	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	L$ofb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
L$ofb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	L$ofb_loop

	cmpq	%rsp,%rbp
	je	L$ofb_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
L$ofb_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	L$ofb_bzero

L$ofb_done:
	leaq	(%rbp),%rsp
	jmp	L$ofb_exit
.p2align	4
L$ofb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,232	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
L$ofb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
L$ofb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3

.globl	_padlock_ctr32_encrypt

.p2align	4
_padlock_ctr32_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	L$ctr32_abort
	testq	$15,%rcx
	jnz	L$ctr32_abort
	leaq	L$padlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpq	$64,%rcx
	jbe	L$ctr32_short
	testl	$32,(%rdx)
	jnz	L$ctr32_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	L$ctr32_aligned
	negq	%rax
	movq	$512,%rbx
	notq	%rax
	leaq	(%rsp),%rbp
	cmpq	%rbx,%rcx
	cmovcq	%rcx,%rbx
	andq	%rbx,%rax
	movq	%rcx,%rbx
	negq	%rax
	andq	$512-1,%rbx
	leaq	(%rax,%rbp,1),%rsp
L$ctr32_reenter:
	movl	-4(%rdx),%eax
	bswapl	%eax
	negl	%eax
	andl	$31,%eax
	jz	L$ctr32_loop
	shll	$4,%eax
	cmpq	%rax,%rcx
	cmovaq	%rax,%rbx
	jmp	L$ctr32_loop
.p2align	4
L$ctr32_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	L$ctr32_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
L$ctr32_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,216	
	movl	-4(%rdx),%eax
	testl	$4294901760,%eax
	jnz	L$ctr32_no_corr
	bswapl	%eax
	addl	$65536,%eax
	bswapl	%eax
	movl	%eax,-4(%rdx)
L$ctr32_no_corr:
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	L$ctr32_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
L$ctr32_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	L$ctr32_loop

	cmpq	%rsp,%rbp
	je	L$ctr32_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
L$ctr32_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	L$ctr32_bzero

L$ctr32_done:
	leaq	(%rbp),%rsp
	jmp	L$ctr32_exit
.p2align	4
L$ctr32_short:
	movq	%rsp,%rbp
	subq	%rcx,%rsp
	xorq	%rbx,%rbx
L$ctr32_short_copy:
	movups	(%rsi,%rbx,1),%xmm0
	leaq	16(%rbx),%rbx
	cmpq	%rbx,%rcx
	movaps	%xmm0,-16(%rsp,%rbx,1)
	ja	L$ctr32_short_copy
	movq	%rsp,%rsi
	movq	%rcx,%rbx
	jmp	L$ctr32_reenter
.p2align	4
L$ctr32_aligned:
	movl	-4(%rdx),%eax
	movq	$1048576,%rbx
	bswapl	%eax
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	negl	%eax
	andl	$65535,%eax
	jz	L$ctr32_aligned_loop
	shll	$4,%eax
	cmpq	%rax,%rcx
	cmovaq	%rax,%rbx
	jmp	L$ctr32_aligned_loop
.p2align	4
L$ctr32_aligned_loop:
	cmpq	%rcx,%rbx
	cmovaq	%rcx,%rbx
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,216	
	movl	-4(%rdx),%eax
	bswapl	%eax
	addl	$65536,%eax
	bswapl	%eax
	movl	%eax,-4(%rdx)

	movq	%r11,%rbx
	movq	%r10,%rcx
	subq	%rbx,%rcx
	movq	$1048576,%rbx
	jnz	L$ctr32_aligned_loop
L$ctr32_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
L$ctr32_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3

.byte	86,73,65,32,80,97,100,108,111,99,107,32,120,56,54,95,54,52,32,109,111,100,117,108,101,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.p2align	4
.data	
.p2align	3
L$padlock_saved_context:
.quad	0

