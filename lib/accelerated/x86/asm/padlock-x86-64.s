# Copyright (c) 2011, Andy Polyakov by <appro@openssl.org>
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

.text	
.globl	padlock_capability
.type	padlock_capability,@function
.align	16
padlock_capability:
	movq	%rbx,%r8
	xorl	%eax,%eax
	cpuid
	xorl	%eax,%eax
	cmpl	$1953391939,%ebx
	jne	.Lnoluck
	cmpl	$1215460705,%edx
	jne	.Lnoluck
	cmpl	$1936487777,%ecx
	jne	.Lnoluck
	movl	$3221225472,%eax
	cpuid
	movl	%eax,%edx
	xorl	%eax,%eax
	cmpl	$3221225473,%edx
	jb	.Lnoluck
	movl	$3221225473,%eax
	cpuid
	movl	%edx,%eax
	andl	$4294967279,%eax
	orl	$16,%eax
.Lnoluck:
	movq	%r8,%rbx
	.byte	0xf3,0xc3
.size	padlock_capability,.-padlock_capability

.globl	padlock_key_bswap
.type	padlock_key_bswap,@function
.align	16
padlock_key_bswap:
	movl	240(%rdi),%edx
.Lbswap_loop:
	movl	(%rdi),%eax
	bswapl	%eax
	movl	%eax,(%rdi)
	leaq	4(%rdi),%rdi
	subl	$1,%edx
	jnz	.Lbswap_loop
	.byte	0xf3,0xc3
.size	padlock_key_bswap,.-padlock_key_bswap

.globl	padlock_verify_context
.type	padlock_verify_context,@function
.align	16
padlock_verify_context:
	movq	%rdi,%rdx
	pushf
	leaq	.Lpadlock_saved_context(%rip),%rax
	call	_padlock_verify_ctx
	leaq	8(%rsp),%rsp
	.byte	0xf3,0xc3
.size	padlock_verify_context,.-padlock_verify_context

.type	_padlock_verify_ctx,@function
.align	16
_padlock_verify_ctx:
	movq	8(%rsp),%r8
	btq	$30,%r8
	jnc	.Lverified
	cmpq	(%rax),%rdx
	je	.Lverified
	pushf
	popf
.Lverified:
	movq	%rdx,(%rax)
	.byte	0xf3,0xc3
.size	_padlock_verify_ctx,.-_padlock_verify_ctx

.globl	padlock_reload_key
.type	padlock_reload_key,@function
.align	16
padlock_reload_key:
	pushf
	popf
	.byte	0xf3,0xc3
.size	padlock_reload_key,.-padlock_reload_key

.globl	padlock_aes_block
.type	padlock_aes_block,@function
.align	16
padlock_aes_block:
	movq	%rbx,%r8
	movq	$1,%rcx
	leaq	32(%rdx),%rbx
	leaq	16(%rdx),%rdx
.byte	0xf3,0x0f,0xa7,0xc8	
	movq	%r8,%rbx
	.byte	0xf3,0xc3
.size	padlock_aes_block,.-padlock_aes_block

.globl	padlock_xstore
.type	padlock_xstore,@function
.align	16
padlock_xstore:
	movl	%esi,%edx
.byte	0x0f,0xa7,0xc0		
	.byte	0xf3,0xc3
.size	padlock_xstore,.-padlock_xstore

.globl	padlock_sha1_oneshot
.type	padlock_sha1_oneshot,@function
.align	16
padlock_sha1_oneshot:
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
.size	padlock_sha1_oneshot,.-padlock_sha1_oneshot

.globl	padlock_sha1_blocks
.type	padlock_sha1_blocks,@function
.align	16
padlock_sha1_blocks:
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
.size	padlock_sha1_blocks,.-padlock_sha1_blocks

.globl	padlock_sha256_oneshot
.type	padlock_sha256_oneshot,@function
.align	16
padlock_sha256_oneshot:
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
.size	padlock_sha256_oneshot,.-padlock_sha256_oneshot

.globl	padlock_sha256_blocks
.type	padlock_sha256_blocks,@function
.align	16
padlock_sha256_blocks:
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
.size	padlock_sha256_blocks,.-padlock_sha256_blocks

.globl	padlock_sha512_blocks
.type	padlock_sha512_blocks,@function
.align	16
padlock_sha512_blocks:
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
.size	padlock_sha512_blocks,.-padlock_sha512_blocks
.globl	padlock_ecb_encrypt
.type	padlock_ecb_encrypt,@function
.align	16
padlock_ecb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	.Lecb_abort
	testq	$15,%rcx
	jnz	.Lecb_abort
	leaq	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpq	$128,%rcx
	jbe	.Lecb_short
	testl	$32,(%rdx)
	jnz	.Lecb_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	.Lecb_aligned
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
	jmp	.Lecb_loop
.align	16
.Lecb_loop:
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
	jz	.Lecb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
.Lecb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,200	
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	.Lecb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
.Lecb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	.Lecb_loop

	cmpq	%rsp,%rbp
	je	.Lecb_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
.Lecb_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	.Lecb_bzero

.Lecb_done:
	leaq	(%rbp),%rsp
	jmp	.Lecb_exit
.align	16
.Lecb_short:
	movq	%rsp,%rbp
	subq	%rcx,%rsp
	xorq	%rbx,%rbx
.Lecb_short_copy:
	movups	(%rsi,%rbx,1),%xmm0
	leaq	16(%rbx),%rbx
	cmpq	%rbx,%rcx
	movaps	%xmm0,-16(%rsp,%rbx,1)
	ja	.Lecb_short_copy
	movq	%rsp,%rsi
	movq	%rcx,%rbx
	jmp	.Lecb_loop
.align	16
.Lecb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,200	
.Lecb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
.Lecb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3
.size	padlock_ecb_encrypt,.-padlock_ecb_encrypt
.globl	padlock_cbc_encrypt
.type	padlock_cbc_encrypt,@function
.align	16
padlock_cbc_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	.Lcbc_abort
	testq	$15,%rcx
	jnz	.Lcbc_abort
	leaq	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpq	$64,%rcx
	jbe	.Lcbc_short
	testl	$32,(%rdx)
	jnz	.Lcbc_aligned
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	.Lcbc_aligned
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
	jmp	.Lcbc_loop
.align	16
.Lcbc_loop:
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
	jz	.Lcbc_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
.Lcbc_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,208	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	.Lcbc_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
.Lcbc_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	.Lcbc_loop

	cmpq	%rsp,%rbp
	je	.Lcbc_done

	pxor	%xmm0,%xmm0
	leaq	(%rsp),%rax
.Lcbc_bzero:
	movaps	%xmm0,(%rax)
	leaq	16(%rax),%rax
	cmpq	%rax,%rbp
	ja	.Lcbc_bzero

.Lcbc_done:
	leaq	(%rbp),%rsp
	jmp	.Lcbc_exit
.align	16
.Lcbc_short:
	movq	%rsp,%rbp
	subq	%rcx,%rsp
	xorq	%rbx,%rbx
.Lcbc_short_copy:
	movups	(%rsi,%rbx,1),%xmm0
	leaq	16(%rbx),%rbx
	cmpq	%rbx,%rcx
	movaps	%xmm0,-16(%rsp,%rbx,1)
	ja	.Lcbc_short_copy
	movq	%rsp,%rsi
	movq	%rcx,%rbx
	jmp	.Lcbc_loop
.align	16
.Lcbc_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,208	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
.Lcbc_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
.Lcbc_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3
.size	padlock_cbc_encrypt,.-padlock_cbc_encrypt
.byte	86,73,65,32,80,97,100,108,111,99,107,32,120,56,54,95,54,52,32,109,111,100,117,108,101,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	16
.data	
.align	8
.Lpadlock_saved_context:
.quad	0

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
