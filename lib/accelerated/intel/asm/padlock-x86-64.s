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
	xorq	%rax,%rax
	movq	%rdx,%rcx
.byte	0xf3,0x0f,0xa6,0xc8	
	.byte	0xf3,0xc3
.size	padlock_sha1_oneshot,.-padlock_sha1_oneshot

.globl	padlock_sha1
.type	padlock_sha1,@function
.align	16
padlock_sha1:
	movq	$-1,%rax
	movq	%rdx,%rcx
.byte	0xf3,0x0f,0xa6,0xc8	
	.byte	0xf3,0xc3
.size	padlock_sha1,.-padlock_sha1

.globl	padlock_sha256_oneshot
.type	padlock_sha256_oneshot,@function
.align	16
padlock_sha256_oneshot:
	xorq	%rax,%rax
	movq	%rdx,%rcx
.byte	0xf3,0x0f,0xa6,0xd0	
	.byte	0xf3,0xc3
.size	padlock_sha256_oneshot,.-padlock_sha256_oneshot

.globl	padlock_sha256
.type	padlock_sha256,@function
.align	16
padlock_sha256:
	movq	$-1,%rax
	movq	%rdx,%rcx
.byte	0xf3,0x0f,0xa6,0xd0	
	.byte	0xf3,0xc3
.size	padlock_sha256,.-padlock_sha256
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
	testl	$32,(%rdx)
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

	testq	$15,%rdi
	jz	.Lecb_done

	movq	%rbp,%rcx
	movq	%rsp,%rdi
	subq	%rsp,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
.byte	0xf3,0x48,0xab		
.Lecb_done:
	leaq	(%rbp),%rsp
	jmp	.Lecb_exit

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
	testl	$32,(%rdx)
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

	testq	$15,%rdi
	jz	.Lcbc_done

	movq	%rbp,%rcx
	movq	%rsp,%rdi
	subq	%rsp,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
.byte	0xf3,0x48,0xab		
.Lcbc_done:
	leaq	(%rbp),%rsp
	jmp	.Lcbc_exit

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
.globl	padlock_cfb_encrypt
.type	padlock_cfb_encrypt,@function
.align	16
padlock_cfb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	.Lcfb_abort
	testq	$15,%rcx
	jnz	.Lcfb_abort
	leaq	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	testl	$32,(%rdx)
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	.Lcfb_aligned
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
	jmp	.Lcfb_loop
.align	16
.Lcfb_loop:
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	.Lcfb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
.Lcfb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,224	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	.Lcfb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
.Lcfb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	.Lcfb_loop

	testq	$15,%rdi
	jz	.Lcfb_done

	movq	%rbp,%rcx
	movq	%rsp,%rdi
	subq	%rsp,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
.byte	0xf3,0x48,0xab		
.Lcfb_done:
	leaq	(%rbp),%rsp
	jmp	.Lcfb_exit

.align	16
.Lcfb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,224	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
.Lcfb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
.Lcfb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3
.size	padlock_cfb_encrypt,.-padlock_cfb_encrypt
.globl	padlock_ofb_encrypt
.type	padlock_ofb_encrypt,@function
.align	16
padlock_ofb_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	.Lofb_abort
	testq	$15,%rcx
	jnz	.Lofb_abort
	leaq	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	testl	$32,(%rdx)
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	.Lofb_aligned
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
	jmp	.Lofb_loop
.align	16
.Lofb_loop:
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	.Lofb_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
.Lofb_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,232	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	.Lofb_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
.Lofb_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	.Lofb_loop

	testq	$15,%rdi
	jz	.Lofb_done

	movq	%rbp,%rcx
	movq	%rsp,%rdi
	subq	%rsp,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
.byte	0xf3,0x48,0xab		
.Lofb_done:
	leaq	(%rbp),%rsp
	jmp	.Lofb_exit

.align	16
.Lofb_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,232	
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16(%rdx)
.Lofb_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
.Lofb_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3
.size	padlock_ofb_encrypt,.-padlock_ofb_encrypt
.globl	padlock_ctr16_encrypt
.type	padlock_ctr16_encrypt,@function
.align	16
padlock_ctr16_encrypt:
	pushq	%rbp
	pushq	%rbx

	xorl	%eax,%eax
	testq	$15,%rdx
	jnz	.Lctr16_abort
	testq	$15,%rcx
	jnz	.Lctr16_abort
	leaq	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	leaq	16(%rdx),%rdx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	testl	$32,(%rdx)
	testq	$15,%rdi
	setz	%al
	testq	$15,%rsi
	setz	%bl
	testl	%ebx,%eax
	jnz	.Lctr16_aligned
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
	jmp	.Lctr16_loop
.align	16
.Lctr16_loop:
	movq	%rdi,%r8
	movq	%rsi,%r9
	movq	%rcx,%r10
	movq	%rbx,%rcx
	movq	%rbx,%r11
	testq	$15,%rdi
	cmovnzq	%rsp,%rdi
	testq	$15,%rsi
	jz	.Lctr16_inp_aligned
	shrq	$3,%rcx
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
	movq	%rbx,%rcx
	movq	%rdi,%rsi
.Lctr16_inp_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,216	
	movq	%r8,%rdi
	movq	%r11,%rbx
	testq	$15,%rdi
	jz	.Lctr16_out_aligned
	movq	%rbx,%rcx
	shrq	$3,%rcx
	leaq	(%rsp),%rsi
.byte	0xf3,0x48,0xa5		
	subq	%rbx,%rdi
.Lctr16_out_aligned:
	movq	%r9,%rsi
	movq	%r10,%rcx
	addq	%rbx,%rdi
	addq	%rbx,%rsi
	subq	%rbx,%rcx
	movq	$512,%rbx
	jnz	.Lctr16_loop

	testq	$15,%rdi
	jz	.Lctr16_done

	movq	%rbp,%rcx
	movq	%rsp,%rdi
	subq	%rsp,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
.byte	0xf3,0x48,0xab		
.Lctr16_done:
	leaq	(%rbp),%rsp
	jmp	.Lctr16_exit

.align	16
.Lctr16_aligned:
	leaq	-16(%rdx),%rax
	leaq	16(%rdx),%rbx
	shrq	$4,%rcx
.byte	0xf3,0x0f,0xa7,216	
.Lctr16_exit:
	movl	$1,%eax
	leaq	8(%rsp),%rsp
.Lctr16_abort:
	popq	%rbx
	popq	%rbp
	.byte	0xf3,0xc3
.size	padlock_ctr16_encrypt,.-padlock_ctr16_encrypt
.byte	86,73,65,32,80,97,100,108,111,99,107,32,120,56,54,95,54,52,32,109,111,100,117,108,101,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	16
.data	
.align	8
.Lpadlock_saved_context:
.quad	0
