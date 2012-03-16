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
.file	"devel/perlasm/e_padlock-x86.s"
.text
.globl	padlock_capability
.type	padlock_capability,@function
.align	16
padlock_capability:
.L_padlock_capability_begin:
	pushl	%ebx
	pushfl
	popl	%eax
	movl	%eax,%ecx
	xorl	$2097152,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	xorl	%eax,%ecx
	xorl	%eax,%eax
	btl	$21,%ecx
	jnc	.L000noluck
	.byte	0x0f,0xa2
	xorl	%eax,%eax
	cmpl	$0x746e6543,%ebx
	jne	.L000noluck
	cmpl	$0x48727561,%edx
	jne	.L000noluck
	cmpl	$0x736c7561,%ecx
	jne	.L000noluck
	movl	$3221225472,%eax
	.byte	0x0f,0xa2
	movl	%eax,%edx
	xorl	%eax,%eax
	cmpl	$3221225473,%edx
	jb	.L000noluck
	movl	$1,%eax
	.byte	0x0f,0xa2
	orl	$15,%eax
	xorl	%ebx,%ebx
	andl	$4095,%eax
	cmpl	$1791,%eax
	sete	%bl
	movl	$3221225473,%eax
	pushl	%ebx
	.byte	0x0f,0xa2
	popl	%ebx
	movl	%edx,%eax
	shll	$4,%ebx
	andl	$4294967279,%eax
	orl	%ebx,%eax
.L000noluck:
	popl	%ebx
	ret
.size	padlock_capability,.-.L_padlock_capability_begin
.globl	padlock_key_bswap
.type	padlock_key_bswap,@function
.align	16
padlock_key_bswap:
.L_padlock_key_bswap_begin:
	movl	4(%esp),%edx
	movl	240(%edx),%ecx
.L001bswap_loop:
	movl	(%edx),%eax
	bswap	%eax
	movl	%eax,(%edx)
	leal	4(%edx),%edx
	subl	$1,%ecx
	jnz	.L001bswap_loop
	ret
.size	padlock_key_bswap,.-.L_padlock_key_bswap_begin
.globl	padlock_verify_context
.type	padlock_verify_context,@function
.align	16
padlock_verify_context:
.L_padlock_verify_context_begin:
	movl	4(%esp),%edx
	leal	.Lpadlock_saved_context-.L002verify_pic_point,%eax
	pushfl
	call	_padlock_verify_ctx
.L002verify_pic_point:
	leal	4(%esp),%esp
	ret
.size	padlock_verify_context,.-.L_padlock_verify_context_begin
.type	_padlock_verify_ctx,@function
.align	16
_padlock_verify_ctx:
	addl	(%esp),%eax
	btl	$30,4(%esp)
	jnc	.L003verified
	cmpl	(%eax),%edx
	je	.L003verified
	pushfl
	popfl
.L003verified:
	movl	%edx,(%eax)
	ret
.size	_padlock_verify_ctx,.-_padlock_verify_ctx
.globl	padlock_reload_key
.type	padlock_reload_key,@function
.align	16
padlock_reload_key:
.L_padlock_reload_key_begin:
	pushfl
	popfl
	ret
.size	padlock_reload_key,.-.L_padlock_reload_key_begin
.globl	padlock_aes_block
.type	padlock_aes_block,@function
.align	16
padlock_aes_block:
.L_padlock_aes_block_begin:
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	movl	16(%esp),%edi
	movl	20(%esp),%esi
	movl	24(%esp),%edx
	movl	$1,%ecx
	leal	32(%edx),%ebx
	leal	16(%edx),%edx
.byte	243,15,167,200
	popl	%ebx
	popl	%esi
	popl	%edi
	ret
.size	padlock_aes_block,.-.L_padlock_aes_block_begin
.globl	padlock_ecb_encrypt
.type	padlock_ecb_encrypt,@function
.align	16
padlock_ecb_encrypt:
.L_padlock_ecb_encrypt_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	20(%esp),%edi
	movl	24(%esp),%esi
	movl	28(%esp),%edx
	movl	32(%esp),%ecx
	testl	$15,%edx
	jnz	.L004ecb_abort
	testl	$15,%ecx
	jnz	.L004ecb_abort
	leal	.Lpadlock_saved_context-.L005ecb_pic_point,%eax
	pushfl
	cld
	call	_padlock_verify_ctx
.L005ecb_pic_point:
	leal	16(%edx),%edx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpl	$128,%ecx
	jbe	.L006ecb_short
	testl	$32,(%edx)
	jnz	.L007ecb_aligned
	testl	$15,%edi
	setz	%al
	testl	$15,%esi
	setz	%bl
	testl	%ebx,%eax
	jnz	.L007ecb_aligned
	negl	%eax
	movl	$512,%ebx
	notl	%eax
	leal	-24(%esp),%ebp
	cmpl	%ebx,%ecx
	cmovcl	%ecx,%ebx
	andl	%ebx,%eax
	movl	%ecx,%ebx
	negl	%eax
	andl	$511,%ebx
	leal	(%eax,%ebp,1),%esp
	andl	$-16,%esp
	jmp	.L008ecb_loop
.align	16
.L008ecb_loop:
	movl	%edi,(%ebp)
	movl	%esi,4(%ebp)
	movl	%ecx,8(%ebp)
	movl	%ebx,%ecx
	movl	%ebx,12(%ebp)
	testl	$15,%edi
	cmovnzl	%esp,%edi
	testl	$15,%esi
	jz	.L009ecb_inp_aligned
	shrl	$2,%ecx
.byte	243,165
	subl	%ebx,%edi
	movl	%ebx,%ecx
	movl	%edi,%esi
.L009ecb_inp_aligned:
	leal	-16(%edx),%eax
	leal	16(%edx),%ebx
	shrl	$4,%ecx
.byte	243,15,167,200
	movl	(%ebp),%edi
	movl	12(%ebp),%ebx
	testl	$15,%edi
	jz	.L010ecb_out_aligned
	movl	%ebx,%ecx
	shrl	$2,%ecx
	leal	(%esp),%esi
.byte	243,165
	subl	%ebx,%edi
.L010ecb_out_aligned:
	movl	4(%ebp),%esi
	movl	8(%ebp),%ecx
	addl	%ebx,%edi
	addl	%ebx,%esi
	subl	%ebx,%ecx
	movl	$512,%ebx
	jnz	.L008ecb_loop
	cmpl	%ebp,%esp
	je	.L011ecb_done
	pxor	%xmm0,%xmm0
	leal	(%esp),%eax
.L012ecb_bzero:
	movaps	%xmm0,(%eax)
	leal	16(%eax),%eax
	cmpl	%eax,%ebp
	ja	.L012ecb_bzero
.L011ecb_done:
	leal	24(%ebp),%esp
	jmp	.L013ecb_exit
.align	16
.L006ecb_short:
	xorl	%eax,%eax
	leal	-24(%esp),%ebp
	subl	%ecx,%eax
	leal	(%eax,%ebp,1),%esp
	andl	$-16,%esp
	xorl	%ebx,%ebx
.L014ecb_short_copy:
	movups	(%esi,%ebx,1),%xmm0
	leal	16(%ebx),%ebx
	cmpl	%ebx,%ecx
	movaps	%xmm0,-16(%esp,%ebx,1)
	ja	.L014ecb_short_copy
	movl	%esp,%esi
	movl	%ecx,%ebx
	jmp	.L008ecb_loop
.align	16
.L007ecb_aligned:
	leal	-16(%edx),%eax
	leal	16(%edx),%ebx
	shrl	$4,%ecx
.byte	243,15,167,200
.L013ecb_exit:
	movl	$1,%eax
	leal	4(%esp),%esp
.L004ecb_abort:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.size	padlock_ecb_encrypt,.-.L_padlock_ecb_encrypt_begin
.globl	padlock_cbc_encrypt
.type	padlock_cbc_encrypt,@function
.align	16
padlock_cbc_encrypt:
.L_padlock_cbc_encrypt_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	20(%esp),%edi
	movl	24(%esp),%esi
	movl	28(%esp),%edx
	movl	32(%esp),%ecx
	testl	$15,%edx
	jnz	.L015cbc_abort
	testl	$15,%ecx
	jnz	.L015cbc_abort
	leal	.Lpadlock_saved_context-.L016cbc_pic_point,%eax
	pushfl
	cld
	call	_padlock_verify_ctx
.L016cbc_pic_point:
	leal	16(%edx),%edx
	xorl	%eax,%eax
	xorl	%ebx,%ebx
	cmpl	$64,%ecx
	jbe	.L017cbc_short
	testl	$32,(%edx)
	jnz	.L018cbc_aligned
	testl	$15,%edi
	setz	%al
	testl	$15,%esi
	setz	%bl
	testl	%ebx,%eax
	jnz	.L018cbc_aligned
	negl	%eax
	movl	$512,%ebx
	notl	%eax
	leal	-24(%esp),%ebp
	cmpl	%ebx,%ecx
	cmovcl	%ecx,%ebx
	andl	%ebx,%eax
	movl	%ecx,%ebx
	negl	%eax
	andl	$511,%ebx
	leal	(%eax,%ebp,1),%esp
	andl	$-16,%esp
	jmp	.L019cbc_loop
.align	16
.L019cbc_loop:
	movl	%edi,(%ebp)
	movl	%esi,4(%ebp)
	movl	%ecx,8(%ebp)
	movl	%ebx,%ecx
	movl	%ebx,12(%ebp)
	testl	$15,%edi
	cmovnzl	%esp,%edi
	testl	$15,%esi
	jz	.L020cbc_inp_aligned
	shrl	$2,%ecx
.byte	243,165
	subl	%ebx,%edi
	movl	%ebx,%ecx
	movl	%edi,%esi
.L020cbc_inp_aligned:
	leal	-16(%edx),%eax
	leal	16(%edx),%ebx
	shrl	$4,%ecx
.byte	243,15,167,208
	movaps	(%eax),%xmm0
	movaps	%xmm0,-16(%edx)
	movl	(%ebp),%edi
	movl	12(%ebp),%ebx
	testl	$15,%edi
	jz	.L021cbc_out_aligned
	movl	%ebx,%ecx
	shrl	$2,%ecx
	leal	(%esp),%esi
.byte	243,165
	subl	%ebx,%edi
.L021cbc_out_aligned:
	movl	4(%ebp),%esi
	movl	8(%ebp),%ecx
	addl	%ebx,%edi
	addl	%ebx,%esi
	subl	%ebx,%ecx
	movl	$512,%ebx
	jnz	.L019cbc_loop
	cmpl	%ebp,%esp
	je	.L022cbc_done
	pxor	%xmm0,%xmm0
	leal	(%esp),%eax
.L023cbc_bzero:
	movaps	%xmm0,(%eax)
	leal	16(%eax),%eax
	cmpl	%eax,%ebp
	ja	.L023cbc_bzero
.L022cbc_done:
	leal	24(%ebp),%esp
	jmp	.L024cbc_exit
.align	16
.L017cbc_short:
	xorl	%eax,%eax
	leal	-24(%esp),%ebp
	subl	%ecx,%eax
	leal	(%eax,%ebp,1),%esp
	andl	$-16,%esp
	xorl	%ebx,%ebx
.L025cbc_short_copy:
	movups	(%esi,%ebx,1),%xmm0
	leal	16(%ebx),%ebx
	cmpl	%ebx,%ecx
	movaps	%xmm0,-16(%esp,%ebx,1)
	ja	.L025cbc_short_copy
	movl	%esp,%esi
	movl	%ecx,%ebx
	jmp	.L019cbc_loop
.align	16
.L018cbc_aligned:
	leal	-16(%edx),%eax
	leal	16(%edx),%ebx
	shrl	$4,%ecx
.byte	243,15,167,208
	movaps	(%eax),%xmm0
	movaps	%xmm0,-16(%edx)
.L024cbc_exit:
	movl	$1,%eax
	leal	4(%esp),%esp
.L015cbc_abort:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.size	padlock_cbc_encrypt,.-.L_padlock_cbc_encrypt_begin
.globl	padlock_xstore
.type	padlock_xstore,@function
.align	16
padlock_xstore:
.L_padlock_xstore_begin:
	pushl	%edi
	movl	8(%esp),%edi
	movl	12(%esp),%edx
.byte	15,167,192
	popl	%edi
	ret
.size	padlock_xstore,.-.L_padlock_xstore_begin
.type	_win32_segv_handler,@function
.align	16
_win32_segv_handler:
	movl	$1,%eax
	movl	4(%esp),%edx
	movl	12(%esp),%ecx
	cmpl	$3221225477,(%edx)
	jne	.L026ret
	addl	$4,184(%ecx)
	movl	$0,%eax
.L026ret:
	ret
.size	_win32_segv_handler,.-_win32_segv_handler
.globl	padlock_sha1_oneshot
.type	padlock_sha1_oneshot,@function
.align	16
padlock_sha1_oneshot:
.L_padlock_sha1_oneshot_begin:
	pushl	%edi
	pushl	%esi
	xorl	%eax,%eax
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	20(%esp),%ecx
	movl	%esp,%edx
	addl	$-128,%esp
	movups	(%edi),%xmm0
	andl	$-16,%esp
	movl	16(%edi),%eax
	movaps	%xmm0,(%esp)
	movl	%esp,%edi
	movl	%eax,16(%esp)
	xorl	%eax,%eax
.byte	243,15,166,200
	movaps	(%esp),%xmm0
	movl	16(%esp),%eax
	movl	%edx,%esp
	movl	12(%esp),%edi
	movups	%xmm0,(%edi)
	movl	%eax,16(%edi)
	popl	%esi
	popl	%edi
	ret
.size	padlock_sha1_oneshot,.-.L_padlock_sha1_oneshot_begin
.globl	padlock_sha1_blocks
.type	padlock_sha1_blocks,@function
.align	16
padlock_sha1_blocks:
.L_padlock_sha1_blocks_begin:
	pushl	%edi
	pushl	%esi
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	%esp,%edx
	movl	20(%esp),%ecx
	addl	$-128,%esp
	movups	(%edi),%xmm0
	andl	$-16,%esp
	movl	16(%edi),%eax
	movaps	%xmm0,(%esp)
	movl	%esp,%edi
	movl	%eax,16(%esp)
	movl	$-1,%eax
.byte	243,15,166,200
	movaps	(%esp),%xmm0
	movl	16(%esp),%eax
	movl	%edx,%esp
	movl	12(%esp),%edi
	movups	%xmm0,(%edi)
	movl	%eax,16(%edi)
	popl	%esi
	popl	%edi
	ret
.size	padlock_sha1_blocks,.-.L_padlock_sha1_blocks_begin
.globl	padlock_sha256_oneshot
.type	padlock_sha256_oneshot,@function
.align	16
padlock_sha256_oneshot:
.L_padlock_sha256_oneshot_begin:
	pushl	%edi
	pushl	%esi
	xorl	%eax,%eax
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	20(%esp),%ecx
	movl	%esp,%edx
	addl	$-128,%esp
	movups	(%edi),%xmm0
	andl	$-16,%esp
	movups	16(%edi),%xmm1
	movaps	%xmm0,(%esp)
	movl	%esp,%edi
	movaps	%xmm1,16(%esp)
	xorl	%eax,%eax
.byte	243,15,166,208
	movaps	(%esp),%xmm0
	movaps	16(%esp),%xmm1
	movl	%edx,%esp
	movl	12(%esp),%edi
	movups	%xmm0,(%edi)
	movups	%xmm1,16(%edi)
	popl	%esi
	popl	%edi
	ret
.size	padlock_sha256_oneshot,.-.L_padlock_sha256_oneshot_begin
.globl	padlock_sha256_blocks
.type	padlock_sha256_blocks,@function
.align	16
padlock_sha256_blocks:
.L_padlock_sha256_blocks_begin:
	pushl	%edi
	pushl	%esi
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	20(%esp),%ecx
	movl	%esp,%edx
	addl	$-128,%esp
	movups	(%edi),%xmm0
	andl	$-16,%esp
	movups	16(%edi),%xmm1
	movaps	%xmm0,(%esp)
	movl	%esp,%edi
	movaps	%xmm1,16(%esp)
	movl	$-1,%eax
.byte	243,15,166,208
	movaps	(%esp),%xmm0
	movaps	16(%esp),%xmm1
	movl	%edx,%esp
	movl	12(%esp),%edi
	movups	%xmm0,(%edi)
	movups	%xmm1,16(%edi)
	popl	%esi
	popl	%edi
	ret
.size	padlock_sha256_blocks,.-.L_padlock_sha256_blocks_begin
.globl	padlock_sha512_blocks
.type	padlock_sha512_blocks,@function
.align	16
padlock_sha512_blocks:
.L_padlock_sha512_blocks_begin:
	pushl	%edi
	pushl	%esi
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	20(%esp),%ecx
	movl	%esp,%edx
	addl	$-128,%esp
	movups	(%edi),%xmm0
	andl	$-16,%esp
	movups	16(%edi),%xmm1
	movups	32(%edi),%xmm2
	movups	48(%edi),%xmm3
	movaps	%xmm0,(%esp)
	movl	%esp,%edi
	movaps	%xmm1,16(%esp)
	movaps	%xmm2,32(%esp)
	movaps	%xmm3,48(%esp)
.byte	243,15,166,224
	movaps	(%esp),%xmm0
	movaps	16(%esp),%xmm1
	movaps	32(%esp),%xmm2
	movaps	48(%esp),%xmm3
	movl	%edx,%esp
	movl	12(%esp),%edi
	movups	%xmm0,(%edi)
	movups	%xmm1,16(%edi)
	movups	%xmm2,32(%edi)
	movups	%xmm3,48(%edi)
	popl	%esi
	popl	%edi
	ret
.size	padlock_sha512_blocks,.-.L_padlock_sha512_blocks_begin
.byte	86,73,65,32,80,97,100,108,111,99,107,32,120,56,54,32
.byte	109,111,100,117,108,101,44,32,67,82,89,80,84,79,71,65
.byte	77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101
.byte	110,115,115,108,46,111,114,103,62,0
.align	16
.data
.align	4
.Lpadlock_saved_context:
.long	0

.section .note.GNU-stack,"",%progbits
