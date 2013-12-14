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
.file	"x86cpuid.s"
.text
.globl	_OPENSSL_ia32_cpuid
.def	_OPENSSL_ia32_cpuid;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_cpuid:
.L_OPENSSL_ia32_cpuid_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	xorl	%edx,%edx
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
	jnc	.L000nocpuid
	movl	20(%esp),%esi
	movl	%eax,8(%esi)
	.byte	0x0f,0xa2
	movl	%eax,%edi
	xorl	%eax,%eax
	cmpl	$1970169159,%ebx
	setne	%al
	movl	%eax,%ebp
	cmpl	$1231384169,%edx
	setne	%al
	orl	%eax,%ebp
	cmpl	$1818588270,%ecx
	setne	%al
	orl	%eax,%ebp
	jz	.L001intel
	cmpl	$1752462657,%ebx
	setne	%al
	movl	%eax,%esi
	cmpl	$1769238117,%edx
	setne	%al
	orl	%eax,%esi
	cmpl	$1145913699,%ecx
	setne	%al
	orl	%eax,%esi
	jnz	.L001intel
	movl	$2147483648,%eax
	.byte	0x0f,0xa2
	cmpl	$2147483649,%eax
	jb	.L001intel
	movl	%eax,%esi
	movl	$2147483649,%eax
	.byte	0x0f,0xa2
	orl	%ecx,%ebp
	andl	$2049,%ebp
	cmpl	$2147483656,%esi
	jb	.L001intel
	movl	$2147483656,%eax
	.byte	0x0f,0xa2
	movzbl	%cl,%esi
	incl	%esi
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	btl	$28,%edx
	jnc	.L002generic
	shrl	$16,%ebx
	andl	$255,%ebx
	cmpl	%esi,%ebx
	ja	.L002generic
	andl	$4026531839,%edx
	jmp	.L002generic
.L001intel:
	cmpl	$7,%edi
	jb	.L003cacheinfo
	movl	20(%esp),%esi
	movl	$7,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	movl	%ebx,8(%esi)
.L003cacheinfo:
	cmpl	$4,%edi
	movl	$-1,%edi
	jb	.L004nocacheinfo
	movl	$4,%eax
	movl	$0,%ecx
	.byte	0x0f,0xa2
	movl	%eax,%edi
	shrl	$14,%edi
	andl	$4095,%edi
.L004nocacheinfo:
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	andl	$3220176895,%edx
	cmpl	$0,%ebp
	jne	.L005notintel
	orl	$1073741824,%edx
	andb	$15,%ah
	cmpb	$15,%ah
	jne	.L005notintel
	orl	$1048576,%edx
.L005notintel:
	btl	$28,%edx
	jnc	.L002generic
	andl	$4026531839,%edx
	cmpl	$0,%edi
	je	.L002generic
	orl	$268435456,%edx
	shrl	$16,%ebx
	cmpb	$1,%bl
	ja	.L002generic
	andl	$4026531839,%edx
.L002generic:
	andl	$2048,%ebp
	andl	$4294965247,%ecx
	movl	%edx,%esi
	orl	%ecx,%ebp
	btl	$27,%ecx
	jnc	.L006clear_avx
	xorl	%ecx,%ecx
.byte	15,1,208
	andl	$6,%eax
	cmpl	$6,%eax
	je	.L007done
	cmpl	$2,%eax
	je	.L006clear_avx
.L008clear_xmm:
	andl	$4261412861,%ebp
	andl	$4278190079,%esi
.L006clear_avx:
	andl	$4026525695,%ebp
	movl	20(%esp),%edi
	andl	$4294967263,8(%edi)
.L007done:
	movl	%esi,%eax
	movl	%ebp,%edx
.L000nocpuid:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_rdtsc
.def	_OPENSSL_rdtsc;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_rdtsc:
.L_OPENSSL_rdtsc_begin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	leal	__gnutls_x86_cpuid_s,%ecx
	btl	$4,(%ecx)
	jnc	.L009notsc
	.byte	0x0f,0x31
.L009notsc:
	ret
.globl	_OPENSSL_instrument_halt
.def	_OPENSSL_instrument_halt;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_halt:
.L_OPENSSL_instrument_halt_begin:
	leal	__gnutls_x86_cpuid_s,%ecx
	btl	$4,(%ecx)
	jnc	.L010nohalt
.long	2421723150
	andl	$3,%eax
	jnz	.L010nohalt
	pushfl
	popl	%eax
	btl	$9,%eax
	jnc	.L010nohalt
	.byte	0x0f,0x31
	pushl	%edx
	pushl	%eax
	hlt
	.byte	0x0f,0x31
	subl	(%esp),%eax
	sbbl	4(%esp),%edx
	addl	$8,%esp
	ret
.L010nohalt:
	xorl	%eax,%eax
	xorl	%edx,%edx
	ret
.globl	_OPENSSL_far_spin
.def	_OPENSSL_far_spin;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_far_spin:
.L_OPENSSL_far_spin_begin:
	pushfl
	popl	%eax
	btl	$9,%eax
	jnc	.L011nospin
	movl	4(%esp),%eax
	movl	8(%esp),%ecx
.long	2430111262
	xorl	%eax,%eax
	movl	(%ecx),%edx
	jmp	.L012spin
.align	16
.L012spin:
	incl	%eax
	cmpl	(%ecx),%edx
	je	.L012spin
.long	529567888
	ret
.L011nospin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	ret
.globl	_OPENSSL_wipe_cpu
.def	_OPENSSL_wipe_cpu;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_wipe_cpu:
.L_OPENSSL_wipe_cpu_begin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	leal	__gnutls_x86_cpuid_s,%ecx
	movl	(%ecx),%ecx
	btl	$1,(%ecx)
	jnc	.L013no_x87
.long	4007259865,4007259865,4007259865,4007259865,2430851995
.L013no_x87:
	leal	4(%esp),%eax
	ret
.globl	_OPENSSL_atomic_add
.def	_OPENSSL_atomic_add;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_atomic_add:
.L_OPENSSL_atomic_add_begin:
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	pushl	%ebx
	nop
	movl	(%edx),%eax
.L014spin:
	leal	(%eax,%ecx,1),%ebx
	nop
.long	447811568
	jne	.L014spin
	movl	%ebx,%eax
	popl	%ebx
	ret
.globl	_OPENSSL_indirect_call
.def	_OPENSSL_indirect_call;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_indirect_call:
.L_OPENSSL_indirect_call_begin:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$28,%esp
	movl	12(%ebp),%ecx
	movl	%ecx,(%esp)
	movl	16(%ebp),%edx
	movl	%edx,4(%esp)
	movl	20(%ebp),%eax
	movl	%eax,8(%esp)
	movl	24(%ebp),%eax
	movl	%eax,12(%esp)
	movl	28(%ebp),%eax
	movl	%eax,16(%esp)
	movl	32(%ebp),%eax
	movl	%eax,20(%esp)
	movl	36(%ebp),%eax
	movl	%eax,24(%esp)
	call	*8(%ebp)
	movl	%ebp,%esp
	popl	%ebp
	ret
.globl	_OPENSSL_cleanse
.def	_OPENSSL_cleanse;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_cleanse:
.L_OPENSSL_cleanse_begin:
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	xorl	%eax,%eax
	cmpl	$7,%ecx
	jae	.L015lot
	cmpl	$0,%ecx
	je	.L016ret
.L017little:
	movb	%al,(%edx)
	subl	$1,%ecx
	leal	1(%edx),%edx
	jnz	.L017little
.L016ret:
	ret
.align	16
.L015lot:
	testl	$3,%edx
	jz	.L018aligned
	movb	%al,(%edx)
	leal	-1(%ecx),%ecx
	leal	1(%edx),%edx
	jmp	.L015lot
.L018aligned:
	movl	%eax,(%edx)
	leal	-4(%ecx),%ecx
	testl	$-4,%ecx
	leal	4(%edx),%edx
	jnz	.L018aligned
	cmpl	$0,%ecx
	jne	.L017little
	ret
.globl	_OPENSSL_instrument_bus
.def	_OPENSSL_instrument_bus;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_bus:
.L_OPENSSL_instrument_bus_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	$0,%eax
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_instrument_bus2
.def	_OPENSSL_instrument_bus2;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_bus2:
.L_OPENSSL_instrument_bus2_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	$0,%eax
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_ia32_rdrand
.def	_OPENSSL_ia32_rdrand;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_rdrand:
.L_OPENSSL_ia32_rdrand_begin:
	movl	$8,%ecx
.L019loop:
.byte	15,199,240
	jc	.L020break
	loop	.L019loop
.L020break:
	cmpl	$0,%eax
	cmovel	%ecx,%eax
	ret
.comm	__gnutls_x86_cpuid_s,16
.section	.ctors
.long	_OPENSSL_cpuid_setup

.section .note.GNU-stack,"",%progbits
