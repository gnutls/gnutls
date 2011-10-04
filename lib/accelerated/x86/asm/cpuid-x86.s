	.file "cpuid.asm"
        
	.text
	.align 16
.globl _gnutls_cpuid
.type _gnutls_cpuid,%function
_gnutls_cpuid:
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
.size _gnutls_cpuid, . - _gnutls_cpuid

	.globl	_gnutls_have_cpuid
	.type	_gnutls_have_cpuid, @function
_gnutls_have_cpuid:
.LFB0:
	.cfi_startproc
	pushfl	
	pop %eax	
	orl $0x200000, %eax	
	push %eax	
	popfl	
	pushfl	
	pop %eax	
	andl $0x200000, %eax	
	ret
	.cfi_endproc
.LFE0:
	.size	_gnutls_have_cpuid, .-_gnutls_have_cpuid

.section .note.GNU-stack,"",@progbits
