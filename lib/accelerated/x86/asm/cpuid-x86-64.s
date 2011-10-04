	.file "cpuid.asm"
        
	.text
	.align 16
.globl _gnutls_cpuid
.type _gnutls_cpuid,%function
_gnutls_cpuid:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rbx
	movl	%edi, -12(%rbp)
	movq	%rsi, -24(%rbp)
	movq	%rdx, -32(%rbp)
	movq	%rcx, -40(%rbp)
	movq	%r8, -48(%rbp)
	movl	-12(%rbp), %eax
	movl	%eax, -60(%rbp)
	movl	-60(%rbp), %eax
	cpuid
	movl	%edx, -56(%rbp)
	movl	%ecx, %esi
	movl	%eax, -52(%rbp)
	movq	-24(%rbp), %rax
	movl	-52(%rbp), %edx
	movl	%edx, (%rax)
	movq	-32(%rbp), %rax
	movl	%ebx, (%rax)
	movq	-40(%rbp), %rax
	movl	%esi, (%rax)
	movq	-48(%rbp), %rax
	movl	-56(%rbp), %ecx
	movl	%ecx, (%rax)
	popq	%rbx
	leave
	ret
.size _gnutls_cpuid, . - _gnutls_cpuid


.section .note.GNU-stack,"",@progbits
