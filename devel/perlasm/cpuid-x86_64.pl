#!/usr/bin/env perl
#
# ====================================================================
# Written by Nikos Mavrogiannopoulos
# Based on e_padlock-x86_64
# ====================================================================
#

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../crypto/perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

$code=".text\n";

($arg1,$arg2,$arg3,$arg4)=$win64?("%rcx","%rdx","%r8", "%r9") : # Win64 order
                                 ("%rdi","%rsi","%rdx","%rcx"); # Unix order


$code.=<<___;
.globl gnutls_cpuid
.type gnutls_cpuid,\@abi-omnipotent
.align	16
gnutls_cpuid:
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
.size gnutls_cpuid,.-gnutls_cpuid
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;

