#!/usr/bin/perl
#
# ====================================================================
# Written by Nikos Mavrogiannopoulos
# Placed under the LGPL
# ====================================================================
#

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../crypto/perlasm");
require "x86asm.pl";

$output=pop;
open STDOUT,">$output";

&asm_init($ARGV[0],$0);

&function_begin_B("gnutls_cpuid");
	&push	("ebp");
	&mov    ("ebp", "esp");
	&sub    ("esp", 12);
	&mov    (&DWP(0,"esp"), "ebx");
	&mov    ("eax",&DWP(8,"ebp"));
	&mov    (&DWP(4,"esp"), "esi");
	&mov    (&DWP(8,"esp"), "edi");
	&push	("ebx");
	&cpuid	();
	&mov    ("edi", "ebx");
	&pop	("ebx");
	&mov	("esi","edx");
	&mov    ("edx",&DWP(12,"ebp"));
	&mov    (&DWP(0,"edx"), "eax");
	&mov    ("eax",&DWP(16,"ebp"));
	&mov    (&DWP(0,"eax"), "edi");
	&mov    ("eax",&DWP(20,"ebp"));
	&mov    (&DWP(0,"eax"), "ecx");
	&mov    ("eax",&DWP(24,"ebp"));
	&mov    (&DWP(0,"eax"), "esi");
	&mov    ("ebx",&DWP(0,"esp"));
	&mov    ("esi",&DWP(4,"esp"));
	&mov    ("edi",&DWP(8,"esp"));
	&mov    ("esp","ebp");
	&pop	("ebp");
	&ret    ();
&function_end_B("gnutls_cpuid");

&function_begin_B("gnutls_have_cpuid");
	&pushf	();
	&pop    ("eax");
	&or     ("eax",0x200000);
	&push   ("eax");
	&popf   ();
	&pushf  ();
	&pop    ("eax");
	&and     ("eax",0x200000);
	&ret    ();
&function_end_B("gnutls_have_cpuid");

&asciz("CPUID for x86");
&asm_finish();

close STDOUT;
