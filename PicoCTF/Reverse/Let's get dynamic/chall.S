	.file	"chall.c"
	.text
	.section	.rodata
	.align 8
.LC1:
	.string	"Correct! You entered the flag."
.LC2:
	.string	"No, that's not right."
	.align 8
.LC0:
	.string	"\002qs\312\307*\207\375\313-\370\371+\361\025I\020<"
	.string	"TL\r\357\247C\250\002M\367\314\231\223\327\210\226\230\030\370\306*\205LX3\312\353Q\237\347"
	.text
	.globl	main
	.type	main, @function
main:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$296, %rsp
	.cfi_offset 3, -24
	movl	%edi, -292(%rbp)
	movq	%rsi, -304(%rbp)
	movq	%fs:40, %rax
	movq	%rax, -24(%rbp)
	xorl	%eax, %eax
	movq	.LC0(%rip), %rax
	movq	8+.LC0(%rip), %rdx
	movq	%rax, -144(%rbp)
	movq	%rdx, -136(%rbp)
	movq	16+.LC0(%rip), %rax
	movq	24+.LC0(%rip), %rdx
	movq	%rax, -128(%rbp)
	movq	%rdx, -120(%rbp)
	movq	32+.LC0(%rip), %rax
	movq	40+.LC0(%rip), %rdx
	movq	%rax, -112(%rbp)
	movq	%rdx, -104(%rbp)
	movzwl	48+.LC0(%rip), %eax
	movw	%ax, -96(%rbp)
	movabsq	$-7866547665503188383, %rax
	movabsq	$750938240303713972, %rdx
	movq	%rax, -80(%rbp)
	movq	%rdx, -72(%rbp)
	movabsq	$-245100717349187545, %rax
	movabsq	$-1321891645065211527, %rdx
	movq	%rax, -64(%rbp)
	movq	%rdx, -56(%rbp)
	movabsq	$4728704058583732155, %rax
	movabsq	$-7828694793552836984, %rdx
	movq	%rax, -48(%rbp)
	movq	%rdx, -40(%rbp)
	movw	$185, -32(%rbp)
	movq	stdin(%rip), %rdx
	leaq	-208(%rbp), %rax
	movl	$49, %esi
	movq	%rax, %rdi
	call	fgets@PLT
	movl	$0, -276(%rbp)
	jmp	.L2
.L3:
	movl	-276(%rbp), %eax
	cltq
	movzbl	-144(%rbp,%rax), %edx
	movl	-276(%rbp), %eax
	cltq
	movzbl	-80(%rbp,%rax), %eax
	xorl	%eax, %edx
	movl	-276(%rbp), %eax
	xorl	%edx, %eax
	xorl	$19, %eax
	movl	%eax, %edx
	movl	-276(%rbp), %eax
	cltq
	movb	%dl, -272(%rbp,%rax)
	addl	$1, -276(%rbp)
.L2:
	movl	-276(%rbp), %eax
	movslq	%eax, %rbx
	leaq	-144(%rbp), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	cmpq	%rax, %rbx
	jb	.L3
	leaq	-272(%rbp), %rcx
	leaq	-208(%rbp), %rax
	movl	$49, %edx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	memcmp@PLT
	testl	%eax, %eax
	je	.L4
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
	movl	$0, %eax
	jmp	.L6
.L4:
	leaq	.LC2(%rip), %rdi
	call	puts@PLT
	movl	$1, %eax
.L6:
	movq	-24(%rbp), %rcx
	xorq	%fs:40, %rcx
	je	.L7
	call	__stack_chk_fail@PLT
.L7:
	addq	$296, %rsp
	popq	%rbx
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
