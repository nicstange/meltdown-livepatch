#ifndef _CALLING_H
#define _CALLING_H

/* from arch/x86/entry/calling.h */
/*
 * 64-bit system call stack frame layout defines and helpers,
 * for assembly code:
 */

/* The layout forms the "struct pt_regs" on the stack: */
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
#define R15		0*8
#define R14		1*8
#define R13		2*8
#define R12		3*8
#define RBP		4*8
#define RBX		5*8
/* These regs are callee-clobbered. Always saved on kernel entry. */
#define R11		6*8
#define R10		7*8
#define R9		8*8
#define R8		9*8
#define RAX		10*8
#define RCX		11*8
#define RDX		12*8
#define RSI		13*8
#define RDI		14*8
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
#define ORIG_RAX	15*8
/* Return frame for iretq */
#define RIP		16*8
#define CS		17*8
#define EFLAGS		18*8
#define RSP		19*8
#define SS		20*8

#define SIZEOF_PTREGS	21*8

	.macro ALLOC_PT_GPREGS_ON_STACK addskip=0
	addq	$-(15*8+\addskip), %rsp
	.endm

	.macro SAVE_C_REGS_HELPER offset=0 rax=1 rcx=1 r8910=1 r11=1
	.if \r11
	movq %r11, 6*8+\offset(%rsp)
	.endif
	.if \r8910
	movq %r10, 7*8+\offset(%rsp)
	movq %r9,  8*8+\offset(%rsp)
	movq %r8,  9*8+\offset(%rsp)
	.endif
	.if \rax
	movq %rax, 10*8+\offset(%rsp)
	.endif
	.if \rcx
	movq %rcx, 11*8+\offset(%rsp)
	.endif
	movq %rdx, 12*8+\offset(%rsp)
	movq %rsi, 13*8+\offset(%rsp)
	movq %rdi, 14*8+\offset(%rsp)
	.endm
	.macro SAVE_C_REGS offset=0
	SAVE_C_REGS_HELPER \offset, 1, 1, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX offset=0
	SAVE_C_REGS_HELPER \offset, 0, 0, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_R891011
	SAVE_C_REGS_HELPER 0, 1, 1, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RCX_R891011
	SAVE_C_REGS_HELPER 0, 1, 0, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX_R11
	SAVE_C_REGS_HELPER 0, 0, 0, 1, 0
	.endm

	.macro SAVE_EXTRA_REGS offset=0
	movq %r15, 0*8+\offset(%rsp)
	movq %r14, 1*8+\offset(%rsp)
	movq %r13, 2*8+\offset(%rsp)
	movq %r12, 3*8+\offset(%rsp)
	movq %rbp, 4*8+\offset(%rsp)
	movq %rbx, 5*8+\offset(%rsp)
	.endm

	.macro RESTORE_EXTRA_REGS offset=0
	movq 0*8+\offset(%rsp), %r15
	movq 1*8+\offset(%rsp), %r14
	movq 2*8+\offset(%rsp), %r13
	movq 3*8+\offset(%rsp), %r12
	movq 4*8+\offset(%rsp), %rbp
	movq 5*8+\offset(%rsp), %rbx
	.endm

	.macro ZERO_EXTRA_REGS
	xorl	%r15d, %r15d
	xorl	%r14d, %r14d
	xorl	%r13d, %r13d
	xorl	%r12d, %r12d
	xorl	%ebp, %ebp
	xorl	%ebx, %ebx
	.endm

	.macro RESTORE_C_REGS_HELPER rstor_rax=1, rstor_rcx=1, rstor_r11=1, rstor_r8910=1, rstor_rdx=1
	.if \rstor_r11
	movq 6*8(%rsp), %r11
	.endif
	.if \rstor_r8910
	movq 7*8(%rsp), %r10
	movq 8*8(%rsp), %r9
	movq 9*8(%rsp), %r8
	.endif
	.if \rstor_rax
	movq 10*8(%rsp), %rax
	.endif
	.if \rstor_rcx
	movq 11*8(%rsp), %rcx
	.endif
	.if \rstor_rdx
	movq 12*8(%rsp), %rdx
	.endif
	movq 13*8(%rsp), %rsi
	movq 14*8(%rsp), %rdi
	.endm
	.macro RESTORE_C_REGS
	RESTORE_C_REGS_HELPER 1,1,1,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RAX
	RESTORE_C_REGS_HELPER 0,1,1,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RCX
	RESTORE_C_REGS_HELPER 1,0,1,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_R11
	RESTORE_C_REGS_HELPER 1,1,0,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RCX_R11
	RESTORE_C_REGS_HELPER 1,0,0,1,1
	.endm

	.macro REMOVE_PT_GPREGS_FROM_STACK addskip=0
	subq $-(15*8+\addskip), %rsp
	.endm

	.macro icebp
	.byte 0xf1
	.endm


#endif
