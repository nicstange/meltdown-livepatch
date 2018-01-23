#ifndef _ENTRY_64_COMPAT_KALLSYMS_H
#define _ENTRY_64_COMPAT_KALLSYMS_H

struct pt_regs;

long (*kgr_do_fast_syscall_32)(struct pt_regs *regs);
void (*kgr_do_syscall_32_irqs_off)(struct pt_regs *regs);


#define ENTRY_64_COMPAT_KALLSYMS					\
	{ "do_fast_syscall_32", (void *)&kgr_do_fast_syscall_32 },	\
	{ "do_syscall_32_irqs_off",					\
			(void *)&kgr_do_syscall_32_irqs_off },		\

#endif
