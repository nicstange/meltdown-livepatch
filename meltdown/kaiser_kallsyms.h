#ifndef _KAISER_KALLSYMS_H
#define _KAISER_KALLSYMS_H

#include <asm/hw_irq.h>

extern struct mm_struct *kgr_init_mm;
extern char (*kgr__irqentry_text_start)[];
extern char (*kgr__irqentry_text_end)[];
extern char (*kgr_exception_stacks)
	[(N_EXCEPTION_STACKS - 1) * EXCEPTION_STKSZ + DEBUG_STKSZ];
extern vector_irq_t *kgr_vector_irq;
extern struct debug_store *kgr_cpu_debug_store;

#define KAISER_KALLSYMS						\
	{ "init_mm", (void *)&kgr_init_mm },				\
	{ "__irqentry_text_start",					\
			(void *)&kgr__irqentry_text_start },		\
	{ "__irqentry_text_end", (void *)&kgr__irqentry_text_end },	\
	{ "exception_stacks", (void *)&kgr_exception_stacks },		\
	{ "vector_irq", (void *)&kgr_vector_irq },			\
	{ "cpu_debug_store", (void *)&kgr_cpu_debug_store },		\

#endif
