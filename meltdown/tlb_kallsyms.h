#ifndef _TLB_KALLSYMS_H
#define _TLB_KALLSYMS_H

extern struct tracepoint *kgr__tracepoint_tlb_flush;
extern unsigned long *kgr_tlb_single_page_flush_ceiling;

extern int (*kgr_cpumask_any_but)(const struct cpumask *mask, unsigned int cpu);

#define TLB_KALLSYMS							\
	{ "__tracepoint_tlb_flush",					\
			(void *)&kgr__tracepoint_tlb_flush},		\
	{ "tlb_single_page_flush_ceiling",				\
			(void *)&kgr_tlb_single_page_flush_ceiling },	\
	{ "cpumask_any_but", (void *)&kgr_cpumask_any_but },		\

#endif
