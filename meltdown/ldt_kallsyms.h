#ifndef _LDT_KALLSYMS
#define _LDT_KALLSYMS

extern void (*kgr_flush_ldt)(void *current_mm);

#define LDT_KALLSYMS					\
	{ "flush_ldt", (void *)&kgr_flush_ldt },	\

#endif
