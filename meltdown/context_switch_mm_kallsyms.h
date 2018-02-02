#ifndef _CONTEXT_SWITCH_MM_KALLSYMS_HH
#define _CONTEXT_SWITCH_MM_KALLSYMS_HH

extern struct tracepoint *kgr__tracepoint_sched_switch;

#define CONTEXT_SWITCH_MM_KALLSYMS					\
	{ "__tracepoint_sched_switch",					\
		(void *)&kgr__tracepoint_sched_switch },		\

#endif
