#ifndef _PERF_EVENT_INTEL_DS_KALLSYMS_H
#define _PERF_EVENT_INTEL_DS_KALLSYMS_H

extern struct cpu_hw_events __percpu *kgr_cpu_hw_events;
extern struct x86_pmu *kgr_x86_pmu;
extern void * __percpu *kgr_insn_buffer;
extern struct mutex *kgr_pmc_reserve_mutex;
extern atomic_t *kgr_pmc_refcount;

extern void (*kgr_release_ds_buffer)(int cpu);
extern void (*kgr_init_debug_store_on_cpu)(int cpu);


#define PERF_EVENT_INTEL_DS_KALLSYMS					\
	{ "cpu_hw_events", (void *)&kgr_cpu_hw_events },		\
	{ "x86_pmu", (void *)&kgr_x86_pmu },				\
	{ "insn_buffer", (void *)&kgr_insn_buffer },			\
	{ "pmc_reserve_mutex", (void *)&kgr_pmc_reserve_mutex },	\
	{ "pmc_refcount", (void *)&kgr_pmc_refcount },			\
	{ "release_ds_buffer", (void *)&kgr_release_ds_buffer },	\
	{ "init_debug_store_on_cpu",					\
			(void *)&kgr_init_debug_store_on_cpu },	\

#endif
