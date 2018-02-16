#ifndef _KGR_TLB_H
#define _KGR_TLB_H

#include <linux/tracepoint.h>

void kgr_native_flush_tlb(void);
void kgr_native_flush_tlb_global(void);
void kgr_native_flush_tlb_single(unsigned long addr);
void kgr_flush_tlb_func(void *info);
void kgr_flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
			    unsigned long end, unsigned long vmflag);
void kgr_flush_tlb_page(struct vm_area_struct *vma, unsigned long start);
void kgr_do_kernel_range_flush(void *info);


#define __KGR_DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static inline void kgr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&kgr__tracepoint_##name->key))) \
			__DO_TRACE(kgr__tracepoint_##name,		\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond),,);			\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched(kgr__tracepoint_##name->funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KGR_DECLARE_TRACE_CONDITION(name, proto, args, cond)		\
	__KGR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
		cpu_online(raw_smp_processor_id()) && (PARAMS(cond)),	\
		PARAMS(void *__data, proto),				\
		PARAMS(__data, args))

#define KGR_TRACE_EVENT_CONDITION(name, proto, args, cond)		\
	KGR_DECLARE_TRACE_CONDITION(name, PARAMS(proto),		\
				    PARAMS(args), PARAMS(cond))


extern struct tracepoint *kgr__tracepoint_tlb_flush;

KGR_TRACE_EVENT_CONDITION(tlb_flush,
	TP_PROTO(int reason, unsigned long pages),
	TP_ARGS(reason, pages),
	TP_CONDITION(cpu_online(smp_processor_id())))

#endif
