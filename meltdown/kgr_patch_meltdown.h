#ifndef _KGR_PATCH_MELTDOWN_H
#define _KGR_PATCH_MELTDOWN_H

#include "tlb.h"
#include "kaiser.h"
#include "fork.h"

struct work_struct;

int kgr_patch_meltdown_init(void);
void kgr_patch_meltdown_cleanup(void);

void kgr_kgr_work_fn(struct work_struct *work);
int kgr_kgr_modify_kernel(struct kgr_patch *patch, bool revert);

void kgr_schedule_tail(struct task_struct *prev);

#define KGR_PATCH_MELTDOWN_FUNCS				\
	KGR_PATCH(kgr_work_fn, kgr_kgr_work_fn),		\
	KGR_PATCH(kgr_modify_kernel, kgr_kgr_modify_kernel),	\
	KGR_PATCH(schedule_tail, kgr_schedule_tail),		\
	KGR_PATCH(native_flush_tlb, kgr_native_flush_tlb),	\
	KGR_PATCH(native_flush_tlb_global,			\
		  kgr_native_flush_tlb_global),		\
	KGR_PATCH(native_flush_tlb_single,			\
		  kgr_native_flush_tlb_single),		\
	KGR_PATCH(native_set_pgd, kgr_native_set_pgd),		\
	KGR_PATCH(free_task, kgr_free_task),			\
	KGR_PATCH(copy_process, kgr_copy_process),		\

#endif
