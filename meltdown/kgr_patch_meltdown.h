#ifndef _KGR_PATCH_MELTDOWN_H
#define _KGR_PATCH_MELTDOWN_H

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

#endif
