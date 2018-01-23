#ifndef _KGRAFT_HOOKS_KALLSYMS_H
#define _KGRAFT_HOOKS_KALLSYMS_H

#include <linux/rwlock_types.h>
#include <linux/workqueue.h>

struct kgr_patch_fun;

extern struct workqueue_struct **kgr_kgr_wq;
extern struct delayed_work *kgr_kgr_work;
extern struct mutex *kgr_kgr_in_progress_lock;
extern struct list_head *kgr_kgr_patches;
extern bool __percpu * *kgr_kgr_irq_use_new;
extern bool *kgr_kgr_in_progress;
extern bool *kgr_kgr_initialized;
extern struct kgr_patch **kgr_kgr_patch;
extern bool *kgr_kgr_revert;
extern unsigned long (*kgr_kgr_immutable)[];
extern rwlock_t *kgr_tasklist_lock;
extern int (*kgr_kgr_patch_code)(struct kgr_patch_fun *patch_fun, bool final,
				 bool revert, bool replace_revert);
extern bool (*kgr_kgr_patch_contains)(const struct kgr_patch *p,
				const struct kgr_patch_fun *patch_fun);
extern void (*kgr_kgr_patching_failed)(struct kgr_patch *patch,
			struct kgr_patch_fun *patch_fun, bool process_all);
extern void (*kgr_kgr_handle_irq_cpu)(struct work_struct *work);

extern void (*kgr_signal_wake_up_state)(struct task_struct *t, unsigned int state);
extern int (*kgr_schedule_on_each_cpu)(work_func_t func);

#define KGRAFT_HOOKS_KALLSYMS						\
	{ "kgr_wq", (void *)&kgr_kgr_wq },				\
	{ "kgr_work", (void *)&kgr_kgr_work },				\
	{ "kgr_in_progress_lock", (void *)&kgr_kgr_in_progress_lock },	\
	{ "kgr_patches", (void *)&kgr_kgr_patches },			\
	{ "kgr_irq_use_new", (void *)&kgr_kgr_irq_use_new },		\
	{ "kgr_in_progress", (void *)&kgr_kgr_in_progress },		\
	{ "kgr_initialized", (void *)&kgr_kgr_initialized },		\
	{ "kgr_patch", (void *)&kgr_kgr_patch },			\
	{ "kgr_revert", (void *)&kgr_kgr_revert },			\
	{ "kgr_immutable", (void *)&kgr_kgr_immutable },		\
	{ "tasklist_lock", (void *)&kgr_tasklist_lock },		\
	{ "kgr_patch_code", (void *)&kgr_kgr_patch_code },		\
	{ "kgr_patch_contains", (void *)&kgr_kgr_patch_contains },	\
	{ "kgr_patching_failed", (void *)&kgr_kgr_patching_failed },	\
	{ "kgr_handle_irq_cpu", (void *)&kgr_kgr_handle_irq_cpu },	\
	{ "signal_wake_up_state", (void *)&kgr_signal_wake_up_state },	\
	{ "schedule_on_each_cpu", (void *)&kgr_schedule_on_each_cpu },

#endif
