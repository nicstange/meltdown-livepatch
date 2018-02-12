#ifndef _EXEC_KALLSYMS_H
#define _EXEC_KALLSYMS_H

#include <linux/pid.h>

extern struct tracepoint *kgr__tracepoint_tlb_flush;

extern struct static_key *kgr_rdpmc_always_available;

struct task_struct;
struct mm_struct;
struct signal_struct;
struct file;
struct files_struct;

extern void (*kgr_mm_release)(struct task_struct *tsk, struct mm_struct *mm);
extern void (*kgr_sync_mm_rss)(struct mm_struct *mm);
extern void (*kgr_mm_update_next_owner)(struct mm_struct *mm);
extern int (*kgr_zap_other_threads)(struct task_struct *p);
extern void (*kgr_change_pid)(struct task_struct *task, enum pid_type type,
			      struct pid *pid);
extern void (*kgr_transfer_pid)(struct task_struct *old,
				struct task_struct *new, enum pid_type type);
extern void (*kgr__wake_up_parent)(struct task_struct *p,
				   struct task_struct *parent);
extern void (*kgr_release_task)(struct task_struct *p);
extern void (*kgr_exit_itimers)(struct signal_struct *sig);
extern void (*kgr_flush_itimer_signals)(void);
extern void (*kgr_set_mm_exe_file)(struct mm_struct *mm,
				   struct file *new_exe_file);
extern void (*kgr_flush_thread)(void);
extern void (*kgr_do_close_on_exec)(struct files_struct *files);


#define EXEC_KALLSYMS							\
	{ "mm_release", (void *)&kgr_mm_release },			\
	{ "sync_mm_rss", (void *)&kgr_sync_mm_rss },			\
	{ "mm_update_next_owner", (void *)&kgr_mm_update_next_owner },	\
	{ "zap_other_threads", (void *)&kgr_zap_other_threads },	\
	{ "change_pid", (void *)&kgr_change_pid },			\
	{ "transfer_pid", (void *)&kgr_transfer_pid },			\
	{ "__wake_up_parent", (void *)&kgr__wake_up_parent },		\
	{ "release_task", (void *)&kgr_release_task },			\
	{ "exit_itimers", (void *)&kgr_exit_itimers },			\
	{ "flush_itimer_signals", (void *)&kgr_flush_itimer_signals },	\
	{ "set_mm_exe_file", (void *)&kgr_set_mm_exe_file },		\
	{ "flush_thread", (void *)&kgr_flush_thread },			\
	{ "do_close_on_exec", (void *)&kgr_do_close_on_exec },		\

#endif
