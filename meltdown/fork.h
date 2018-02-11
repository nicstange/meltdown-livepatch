#ifndef _KGR_FORK_H
#define _KGR_FORK_H

void kgr_free_task(struct task_struct *tsk);

struct task_struct *kgr_copy_process(unsigned long clone_flags,
				     unsigned long stack_start,
				     unsigned long stack_size,
				     int __user *child_tidptr,
				     struct pid *pid,
				     int trace,
				     unsigned long tls,
				     int node);

int kgr_kaiser_map_all_thread_stacks(void);

#endif
