#ifndef _FORK_KALLSYMS_H
#define _FORK_KALLSYMS_H

#include <linux/hrtimer.h>

extern struct tracepoint *kgr__tracepoint_task_newtask;
extern struct kmem_cache **kgr_task_struct_cachep;
extern struct kmem_cache **kgr_mm_cachep;
extern struct kmem_cache **kgr_vm_area_cachep;
extern struct kmem_cache **kgr_signal_cachep;
extern struct kmem_cache **kgr_taskstats_cache;
extern struct kmem_cache **kgr_delayacct_cache;
extern struct kmem_cache **kgr_sighand_cachep;
extern struct percpu_counter *kgr_vm_committed_as;
extern s32 *kgr_vm_committed_as_batch;
extern struct pid *kgr_init_struct_pid;
extern struct percpu_rw_semaphore *kgr_cgroup_threadgroup_rwsem;
extern unsigned long __percpu *kgr_process_counts;
extern unsigned long *kgr_total_forks;
extern int *kgr_nr_threads;
extern int *kgr_max_threads;
extern struct user_struct *kgr_root_user;

struct mm_struct;
struct task_struct;
struct mempolicy;
struct vm_area_struct;
struct cred;
struct file;
struct files_struct;
struct signal_struct;
struct user_namespace;
struct thread_info;
struct rb_root;
struct rb_node;
struct pid_namespace;
struct sighand_struct;

extern int (*kgr__ksm_enter)(struct mm_struct *mm);
extern int (*kgr__khugepaged_enter)(struct mm_struct *mm);
extern void (*kgr__delayacct_tsk_init)(struct task_struct *tsk);
extern void (*kgr__mpol_put)(struct mempolicy *pol);
extern struct mempolicy* (*kgr__mpol_dup)(struct mempolicy *pol);
extern int (*kgr_vma_dup_policy)(struct vm_area_struct *src,
				 struct vm_area_struct *dst);
extern void (*kgr__ptrace_link)(struct task_struct *child,
				struct task_struct *new_parent,
				const struct cred *ptracer_cred);
extern bool (*kgr_task_set_jobctl_pending)(struct task_struct *task,
					   unsigned long mask);
extern void (*kgr__audit_free)(struct task_struct *tsk);
extern void (*kgr_uprobe_start_dup_mmap)(void);
extern void (*kgr_uprobe_end_dup_mmap)(void);
extern void (*kgr_uprobe_dup_mmap)(struct mm_struct *oldmm,
				   struct mm_struct *newmm);
extern void (*kgr_vm_stat_account)(struct mm_struct *mm, unsigned long flags,
			    struct file *file, long pages);
extern int (*kgr_security_vm_enough_memory_mm)(struct mm_struct *mm,
					       long pages);
extern struct files_struct* (*kgr_dup_fd)(struct files_struct *oldf,
					  int *errorp);
extern void (*kgr_tty_audit_fork)(struct signal_struct *sig);
extern struct fs_struct* (*kgr_copy_fs_struct)(struct fs_struct *old);
extern struct mm_struct* (*kgr_mm_init)(struct mm_struct *mm,
					struct task_struct *p,
					struct user_namespace *user_ns);
extern void (*kgr_get_seccomp_filter)(struct task_struct *tsk);
extern int (*kgr_tsk_fork_get_node)(struct task_struct *tsk);
extern int (*kgr_arch_dup_task_struct)(struct task_struct *dst,
				       struct task_struct *src);
extern void (*kgr_set_task_stack_end_magic)(struct task_struct *tsk);
extern void (*kgr_account_kernel_stack)(struct thread_info *ti, int account);
extern int (*kgr_anon_vma_fork)(struct vm_area_struct *vma,
				struct vm_area_struct *pvma);
extern void (*kgr_vma_interval_tree_insert_after)(struct vm_area_struct *node,
						  struct vm_area_struct *prev,
						  struct rb_root *root);
extern void (*kgr_reset_vma_resv_huge_pages)(struct vm_area_struct *vma);
extern void (*kgr__vma_link_rb)(struct mm_struct *mm,
				struct vm_area_struct *vma,
				struct rb_node **rb_link,
				struct rb_node *rb_parent);
extern int (*kgr_copy_page_range)(struct mm_struct *dst_mm,
				  struct mm_struct *src_mm,
				  struct vm_area_struct *vma);
extern int (*kgr_security_task_create)(unsigned long clone_flags);
extern void (*kgr_ftrace_graph_init_task)(struct task_struct *t);
extern int (*kgr_copy_creds)(struct task_struct *p, unsigned long clone_flags);
extern void (*kgr_acct_clear_integrals)(struct task_struct *tsk);
extern void (*kgr_cgroup_fork)(struct task_struct *child);
extern int (*kgr_sched_fork)(unsigned long clone_flags, struct task_struct *p);
extern int (*kgr_perf_event_init_task)(struct task_struct *child);
extern int (*kgr_audit_alloc)(struct task_struct *tsk);
extern int (*kgr_copy_semundo)(unsigned long clone_flags,
			       struct task_struct *tsk);
extern int (*kgr_copy_namespaces)(unsigned long flags, struct task_struct *tsk);
extern int (*kgr_copy_thread_tls)(unsigned long clone_flags, unsigned long sp,
				  unsigned long arg, struct task_struct *p,
				  unsigned long tls);
extern struct pid* (*kgr_alloc_pid)(struct pid_namespace *ns);
extern void (*kgr_user_disable_single_step)(struct task_struct *child);
extern void (*kgr_clear_all_latency_tracing)(struct task_struct *p);
extern int (*kgr_cgroup_can_fork)(struct task_struct *child,
				  void *ss_priv[]);
extern void (*kgr_attach_pid)(struct task_struct *task, enum pid_type type);
extern void (*kgr_proc_fork_connector)(struct task_struct *task);
extern void (*kgr_cgroup_post_fork)(struct task_struct *child,
				    void *old_ss_priv[]);
extern void (*kgr_perf_event_fork)(struct task_struct *task);
extern void (*kgr_uprobe_copy_process)(struct task_struct *t,
				       unsigned long flags);
extern void (*kgr_cgroup_cancel_fork)(struct task_struct *child,
				      void *ss_priv[]);
extern void (*kgr_free_pid)(struct pid *pid);
extern void (*kgr_exit_thread)(struct task_struct *tsk);
extern void (*kgr_exit_io_context)(struct task_struct *task);
extern void (*kgr_exit_task_namespaces)(struct task_struct *p);
extern void (*kgr__cleanup_sighand)(struct sighand_struct *sighand);
extern void (*kgr_exit_fs)(struct task_struct *tsk);
extern void (*kgr_exit_files)(struct task_struct *tsk);
extern void (*kgr_exit_sem)(struct task_struct *tsk);
extern void (*kgr_perf_event_free_task)(struct task_struct *task);
extern void (*kgr_exit_creds)(struct task_struct *tsk);
extern struct page* (*kgr_alloc_kmem_pages_node)(int nid, gfp_t gfp_mask,
						 unsigned int order);
extern void (*kgr_free_kmem_pages)(unsigned long addr, unsigned int order);
extern enum hrtimer_restart (*kgr_it_real_fn)(struct hrtimer *timer);
extern void (*kgr_flush_tlb_mm_range)(struct mm_struct *mm, unsigned long start,
				      unsigned long end, unsigned long vmflag);
extern void (*kgr_arch_release_thread_info)(struct thread_info *ti);
extern void (*kgr_ftrace_graph_exit_task)(struct task_struct *t);
extern void (*kgr_put_seccomp_filter)(struct task_struct *tsk);
extern void (*kgr_arch_release_task_struct)(struct task_struct *tsk);

#define FORK_KALLSYMS							\
	{ "__tracepoint_task_newtask",					\
			(void *)&kgr__tracepoint_task_newtask },	\
	{ "task_struct_cachep", (void *)&kgr_task_struct_cachep },	\
	{ "mm_cachep", (void *)&kgr_mm_cachep },			\
	{ "vm_area_cachep", (void *)&kgr_vm_area_cachep },		\
	{ "signal_cachep", (void *)&kgr_signal_cachep },		\
	{ "taskstats_cache", (void *)&kgr_taskstats_cache },		\
	{ "delayacct_cache", (void *)&kgr_delayacct_cache },		\
	{ "sighand_cachep", (void *)&kgr_sighand_cachep },		\
	{ "vm_committed_as", (void *)&kgr_vm_committed_as },		\
	{ "vm_committed_as_batch",					\
			(void *)&kgr_vm_committed_as_batch },		\
	{ "init_struct_pid", (void *)&kgr_init_struct_pid },		\
	{ "cgroup_threadgroup_rwsem",					\
			(void *)&kgr_cgroup_threadgroup_rwsem },	\
	{ "process_counts", (void *)&kgr_process_counts },		\
	{ "total_forks", (void *)&kgr_total_forks },			\
	{ "nr_threads", (void *)&kgr_nr_threads },			\
	{ "max_threads", (void *)&kgr_max_threads },			\
	{ "root_user", (void *)&kgr_root_user },			\
	{ "__ksm_enter", (void *)&kgr__ksm_enter },			\
	{ "__khugepaged_enter", (void *)&kgr__khugepaged_enter },	\
	{ "__delayacct_tsk_init", (void *)&kgr__delayacct_tsk_init },	\
	{ "__mpol_put", (void *)&kgr__mpol_put },			\
	{ "__mpol_dup", (void *)&kgr__mpol_dup },			\
	{ "vma_dup_policy", (void *)&kgr_vma_dup_policy },		\
	{ "__ptrace_link", (void *)&kgr__ptrace_link },		\
	{ "task_set_jobctl_pending",					\
			(void *)&kgr_task_set_jobctl_pending },	\
	{ "__audit_free", (void *)&kgr__audit_free },			\
	{ "uprobe_start_dup_mmap",					\
			(void *)&kgr_uprobe_start_dup_mmap },		\
	{ "uprobe_end_dup_mmap", (void *)&kgr_uprobe_end_dup_mmap },	\
	{ "uprobe_dup_mmap", (void *)&kgr_uprobe_dup_mmap },		\
	{ "vm_stat_account", (void *)&kgr_vm_stat_account },		\
	{ "security_vm_enough_memory_mm",				\
			(void *)&kgr_security_vm_enough_memory_mm },	\
	{ "dup_fd", (void *)&kgr_dup_fd },				\
	{ "tty_audit_fork", (void *)&kgr_tty_audit_fork },		\
	{ "copy_fs_struct", (void *)&kgr_copy_fs_struct },		\
	{ "mm_init", (void *)&kgr_mm_init },				\
	{ "get_seccomp_filter", (void *)&kgr_get_seccomp_filter },	\
	{ "tsk_fork_get_node", (void *)&kgr_tsk_fork_get_node },	\
	{ "arch_dup_task_struct", (void *)&kgr_arch_dup_task_struct },	\
	{ "set_task_stack_end_magic",					\
			(void *)&kgr_set_task_stack_end_magic },	\
	{ "account_kernel_stack", (void *)&kgr_account_kernel_stack },	\
	{ "anon_vma_fork", (void *)&kgr_anon_vma_fork },		\
	{ "vma_interval_tree_insert_after",				\
			(void *)&kgr_vma_interval_tree_insert_after },	\
	{ "reset_vma_resv_huge_pages",					\
			(void *)&kgr_reset_vma_resv_huge_pages },	\
	{ "__vma_link_rb", (void *)&kgr__vma_link_rb },		\
	{ "copy_page_range", (void *)&kgr_copy_page_range },		\
	{ "security_task_create", (void *)&kgr_security_task_create },	\
	{ "ftrace_graph_init_task",					\
			(void *)&kgr_ftrace_graph_init_task },		\
	{ "copy_creds", (void *)&kgr_copy_creds },			\
	{ "acct_clear_integrals", (void *)&kgr_acct_clear_integrals },	\
	{ "cgroup_fork", (void *)&kgr_cgroup_fork },			\
	{ "sched_fork", (void *)&kgr_sched_fork },			\
	{ "perf_event_init_task", (void *)&kgr_perf_event_init_task },	\
	{ "audit_alloc", (void *)&kgr_audit_alloc },			\
	{ "copy_semundo", (void *)&kgr_copy_semundo },			\
	{ "copy_namespaces", (void *)&kgr_copy_namespaces },		\
	{ "copy_thread_tls", (void *)&kgr_copy_thread_tls },		\
	{ "alloc_pid", (void *)&kgr_alloc_pid },			\
	{ "user_disable_single_step",					\
			(void *)&kgr_user_disable_single_step },	\
	{ "clear_all_latency_tracing",					\
			(void *)&kgr_clear_all_latency_tracing },	\
	{ "cgroup_can_fork", (void *)&kgr_cgroup_can_fork },		\
	{ "attach_pid", (void *)&kgr_attach_pid },			\
	{ "proc_fork_connector", (void *)&kgr_proc_fork_connector },	\
	{ "cgroup_post_fork", (void *)&kgr_cgroup_post_fork },		\
	{ "perf_event_fork", (void *)&kgr_perf_event_fork },		\
	{ "uprobe_copy_process", (void *)&kgr_uprobe_copy_process },	\
	{ "cgroup_cancel_fork", (void *)&kgr_cgroup_cancel_fork },	\
	{ "free_pid", (void *)&kgr_free_pid },				\
	{ "exit_thread", (void *)&kgr_exit_thread },			\
	{ "exit_io_context", (void *)&kgr_exit_io_context },		\
	{ "exit_task_namespaces", (void *)&kgr_exit_task_namespaces },	\
	{ "__cleanup_sighand", (void *)&kgr__cleanup_sighand },	\
	{ "exit_fs", (void *)&kgr_exit_fs },				\
	{ "exit_files", (void *)&kgr_exit_files },			\
	{ "exit_sem", (void *)&kgr_exit_sem },				\
	{ "perf_event_free_task", (void *)&kgr_perf_event_free_task },	\
	{ "exit_creds", (void *)&kgr_exit_creds },			\
	{ "alloc_kmem_pages_node",					\
			(void *)&kgr_alloc_kmem_pages_node },		\
	{ "free_kmem_pages", (void *)&kgr_free_kmem_pages },		\
	{ "it_real_fn", (void *)&kgr_it_real_fn },			\
	{ "flush_tlb_mm_range", (void *)&kgr_flush_tlb_mm_range },	\
	{ "arch_release_thread_info",					\
			(void *)&kgr_arch_release_thread_info },	\
	{ "ftrace_graph_exit_task",					\
			(void *)&kgr_ftrace_graph_exit_task },		\
	{ "put_seccomp_filter",					\
			(void *)&kgr_put_seccomp_filter },		\
	{ "arch_release_task_struct",					\
			(void *)&kgr_arch_release_task_struct },	\

#endif
