#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/delayacct.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/fs_struct.h>
#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/vmacache.h>
#include <linux/fdtable.h>
#include <linux/random.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/tty.h>
#include <linux/user-return-notifier.h>
#include <linux/rtmutex.h>
#include <trace/syscall.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include "fork.h"
#include "fork_kallsyms.h"
#include "kaiser.h"
#include "shared_data.h"
#include "tlb.h"

#if IS_ENABLED(CONFIG_ARCH_TASK_STRUCT_ALLOCATOR)
#error "Livepatch supports only CONFIG_ARCH_TASK_STRUCT_ALLOCATOR=n"
#endif

#if THREAD_SIZE < PAGE_SIZE
#error "Livepatch supports only THREAD_SIZE >= PAGE_SIZE"
#endif

#if !IS_ENABLED(CONFIG_TASK_DELAY_ACCT)
#error "Livepatch supports only CONFIG_TASK_DELAY_ACCT=y"
#endif

#if !IS_ENABLED(CONFIG_TASK_XACCT)
#error "Livepatch supports only CONFIG_TASK_XACCT=y"
#endif

#if !IS_ENABLED(CONFIG_CGROUPS)
#error "Livepatch supports only CONFIG_CGROUPS=y"
#endif

#if !IS_ENABLED(CONFIG_PERF_EVENTS)
#error "Livepatch supports only CONFIG_PERF_EVENTS=y"
#endif

#if !IS_ENABLED(CONFIG_AUDITSYSCALL)
#error "Livepatch supports only CONFIG_AUDITSYSCALL=y"
#endif

#if !IS_ENABLED(CONFIG_SYSVIPC)
#error "Livepatch supports only CONFIG_SYSVIPC=y"
#endif

#if !IS_ENABLED(CONFIG_MMU)
#error "Livepatch supports only CONFIG_MMU=y"
#endif

#if !IS_ENABLED(CONFIG_UPROBES)
#error "Livepatch supports only CONFIG_UPROBES=y"
#endif

#if !IS_ENABLED(CONFIG_KSM)
#error "Livepatch supports only CONFIG_KSM=y"
#endif

#if !IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)
#error "Livepatch supports only CONFIG_TRANSPARENT_HUGEPAGE=y"
#endif

#if !IS_ENABLED(CONFIG_PROC_FS)
#error "Livepatch supports only CONFIG_PROC_FS=y"
#endif

#if !IS_ENABLED(CONFIG_SECURITY)
#error "Livepatch supports only CONFIG_SECURITY=y"
#endif

#if !IS_ENABLED(CONFIG_HUGETLB_PAGE)
#error "Livepatch supports only CONFIG_HUGETLB_PAGE=y"
#endif

#if !IS_ENABLED(CONFIG_LATENCYTOP)
#error "Livepatch supports only CONFIG_LATENCYTOP=y"
#endif

#if !IS_ENABLED(CONFIG_SECCOMP)
#error "Livepatch supports only CONFIG_SECCOMP=y"
#endif

#if !IS_ENABLED(CONFIG_PROC_EVENTS)
#error "Livepatch supports only CONFIG_PROC_EVENTS=y"
#endif

#if !IS_ENABLED(CONFIG_TASKSTATS)
#error "Livepatch supports only CONFIG_TASKSTATS=y"
#endif

#if IS_ENABLED(CONFIG_SCHED_AUTOGROUP)
#error "Livepatch supports only CONFIG_SCHED_AUTOGROUP=n"
#endif

#if !IS_ENABLED(CONFIG_AUDIT)
#error "Livepatch supports only CONFIG_AUDIT=y"
#endif

#if IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES)
#error "Livepatch supports only CONFIG_DEBUG_RT_MUTEXES=n"
#endif

#if !IS_ENABLED(CONFIG_FUNCTION_GRAPH_TRACER)
#error "Livepatch supports only CONFIG_FUNCTION_GRAPH_TRACER=y"
#endif

#if !IS_ENABLED(CONFIG_SECCOMP_FILTER)
#error "Livepatch supports only CONFIG_SECCOMP_FILTER=y"
#endif


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

#define KGR_DECLARE_TRACE(name, proto, args)				\
	__KGR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KGR_TRACE_EVENT(name, proto, args)			\
	KGR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))


struct tracepoint *kgr__tracepoint_task_newtask;

KGR_TRACE_EVENT(task_newtask,
		TP_PROTO(struct task_struct *task, unsigned long clone_flags),
		TP_ARGS(task, clone_flags));


extern rwlock_t *kgr_tasklist_lock;

struct kmem_cache **kgr_task_struct_cachep;
struct kmem_cache **kgr_mm_cachep;
struct kmem_cache **kgr_vm_area_cachep;
struct kmem_cache **kgr_signal_cachep;
struct kmem_cache **kgr_taskstats_cache;
struct kmem_cache **kgr_delayacct_cache;
struct kmem_cache **kgr_sighand_cachep;
struct percpu_counter *kgr_vm_committed_as;
s32 *kgr_vm_committed_as_batch;
struct pid *kgr_init_struct_pid;
struct percpu_rw_semaphore *kgr_cgroup_threadgroup_rwsem;
unsigned long __percpu *kgr_process_counts;
unsigned long *kgr_total_forks;
int *kgr_nr_threads;
int *kgr_max_threads;
struct user_struct *kgr_root_user;

int (*kgr__ksm_enter)(struct mm_struct *mm);
int (*kgr__khugepaged_enter)(struct mm_struct *mm);
void (*kgr__delayacct_tsk_init)(struct task_struct *tsk);
void (*kgr__mpol_put)(struct mempolicy *pol);
struct mempolicy* (*kgr__mpol_dup)(struct mempolicy *pol);
int (*kgr_vma_dup_policy)(struct vm_area_struct *src,
			  struct vm_area_struct *dst);
void (*kgr__ptrace_link)(struct task_struct *child,
			 struct task_struct *new_parent,
			  const struct cred *ptracer_cred);
bool (*kgr_task_set_jobctl_pending)(struct task_struct *task,
				    unsigned long mask);
void (*kgr__audit_free)(struct task_struct *tsk);
void (*kgr_uprobe_start_dup_mmap)(void);
void (*kgr_uprobe_end_dup_mmap)(void);
void (*kgr_uprobe_dup_mmap)(struct mm_struct *oldmm, struct mm_struct *newmm);
void (*kgr_vm_stat_account)(struct mm_struct *mm, unsigned long flags,
			    struct file *file, long pages);
int (*kgr_security_vm_enough_memory_mm)(struct mm_struct *mm, long pages);
struct files_struct* (*kgr_dup_fd)(struct files_struct *oldf, int *errorp);
void (*kgr_tty_audit_fork)(struct signal_struct *sig);
struct fs_struct* (*kgr_copy_fs_struct)(struct fs_struct *old);
struct mm_struct* (*kgr_mm_init)(struct mm_struct *mm, struct task_struct *p,
				 struct user_namespace *user_ns);
void (*kgr_get_seccomp_filter)(struct task_struct *tsk);
int (*kgr_tsk_fork_get_node)(struct task_struct *tsk);
int (*kgr_arch_dup_task_struct)(struct task_struct *dst,
				struct task_struct *src);
void (*kgr_set_task_stack_end_magic)(struct task_struct *tsk);
void (*kgr_account_kernel_stack)(struct thread_info *ti, int account);
int (*kgr_anon_vma_fork)(struct vm_area_struct *vma,
			 struct vm_area_struct *pvma);
void (*kgr_vma_interval_tree_insert_after)(struct vm_area_struct *node,
					   struct vm_area_struct *prev,
					   struct rb_root *root);
void (*kgr_reset_vma_resv_huge_pages)(struct vm_area_struct *vma);
void (*kgr__vma_link_rb)(struct mm_struct *mm, struct vm_area_struct *vma,
			 struct rb_node **rb_link, struct rb_node *rb_parent);
int (*kgr_copy_page_range)(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			   struct vm_area_struct *vma);
int (*kgr_security_task_create)(unsigned long clone_flags);
void (*kgr_ftrace_graph_init_task)(struct task_struct *t);
int (*kgr_copy_creds)(struct task_struct *p, unsigned long clone_flags);
void (*kgr_acct_clear_integrals)(struct task_struct *tsk);
void (*kgr_cgroup_fork)(struct task_struct *child);
int (*kgr_sched_fork)(unsigned long clone_flags, struct task_struct *p);
int (*kgr_perf_event_init_task)(struct task_struct *child);
int (*kgr_audit_alloc)(struct task_struct *tsk);
int (*kgr_copy_semundo)(unsigned long clone_flags, struct task_struct *tsk);
int (*kgr_copy_namespaces)(unsigned long flags, struct task_struct *tsk);
int (*kgr_copy_thread_tls)(unsigned long clone_flags, unsigned long sp,
			   unsigned long arg, struct task_struct *p,
			   unsigned long tls);
struct pid* (*kgr_alloc_pid)(struct pid_namespace *ns);
void (*kgr_user_disable_single_step)(struct task_struct *child);
void (*kgr_clear_all_latency_tracing)(struct task_struct *p);
int (*kgr_cgroup_can_fork)(struct task_struct *child,
			   void *ss_priv[CGROUP_CANFORK_COUNT]);
void (*kgr_attach_pid)(struct task_struct *task, enum pid_type type);
void (*kgr_proc_fork_connector)(struct task_struct *task);
void (*kgr_cgroup_post_fork)(struct task_struct *child,
			     void *old_ss_priv[CGROUP_CANFORK_COUNT]);
void (*kgr_perf_event_fork)(struct task_struct *task);
void (*kgr_uprobe_copy_process)(struct task_struct *t, unsigned long flags);
void (*kgr_cgroup_cancel_fork)(struct task_struct *child,
			       void *ss_priv[CGROUP_CANFORK_COUNT]);
void (*kgr_free_pid)(struct pid *pid);
void (*kgr_exit_thread)(struct task_struct *tsk);
void (*kgr_exit_io_context)(struct task_struct *task);
void (*kgr_exit_task_namespaces)(struct task_struct *p);
void (*kgr__cleanup_sighand)(struct sighand_struct *sighand);
void (*kgr_exit_fs)(struct task_struct *tsk);
void (*kgr_exit_files)(struct task_struct *tsk);
void (*kgr_exit_sem)(struct task_struct *tsk);
void (*kgr_perf_event_free_task)(struct task_struct *task);
void (*kgr_exit_creds)(struct task_struct *tsk);
struct page* (*kgr_alloc_kmem_pages_node)(int nid, gfp_t gfp_mask,
					  unsigned int order);
void (*kgr_free_kmem_pages)(unsigned long addr, unsigned int order);
enum hrtimer_restart (*kgr_it_real_fn)(struct hrtimer *timer);

void (*kgr_arch_release_thread_info)(struct thread_info *ti);
void (*kgr_ftrace_graph_exit_task)(struct task_struct *t);
void (*kgr_put_seccomp_filter)(struct task_struct *tsk);
void (*kgr_arch_release_task_struct)(struct task_struct *tsk);


/* from include/linux/taskstats_kern.h */
/* line 23 */
static inline void kgr_taskstats_tgid_free(struct signal_struct *sig)
{
	if (sig->stats)
		kmem_cache_free(*kgr_taskstats_cache, sig->stats);
}


/* from include/linux/cgroups-defs.h */
/* line 148 */
static inline void kgr_cgroup_threadgroup_change_begin(struct task_struct *tsk)
{
	percpu_down_read(kgr_cgroup_threadgroup_rwsem);
}

static inline void kgr_cgroup_threadgroup_change_end(struct task_struct *tsk)
{
	percpu_up_read(kgr_cgroup_threadgroup_rwsem);
}

/* from include/linux/sched.h */
/* line 2903 */
static inline void kgr_threadgroup_change_begin(struct task_struct *tsk)
{
	might_sleep();
	kgr_cgroup_threadgroup_change_begin(tsk);
}

static inline void kgr_threadgroup_change_end(struct task_struct *tsk)
{
	kgr_cgroup_threadgroup_change_end(tsk);
}


/* from include/linux/mman.h */
static inline void kgr_vm_acct_memory(long pages)
{
	__percpu_counter_add(kgr_vm_committed_as, pages,
			     *kgr_vm_committed_as_batch);
}

static inline void kgr_vm_unacct_memory(long pages)
{
	kgr_vm_acct_memory(-pages);
}


/* from include/linux/ksm.h */
/* line 28 */
static inline int kgr_ksm_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	if (test_bit(MMF_VM_MERGEABLE, &oldmm->flags))
		return kgr__ksm_enter(mm);
	return 0;
}


/* from include/linux/khugepaged.h */
/* line 26 */
static inline int kgr_khugepaged_fork(struct mm_struct *mm,
				      struct mm_struct *oldmm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &oldmm->flags))
		return kgr__khugepaged_enter(mm);
	return 0;
}


/* from include/linux/delayacct.h */
/* line 72 */
static inline void kgr_delayacct_tsk_init(struct task_struct *tsk)
{
	/* reinitialize in case parent's non-null pointer was dup'ed*/
	tsk->delays = NULL;
	if (delayacct_on)
		kgr__delayacct_tsk_init(tsk);
}

static inline void kgr_delayacct_tsk_free(struct task_struct *tsk)
{
	if (tsk->delays)
		kmem_cache_free(*kgr_delayacct_cache, tsk->delays);
	tsk->delays = NULL;
}



/* from include/linux/mempolicy.h */
/* line 69 */
static inline void kgr_mpol_put(struct mempolicy *pol)
{
	if (pol)
		kgr__mpol_put(pol);
}

/* line 92 */
static inline struct mempolicy *kgr_mpol_dup(struct mempolicy *pol)
{
	if (pol)
		pol = kgr__mpol_dup(pol);
	return pol;
}


/* from include/linux/ptrace.h */
/* line 218 */
static inline void kgr_ptrace_init_task(struct task_struct *child, bool ptrace)
{
	INIT_LIST_HEAD(&child->ptrace_entry);
	INIT_LIST_HEAD(&child->ptraced);
	child->jobctl = 0;
	child->ptrace = 0;
	child->parent = child->real_parent;

	if (unlikely(ptrace) && current->ptrace) {
		child->ptrace = current->ptrace;
		kgr__ptrace_link(child, current->parent, current->ptracer_cred);

		if (child->ptrace & PT_SEIZED)
			kgr_task_set_jobctl_pending(child, JOBCTL_TRAP_STOP);
		else
			sigaddset(&child->pending.signal, SIGSTOP);

		set_tsk_thread_flag(child, TIF_SIGPENDING);
	}
	else
		child->ptracer_cred = NULL;
}

/* from include/linux/audit.h */
/* line 151 */
static inline void kgr_audit_free(struct task_struct *task)
{
	if (unlikely(task->audit_context))
		kgr__audit_free(task);
}

/* from arch/x86/include/asm/tlbflush.h */
#define kgr_flush_tlb_mm(mm)					\
	kgr_flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL)


/* from kernel/fork.c */
/* line 139 */
/* inlined */
static inline struct task_struct *kgr_alloc_task_struct_node(int node)
{
	return kmem_cache_alloc_node(*kgr_task_struct_cachep, GFP_KERNEL, node);
}

/* inlined */
static inline void kgr_free_task_struct(struct task_struct *tsk)
{
	kmem_cache_free(*kgr_task_struct_cachep, tsk);
}

/* line 161 */
/* inlined */
static struct thread_info *kgr_alloc_thread_info_node(struct task_struct *tsk,
						      int node)
{
	struct page *page = kgr_alloc_kmem_pages_node(node, THREADINFO_GFP,
						      THREAD_SIZE_ORDER);

	return page ? page_address(page) : NULL;
}

/* line 241 */
/* inlined */
static inline void kgr_free_signal_struct(struct signal_struct *sig)
{
	kgr_taskstats_tgid_free(sig);
	sched_autogroup_exit(sig);
	kmem_cache_free(*kgr_signal_cachep, sig);
}

/* line 398 */
/* inlined */
static int kgr_dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;

	kgr_uprobe_start_dup_mmap();
	down_write(&oldmm->mmap_sem);
	flush_cache_dup_mm(oldmm);
	kgr_uprobe_dup_mmap(oldmm, mm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/* No ordering required: file already has been exposed. */
	RCU_INIT_POINTER(mm->exe_file, get_mm_exe_file(oldmm));

	mm->total_vm = oldmm->total_vm;
	mm->shared_vm = oldmm->shared_vm;
	mm->exec_vm = oldmm->exec_vm;
	mm->stack_vm = oldmm->stack_vm;

	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;
	retval = kgr_ksm_fork(mm, oldmm);
	if (retval)
		goto out;
	retval = kgr_khugepaged_fork(mm, oldmm);
	if (retval)
		goto out;

	prev = NULL;
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct file *file;

		if (mpnt->vm_flags & VM_DONTCOPY) {
			kgr_vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
							-vma_pages(mpnt));
			continue;
		}
		charge = 0;
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned long len = vma_pages(mpnt);

			if (kgr_security_vm_enough_memory_mm(oldmm, len)) /* sic */
				goto fail_nomem;
			charge = len;
		}
		tmp = kmem_cache_alloc(*kgr_vm_area_cachep, GFP_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		INIT_LIST_HEAD(&tmp->anon_vma_chain);
		retval = kgr_vma_dup_policy(mpnt, tmp);
		if (retval)
			goto fail_nomem_policy;
		tmp->vm_mm = mm;
		if (kgr_anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;
		tmp->vm_flags &=
			~(VM_LOCKED|VM_LOCKONFAULT|VM_UFFD_MISSING|VM_UFFD_WP);
		tmp->vm_next = tmp->vm_prev = NULL;
		tmp->vm_userfaultfd_ctx = NULL_VM_UFFD_CTX;
		file = tmp->vm_file;
		if (file) {
			struct inode *inode = file_inode(file);
			struct address_space *mapping = file->f_mapping;

			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);
			i_mmap_lock_write(mapping);
			if (tmp->vm_flags & VM_SHARED)
				atomic_inc(&mapping->i_mmap_writable);
			flush_dcache_mmap_lock(mapping);
			/* insert tmp into the share list, just after mpnt */
			kgr_vma_interval_tree_insert_after(tmp, mpnt,
					&mapping->i_mmap);
			flush_dcache_mmap_unlock(mapping);
			i_mmap_unlock_write(mapping);
		}

		/*
		 * Clear hugetlb-related page reserves for children. This only
		 * affects MAP_PRIVATE mappings. Faults generated by the child
		 * are not guaranteed to succeed, even if read-only
		 */
		if (is_vm_hugetlb_page(tmp))
			kgr_reset_vma_resv_huge_pages(tmp);

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		kgr__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		retval = kgr_copy_page_range(mm, oldmm, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	/* a new mm has just been created */
	arch_dup_mmap(oldmm, mm);
	retval = 0;
out:
	up_write(&mm->mmap_sem);
	kgr_flush_tlb_mm(oldmm);
	up_write(&oldmm->mmap_sem);
	kgr_uprobe_end_dup_mmap();
	return retval;
fail_nomem_anon_vma_fork:
	kgr_mpol_put(vma_policy(tmp));
fail_nomem_policy:
	kmem_cache_free(*kgr_vm_area_cachep, tmp);
fail_nomem:
	retval = -ENOMEM;
	kgr_vm_unacct_memory(charge);
	goto out;
}

/* line 559 */
#define kgr_allocate_mm()	(kmem_cache_alloc(*kgr_mm_cachep, GFP_KERNEL))
#define kgr_free_mm(mm)	(kmem_cache_free(*kgr_mm_cachep, (mm)))

/* line 939 */
/* inlined */
static struct mm_struct * kgr_dup_mm(struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm = current->mm;
	int err;

	mm = kgr_allocate_mm();
	if (!mm)
		goto fail_nomem;

	memcpy(mm, oldmm, sizeof(*mm));

	if (!kgr_mm_init(mm, tsk, mm->user_ns))
		goto fail_nomem;

	err = kgr_dup_mmap(mm, oldmm);
	if (err)
		goto free_pt;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (mm->binfmt && !try_module_get(mm->binfmt->module))
		goto free_pt;

	return mm;

free_pt:
	/* don't put binfmt in mmput, we haven't got module yet */
	mm->binfmt = NULL;
	mmput(mm);

fail_nomem:
	return NULL;
}


/* line 974 */
/* inlined */
static int kgr_copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;
	int retval;

	tsk->min_flt = tsk->maj_flt = 0;
	tsk->nvcsw = tsk->nivcsw = 0;
#ifdef CONFIG_DETECT_HUNG_TASK
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;
#endif

	tsk->mm = NULL;
	tsk->active_mm = NULL;

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	oldmm = current->mm;
	if (!oldmm)
		return 0;

	/* initialize the new vmacache entries */
	vmacache_flush(tsk);

	if (clone_flags & CLONE_VM) {
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		goto good_mm;
	}

	retval = -ENOMEM;
	mm = kgr_dup_mm(tsk);
	if (!mm)
		goto fail_nomem;

good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;

fail_nomem:
	return retval;
}

/* line 1020 */
/* inlined */
static int kgr_copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
	struct fs_struct *fs = current->fs;
	if (clone_flags & CLONE_FS) {
		/* tsk->fs is already what we want */
		spin_lock(&fs->lock);
		if (fs->in_exec) {
			spin_unlock(&fs->lock);
			return -EAGAIN;
		}
		fs->users++;
		spin_unlock(&fs->lock);
		return 0;
	}
	tsk->fs = kgr_copy_fs_struct(fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}

/* line 1049 */
/* inlined */
static int kgr_copy_files(unsigned long clone_flags, struct task_struct *tsk)
{
	struct files_struct *oldf, *newf;
	int error = 0;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	newf = kgr_dup_fd(oldf, &error);
	if (!newf)
		goto out;

	tsk->files = newf;
	error = 0;
out:
	return error;
}

/* inlined */
/* line 1067 */
static int kgr_copy_io(unsigned long clone_flags, struct task_struct *tsk)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc = current->io_context;
	struct io_context *new_ioc;

	if (!ioc)
		return 0;
	/*
	 * Share io context with parent, if CLONE_IO is set
	 */
	if (clone_flags & CLONE_IO) {
		ioc_task_link(ioc);
		tsk->io_context = ioc;
	} else if (ioprio_valid(ioc->ioprio)) {
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);
		if (unlikely(!new_ioc))
			return -ENOMEM;

		new_ioc->ioprio = ioc->ioprio;
		put_io_context(new_ioc);
	}
#endif
	return 0;
}

/* inlined */
/* line 1110 */

static int kgr_copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sighand_struct *sig;

	if (clone_flags & CLONE_SIGHAND) {
		atomic_inc(&current->sighand->count);
		return 0;
	}
	sig = kmem_cache_alloc(*kgr_sighand_cachep, GFP_KERNEL);
	rcu_assign_pointer(tsk->sighand, sig);
	if (!sig)
		return -ENOMEM;

	atomic_set(&sig->count, 1);
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
	return 0;
}

/* inlined */

/* line 1141 */
static void kgr_posix_cpu_timers_init_group(struct signal_struct *sig)
{
	unsigned long cpu_limit;

	cpu_limit = READ_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);
	if (cpu_limit != RLIM_INFINITY) {
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit);
		sig->cputimer.running = true;
	}

	/* The timer lists. */
	INIT_LIST_HEAD(&sig->cpu_timers[0]);
	INIT_LIST_HEAD(&sig->cpu_timers[1]);
	INIT_LIST_HEAD(&sig->cpu_timers[2]);
}

/* inlined */
/* line 1142 */
static int kgr_copy_signal(unsigned long clone_flags, struct task_struct *tsk)
{
	struct signal_struct *sig;

	if (clone_flags & CLONE_THREAD)
		return 0;

	sig = kmem_cache_zalloc(*kgr_signal_cachep, GFP_KERNEL);
	tsk->signal = sig;
	if (!sig)
		return -ENOMEM;

	sig->nr_threads = 1;
	atomic_set(&sig->live, 1);
	atomic_set(&sig->sigcnt, 1);

	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node);
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head);

	init_waitqueue_head(&sig->wait_chldexit);
	sig->curr_target = tsk;
	init_sigpending(&sig->shared_pending);
	INIT_LIST_HEAD(&sig->posix_timers);
	seqlock_init(&sig->stats_lock);
	prev_cputime_init(&sig->prev_cputime);

	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sig->real_timer.function = kgr_it_real_fn;

	task_lock(current->group_leader);
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
	task_unlock(current->group_leader);

	kgr_posix_cpu_timers_init_group(sig);

	kgr_tty_audit_fork(sig);
	sched_autogroup_fork(sig);

	sig->oom_score_adj = current->signal->oom_score_adj;
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;

	mutex_init(&sig->cred_guard_mutex);

	return 0;
}

/* line 1221 */
/* inlined */
static void kgr_copy_seccomp(struct task_struct *p)
{
#ifdef CONFIG_SECCOMP
	/*
	 * Must be called with sighand->lock held, which is common to
	 * all threads in the group. Holding cred_guard_mutex is not
	 * needed because this new task is not yet running and cannot
	 * be racing exec.
	 */
	assert_spin_locked(&current->sighand->siglock);

	/* Ref-count the new filter user, and assign it. */
	kgr_get_seccomp_filter(current);
	p->seccomp = current->seccomp;

	/*
	 * Explicitly enable no_new_privs here in case it got set
	 * between the task_struct being duplicated and holding the
	 * sighand lock. The seccomp state and nnp must be in sync.
	 */
	if (task_no_new_privs(current))
		task_set_no_new_privs(p);

	/*
	 * If the parent gained a seccomp mode after copying thread
	 * flags and between before we held the sighand lock, we have
	 * to manually enable the seccomp thread flag here.
	 */
	if (p->seccomp.mode != SECCOMP_MODE_DISABLED)
		set_tsk_thread_flag(p, TIF_SECCOMP);
#endif
}

/* line 1238 */
/* inlined */
static void kgr_rt_mutex_init_task(struct task_struct *p)
{
	raw_spin_lock_init(&p->pi_lock);
#ifdef CONFIG_RT_MUTEXES
	p->pi_waiters = RB_ROOT;
	p->pi_waiters_leftmost = NULL;
	p->pi_blocked_on = NULL;
#endif
}

/* line 1251 */
/* inlined */
static void kgr_posix_cpu_timers_init(struct task_struct *tsk)
{
	tsk->cputime_expires.prof_exp = 0;
	tsk->cputime_expires.virt_exp = 0;
	tsk->cputime_expires.sched_exp = 0;
	INIT_LIST_HEAD(&tsk->cpu_timers[0]);
	INIT_LIST_HEAD(&tsk->cpu_timers[1]);
	INIT_LIST_HEAD(&tsk->cpu_timers[2]);
}

/* line 1257 */
/* inlined */
static inline void
kgr_init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
	 task->pids[type].pid = pid;
}



static void *pending_forks = &pending_forks;

/* New */
static void add_pending_fork(struct task_struct *t)
{
	write_lock(kgr_tasklist_lock);
	t->suse_kabi_padding = pending_forks;
	pending_forks = &t->suse_kabi_padding;
	write_unlock(kgr_tasklist_lock);
}

/* New */
static void ___remove_pending_fork(struct task_struct *t)
{
	void *prev, *cur;
	struct task_struct *cur_task;

	prev = &pending_forks;
	cur = pending_forks;
	while (cur != &pending_forks) {
		cur_task = container_of(cur, struct task_struct,
					suse_kabi_padding);
		if (cur_task == t) {
			*(void **)prev = t->suse_kabi_padding;
			t->suse_kabi_padding = NULL;
			break;
		}

		prev = cur;
		cur = cur_task->suse_kabi_padding;
	}
}

/* New */
static void __remove_pending_fork(struct task_struct *t)
{
	if (likely(!t->suse_kabi_padding))
		return;

	___remove_pending_fork(t);
}

/* New */
static void remove_pending_fork(struct task_struct *t)
{

	if (likely(!t->suse_kabi_padding))
		return;

	write_lock(kgr_tasklist_lock);
	if (likely(t->suse_kabi_padding))
		___remove_pending_fork(t);
	write_unlock(kgr_tasklist_lock);
}


/* Patched, inlined */
static inline void kgr_free_thread_info(struct thread_info *ti)
{
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	kgr_kaiser_unmap_thread_stack(ti);
	kgr_free_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER);
}

/* Patched, calls inlined free_thread_info() */
void kgr_free_task(struct task_struct *tsk)
{
	kgr_account_kernel_stack(tsk->stack, -1);
	kgr_arch_release_thread_info(tsk->stack);
	kgr_free_thread_info(tsk->stack);
	rt_mutex_debug_task_free(tsk);
	kgr_ftrace_graph_exit_task(tsk);
	kgr_put_seccomp_filter(tsk);
	kgr_arch_release_task_struct(tsk);
	kgr_free_task_struct(tsk);
}

/* Patched, inlined */
static struct task_struct *kgr_dup_task_struct(struct task_struct *orig,
					       int node)
{
	struct task_struct *tsk;
	struct thread_info *ti;
	int err;
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	enum patch_state ps;

	if (node == NUMA_NO_NODE)
		node = kgr_tsk_fork_get_node(orig);
	tsk = kgr_alloc_task_struct_node(node);
	if (!tsk)
		return NULL;

	ti = kgr_alloc_thread_info_node(tsk, node);
	if (!ti)
		goto free_tsk;

	err = kgr_arch_dup_task_struct(tsk, orig);
	if (err)
		goto free_ti;

	tsk->stack = ti;

	/*
	 * Fix CVE-2017-5754
	 *  +12 lines
	 */
	ps = kgr_meltdown_patch_state();
	if (ps >= ps_activating) {
		err = kgr_kaiser_map_thread_stack(tsk->stack);
		if (err)
			goto free_ti;
	} else if (ps == ps_enabled) {
		/*
		 * Make sure that kgr_kaiser_map_all_thread_stacks()
		 * will find us.
		 */
		add_pending_fork(tsk);
	}

#ifdef CONFIG_SECCOMP
	/*
	 * We must handle setting up seccomp filters once we're under
	 * the sighand lock in case orig has changed between now and
	 * then. Until then, filter must be NULL to avoid messing up
	 * the usage counts on the error path calling free_task.
	 */
	tsk->seccomp.filter = NULL;
#endif

	setup_thread_stack(tsk, orig);
	clear_user_return_notifier(tsk);
	clear_tsk_need_resched(tsk);
	kgr_set_task_stack_end_magic(tsk);

#ifdef CONFIG_CC_STACKPROTECTOR
	tsk->stack_canary = get_random_long();
#endif

	/*
	 * One for us, one for whoever does the "release_task()" (usually
	 * parent)
	 */
	atomic_set(&tsk->usage, 2);
#ifdef CONFIG_BLK_DEV_IO_TRACE
	tsk->btrace_seq = 0;
#endif
	tsk->splice_pipe = NULL;
	tsk->task_frag.page = NULL;
	tsk->wake_q.next = NULL;

	kgr_account_kernel_stack(ti, 1);

	return tsk;

free_ti:
	kgr_free_thread_info(ti);
free_tsk:
	kgr_free_task_struct(tsk);
	return NULL;
}


/* Patched, calls inlined dup_task_struct() */
struct task_struct *kgr_copy_process(unsigned long clone_flags,
				     unsigned long stack_start,
				     unsigned long stack_size,
				     int __user *child_tidptr,
				     struct pid *pid,
				     int trace,
				     unsigned long tls,
				     int node)
{
	int retval;
	struct task_struct *p;
	void *cgrp_ss_priv[CGROUP_CANFORK_COUNT] = {};

	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	/*
	 * Siblings of global init remain as zombies on exit since they are
	 * not reaped by their parent (swapper). To solve this and to avoid
	 * multi-rooted process trees, prevent global and container-inits
	 * from creating siblings.
	 */
	if ((clone_flags & CLONE_PARENT) &&
				current->signal->flags & SIGNAL_UNKILLABLE)
		return ERR_PTR(-EINVAL);

	/*
	 * If the new process will be in a different pid or user namespace
	 * do not allow it to share a thread group with the forking task.
	 */
	if (clone_flags & CLONE_THREAD) {
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
		    (task_active_pid_ns(current) !=
				current->nsproxy->pid_ns_for_children))
			return ERR_PTR(-EINVAL);
	}

	retval = kgr_security_task_create(clone_flags);
	if (retval)
		goto fork_out;

	retval = -ENOMEM;
	p = kgr_dup_task_struct(current, node);
	if (!p)
		goto fork_out;

	kgr_ftrace_graph_init_task(p);

	kgr_rt_mutex_init_task(p);

#ifdef CONFIG_PROVE_LOCKING
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif
	retval = -EAGAIN;
	if (atomic_read(&p->real_cred->user->processes) >=
			task_rlimit(p, RLIMIT_NPROC)) {
		if (p->real_cred->user != kgr_root_user &&
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
			goto bad_fork_free;
	}
	current->flags &= ~PF_NPROC_EXCEEDED;

	retval = kgr_copy_creds(p, clone_flags);
	if (retval < 0)
		goto bad_fork_free;

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
	retval = -EAGAIN;
	if (*kgr_nr_threads >= *kgr_max_threads)
		goto bad_fork_cleanup_count;

	kgr_delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */
	p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER);
	p->flags |= PF_FORKNOEXEC;
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	rcu_copy_process(p);
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);

	init_sigpending(&p->pending);

	p->utime = p->stime = p->gtime = 0;
	p->utimescaled = p->stimescaled = 0;
	prev_cputime_init(&p->prev_cputime);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqcount_init(&p->vtime_seqcount);
	p->vtime_snap = 0;
	p->vtime_snap_whence = VTIME_INACTIVE;
#endif

#if defined(SPLIT_RSS_COUNTING)
	memset(&p->rss_stat, 0, sizeof(p->rss_stat));
#endif

	p->default_timer_slack_ns = current->timer_slack_ns;

	task_io_accounting_init(&p->ioac);
	kgr_acct_clear_integrals(p);

	kgr_posix_cpu_timers_init(p);

	p->start_time = ktime_get_ns();
	p->real_start_time = ktime_get_boot_ns();
	p->io_context = NULL;
	p->audit_context = NULL;
	kgr_cgroup_fork(p);
#ifdef CONFIG_NUMA
	p->mempolicy = kgr_mpol_dup(p->mempolicy);
	if (IS_ERR(p->mempolicy)) {
		retval = PTR_ERR(p->mempolicy);
		p->mempolicy = NULL;
		goto bad_fork_cleanup_threadgroup_lock;
	}
#endif
#ifdef CONFIG_CPUSETS
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE;
	seqcount_init(&p->mems_allowed_seq);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	p->irq_events = 0;
	p->hardirqs_enabled = 0;
	p->hardirq_enable_ip = 0;
	p->hardirq_enable_event = 0;
	p->hardirq_disable_ip = _THIS_IP_;
	p->hardirq_disable_event = 0;
	p->softirqs_enabled = 1;
	p->softirq_enable_ip = _THIS_IP_;
	p->softirq_enable_event = 0;
	p->softirq_disable_ip = 0;
	p->softirq_disable_event = 0;
	p->hardirq_context = 0;
	p->softirq_context = 0;
#endif

	p->pagefault_disabled = 0;

#ifdef CONFIG_LOCKDEP
	p->lockdep_depth = 0; /* no locks held yet */
	p->curr_chain_key = 0;
	p->lockdep_recursion = 0;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	p->blocked_on = NULL; /* not blocked yet */
#endif
#ifdef CONFIG_BCACHE
	p->sequential_io	= 0;
	p->sequential_io_avg	= 0;
#endif

	/* Perform scheduler related setup. Assign this task to a CPU. */
	retval = kgr_sched_fork(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_policy;

	retval = kgr_perf_event_init_task(p);
	if (retval)
		goto bad_fork_cleanup_policy;
	retval = kgr_audit_alloc(p);
	if (retval)
		goto bad_fork_cleanup_perf;
	/* copy all the process information */
	shm_init_task(p);
	retval = kgr_copy_semundo(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_audit;
	retval = kgr_copy_files(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_semundo;
	retval = kgr_copy_fs(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_files;
	retval = kgr_copy_sighand(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_fs;
	retval = kgr_copy_signal(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_sighand;
	retval = kgr_copy_mm(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_signal;
	retval = kgr_copy_namespaces(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_mm;
	retval = kgr_copy_io(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_namespaces;
	retval = kgr_copy_thread_tls(clone_flags, stack_start, stack_size, p,
				     tls);
	if (retval)
		goto bad_fork_cleanup_io;

	if (pid != kgr_init_struct_pid) {
		pid = kgr_alloc_pid(p->nsproxy->pid_ns_for_children);
		if (IS_ERR(pid)) {
			retval = PTR_ERR(pid);
			goto bad_fork_cleanup_thread;
		}
	}

	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;
#ifdef CONFIG_BLOCK
	p->plug = NULL;
#endif
#ifdef CONFIG_FUTEX
	p->robust_list = NULL;
#ifdef CONFIG_COMPAT
	p->compat_robust_list = NULL;
#endif
	INIT_LIST_HEAD(&p->pi_state_list);
	p->pi_state_cache = NULL;
#endif
	/*
	 * sigaltstack should be cleared when sharing the same VM
	 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		p->sas_ss_sp = p->sas_ss_size = 0;

	/*
	 * Syscall tracing and stepping should be turned off in the
	 * child regardless of CLONE_PTRACE.
	 */
	kgr_user_disable_single_step(p);
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);
#ifdef TIF_SYSCALL_EMU
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif
	kgr_clear_all_latency_tracing(p);

	/* ok, now we should be set up.. */
	p->pid = pid_nr(pid);
	if (clone_flags & CLONE_THREAD) {
		p->exit_signal = -1;
		p->group_leader = current->group_leader;
		p->tgid = current->tgid;
	} else {
		if (clone_flags & CLONE_PARENT)
			p->exit_signal = current->group_leader->exit_signal;
		else
			p->exit_signal = (clone_flags & CSIGNAL);
		p->group_leader = p;
		p->tgid = p->pid;
	}

	p->nr_dirtied = 0;
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
	p->dirty_paused_when = 0;

	p->pdeath_signal = 0;
	INIT_LIST_HEAD(&p->thread_group);
	p->task_works = NULL;

	kgr_threadgroup_change_begin(current);
	/*
	 * Ensure that the cgroup subsystem policies allow the new process to be
	 * forked. It should be noted the the new process's css_set can be changed
	 * between here and cgroup_post_fork() if an organisation operation is in
	 * progress.
	 */
	retval = kgr_cgroup_can_fork(p, cgrp_ss_priv);
	if (retval)
		goto bad_fork_free_pid;

	/*
	 * Make it visible to the rest of the system, but dont wake it up yet.
	 * Need tasklist lock for parent etc handling!
	 */
	write_lock_irq(kgr_tasklist_lock);
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	__remove_pending_fork(p);

	/* CLONE_PARENT re-uses the old parent */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
		p->real_parent = current->real_parent;
		p->parent_exec_id = current->parent_exec_id;
	} else {
		p->real_parent = current;
		p->parent_exec_id = current->self_exec_id;
	}

	spin_lock(&current->sighand->siglock);

	/*
	 * Copy seccomp details explicitly here, in case they were changed
	 * before holding sighand lock.
	 */
	kgr_copy_seccomp(p);

	/*
	 * Process group and session signals need to be delivered to just the
	 * parent before the fork or both the parent and the child after the
	 * fork. Restart if a signal comes in before we add the new process to
	 * it's process group.
	 * A fatal signal pending means that current will exit, so the new
	 * thread can't slip out of an OOM kill (or normal SIGKILL).
	*/
	recalc_sigpending();
	if (signal_pending(current)) {
		retval = -ERESTARTNOINTR;
		goto bad_fork_cancel_cgroup;
	}
	if (unlikely(!(ns_of_pid(pid)->nr_hashed & PIDNS_HASH_ADDING))) {
		retval = -ENOMEM;
		goto bad_fork_cancel_cgroup;
	}

	if (likely(p->pid)) {
		kgr_ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);

		kgr_init_task_pid(p, PIDTYPE_PID, pid);
		if (thread_group_leader(p)) {
			kgr_init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));
			kgr_init_task_pid(p, PIDTYPE_SID, task_session(current));

			if (is_child_reaper(pid)) {
				ns_of_pid(pid)->child_reaper = p;
				p->signal->flags |= SIGNAL_UNKILLABLE;
			}

			p->signal->leader_pid = pid;
			p->signal->tty = tty_kref_get(current->signal->tty);
			/*
			 * Inherit has_child_subreaper flag under the same
			 * tasklist_lock with adding child to the process tree
			 * for propagate_has_child_subreaper optimization.
			 */
			p->signal->has_child_subreaper = p->real_parent->signal->has_child_subreaper ||
							 p->real_parent->signal->is_child_subreaper;
			list_add_tail(&p->sibling, &p->real_parent->children);
			list_add_tail_rcu(&p->tasks, &init_task.tasks);
			kgr_attach_pid(p, PIDTYPE_PGID);
			kgr_attach_pid(p, PIDTYPE_SID);
			asm volatile ("incq (%0)"
				:
				: "r" (this_cpu_ptr(kgr_process_counts)));
			/* __this_cpu_inc(*process_counts); */
		} else {
			current->signal->nr_threads++;
			atomic_inc(&current->signal->live);
			atomic_inc(&current->signal->sigcnt);
			list_add_tail_rcu(&p->thread_group,
					  &p->group_leader->thread_group);
			list_add_tail_rcu(&p->thread_node,
					  &p->signal->thread_head);
		}
		kgr_attach_pid(p, PIDTYPE_PID);
		(*kgr_nr_threads)++;
	}

	(*kgr_total_forks)++;
	spin_unlock(&current->sighand->siglock);
	syscall_tracepoint_update(p);
	write_unlock_irq(kgr_tasklist_lock);

	kgr_proc_fork_connector(p);
	kgr_cgroup_post_fork(p, cgrp_ss_priv);
	kgr_threadgroup_change_end(current);
	kgr_perf_event_fork(p);

	kgr_trace_task_newtask(p, clone_flags);
	kgr_uprobe_copy_process(p, clone_flags);

	return p;

bad_fork_cancel_cgroup:
	spin_unlock(&current->sighand->siglock);
	write_unlock_irq(kgr_tasklist_lock);
	kgr_cgroup_cancel_fork(p, cgrp_ss_priv);
bad_fork_free_pid:
	kgr_threadgroup_change_end(current);
	if (pid != kgr_init_struct_pid)
		kgr_free_pid(pid);
bad_fork_cleanup_thread:
	kgr_exit_thread(p);
bad_fork_cleanup_io:
	if (p->io_context)
		kgr_exit_io_context(p);
bad_fork_cleanup_namespaces:
	kgr_exit_task_namespaces(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	if (!(clone_flags & CLONE_THREAD))
		kgr_free_signal_struct(p->signal);
bad_fork_cleanup_sighand:
	kgr__cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
	kgr_exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	kgr_exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	kgr_exit_sem(p);
bad_fork_cleanup_audit:
	kgr_audit_free(p);
bad_fork_cleanup_perf:
	kgr_perf_event_free_task(p);
bad_fork_cleanup_policy:
#ifdef CONFIG_NUMA
	kgr_mpol_put(p->mempolicy);
bad_fork_cleanup_threadgroup_lock:
#endif
	kgr_delayacct_tsk_free(p);
bad_fork_cleanup_count:
	atomic_dec(&p->cred->user->processes);
	kgr_exit_creds(p);
bad_fork_free:
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	remove_pending_fork(p);
	free_task(p);
fork_out:
	return ERR_PTR(retval);
}


extern rwlock_t *kgr_tasklist_lock;

int kgr_kaiser_map_all_thread_stacks(void)
{
	struct task_struct *p, *t, *last;
	int ret;
	void *pending;

restart_search:
	last = NULL;
	read_lock(kgr_tasklist_lock);
	for_each_process_thread(p, t) {
		if (t->flags & PF_EXITING)
			continue;

		if (kgr_kaiser_is_thread_stack_mapped((void *)t->stack))
			continue;

		get_task_struct(t);
		read_unlock(kgr_tasklist_lock);

		if (last)
			put_task_struct(last);
		last = t;

		ret = kgr_kaiser_map_thread_stack((void *)t->stack);
		if (ret) {
			put_task_struct(t);
			return ret;
		}

		cond_resched();

		/* Try to continue with the search */
		read_lock(kgr_tasklist_lock);
		if (!t->sighand) {
			read_unlock(kgr_tasklist_lock);
			put_task_struct(t);
			goto restart_search;
		}
	}
	read_unlock(kgr_tasklist_lock);

	if (last) {
		put_task_struct(last);

		/*
		 * We dropped out of tasklist_lock at least
		 * once. Restart the search once again in order to
		 * make sure that we don't miss any new member.
		 */
		goto restart_search;
	}

	/*
	 * Process the pending forks now which might not have seen
	 * ps_activating and haven't made it onto the global tasklist
	 * yet.
	 */
	read_lock(kgr_tasklist_lock);
	pending = pending_forks;
	while (pending != &pending_forks) {
		t = container_of(pending, struct task_struct,
				 suse_kabi_padding);
		pending_forks = t->suse_kabi_padding;
		t->suse_kabi_padding = NULL;
		get_task_struct(t);
		read_unlock(kgr_tasklist_lock);

		ret = kgr_kaiser_map_thread_stack((void *)t->stack);
		put_task_struct(t);
		if (ret)
			return ret;

		read_lock(kgr_tasklist_lock);
		pending = pending_forks;
	}
	read_unlock(kgr_tasklist_lock);

	return 0;
}
