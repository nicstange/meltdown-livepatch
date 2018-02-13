#include <linux/rwsem.h>
#include <asm/mmu_context.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/vmacache.h>
#include <asm/processor.h>
#include "exec.h"
#include "kaiser.h"
#include "shared_data.h"

#if !defined(SPLIT_RSS_COUNTING)
#error "Livepatch supports only defined(SPLIT_RSS_COUNTING)"
#endif

#if !IS_ENABLED(CONFIG_MEMCG)
#error "Livepatch supports only CONFIG_MEMCG=y"
#endif

#if !IS_ENABLED(CONFIG_PERF_EVENTS)
#error "Livepatch supports only CONFIG_PERF_EVENTS=y"
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

#define KGR_DECLARE_TRACE_CONDITION(name, proto, args, cond)		\
	__KGR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
		cpu_online(raw_smp_processor_id()) && (PARAMS(cond)),	\
		PARAMS(void *__data, proto),				\
		PARAMS(__data, args))

#define KGR_TRACE_EVENT_CONDITION(name, proto, args, cond)		\
	KGR_DECLARE_TRACE_CONDITION(name, PARAMS(proto),		\
				    PARAMS(args), PARAMS(cond))


struct tracepoint *kgr__tracepoint_tlb_flush;

KGR_TRACE_EVENT_CONDITION(tlb_flush,
	TP_PROTO(int reason, unsigned long pages),
	TP_ARGS(reason, pages),
	TP_CONDITION(cpu_online(smp_processor_id())))


struct static_key *kgr_rdpmc_always_available;

void (*kgr_mm_release)(struct task_struct *tsk, struct mm_struct *mm);
void (*kgr_sync_mm_rss)(struct mm_struct *mm);
void (*kgr_mm_update_next_owner)(struct mm_struct *mm);
int (*kgr_zap_other_threads)(struct task_struct *p);
void (*kgr_change_pid)(struct task_struct *task, enum pid_type type,
		       struct pid *pid);
void (*kgr_transfer_pid)(struct task_struct *old, struct task_struct *new,
			 enum pid_type type);
void (*kgr__wake_up_parent)(struct task_struct *p, struct task_struct *parent);
void (*kgr_release_task)(struct task_struct *p);
void (*kgr_exit_itimers)(struct signal_struct *sig);
void (*kgr_flush_itimer_signals)(void);
void (*kgr_set_mm_exe_file)(struct mm_struct *mm, struct file *new_exe_file);
void (*kgr_flush_thread)(void);
void (*kgr_do_close_on_exec)(struct files_struct *files);

extern rwlock_t *kgr_tasklist_lock;
extern struct kmem_cache **kgr_sighand_cachep;
extern struct percpu_rw_semaphore *kgr_cgroup_threadgroup_rwsem;
extern void (*kgr__cleanup_sighand)(struct sighand_struct *sighand);

/* from arch/x86/include/asm/mmu_context.h */
/* line 25 */
/* inlined */
static inline void kgr_load_mm_cr4(struct mm_struct *mm)
{
	if (static_key_enabled(kgr_rdpmc_always_available) ||
	    atomic_read(&mm->context.perf_rdpmc_allowed))
		cr4_set_bits(X86_CR4_PCE);
	else
		cr4_clear_bits(X86_CR4_PCE);
}

/* from include/linux/cgroup-defs.h */
/* line 511 */
static inline void kgr_cgroup_threadgroup_change_begin(struct task_struct *tsk)
{
	percpu_down_read(kgr_cgroup_threadgroup_rwsem);
}

static inline void kgr_cgroup_threadgroup_change_end(struct task_struct *tsk)
{
	percpu_up_read(kgr_cgroup_threadgroup_rwsem);
}


/* from include/linux/sched.h */
/* line 2900 */
static inline void kgr_threadgroup_change_begin(struct task_struct *tsk)
{
	might_sleep();
	kgr_cgroup_threadgroup_change_begin(tsk);
}

static inline void kgr_threadgroup_change_end(struct task_struct *tsk)
{
	kgr_cgroup_threadgroup_change_end(tsk);
}


/* from fs/exec.c */
/* line 188 */
/* optimized */
static void kgr_acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

/* line 924 */
/* inlined */
static int kgr_de_thread(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *oldsighand = tsk->sighand;
	spinlock_t *lock = &oldsighand->siglock;

	if (thread_group_empty(tsk))
		goto no_thread_group;

	/*
	 * Kill all other threads in the thread group.
	 */
	spin_lock_irq(lock);
	if (signal_group_exit(sig)) {
		/*
		 * Another group action in progress, just
		 * return so that the signal is processed.
		 */
		spin_unlock_irq(lock);
		return -EAGAIN;
	}

	sig->group_exit_task = tsk;
	sig->notify_count = kgr_zap_other_threads(tsk);
	if (!thread_group_leader(tsk))
		sig->notify_count--;

	while (sig->notify_count) {
		__set_current_state(TASK_KILLABLE);
		spin_unlock_irq(lock);
		schedule();
		if (unlikely(__fatal_signal_pending(tsk)))
			goto killed;
		spin_lock_irq(lock);
	}
	spin_unlock_irq(lock);

	/*
	 * At this point all other threads have exited, all we have to
	 * do is to wait for the thread group leader to become inactive,
	 * and to assume its PID:
	 */
	if (!thread_group_leader(tsk)) {
		struct task_struct *leader = tsk->group_leader;

		for (;;) {
			kgr_threadgroup_change_begin(tsk);
			write_lock_irq(kgr_tasklist_lock);
			/*
			 * Do this under tasklist_lock to ensure that
			 * exit_notify() can't miss ->group_exit_task
			 */
			sig->notify_count = -1;
			if (likely(leader->exit_state))
				break;
			__set_current_state(TASK_KILLABLE);
			write_unlock_irq(kgr_tasklist_lock);
			kgr_threadgroup_change_end(tsk);
			schedule();
			if (unlikely(__fatal_signal_pending(tsk)))
				goto killed;
		}

		/*
		 * The only record we have of the real-time age of a
		 * process, regardless of execs it's done, is start_time.
		 * All the past CPU time is accumulated in signal_struct
		 * from sister threads now dead.  But in this non-leader
		 * exec, nothing survives from the original leader thread,
		 * whose birth marks the true age of this process now.
		 * When we take on its identity by switching to its PID, we
		 * also take its birthdate (always earlier than our own).
		 */
		tsk->start_time = leader->start_time;
		tsk->real_start_time = leader->real_start_time;

		BUG_ON(!same_thread_group(leader, tsk));
		BUG_ON(has_group_leader_pid(tsk));
		/*
		 * An exec() starts a new thread group with the
		 * TGID of the previous thread group. Rehash the
		 * two threads with a switched PID, and release
		 * the former thread group leader:
		 */

		/* Become a process group leader with the old leader's pid.
		 * The old leader becomes a thread of the this thread group.
		 * Note: The old leader also uses this pid until release_task
		 *       is called.  Odd but simple and correct.
		 */
		tsk->pid = leader->pid;
		kgr_change_pid(tsk, PIDTYPE_PID, task_pid(leader));
		kgr_transfer_pid(leader, tsk, PIDTYPE_PGID);
		kgr_transfer_pid(leader, tsk, PIDTYPE_SID);

		list_replace_rcu(&leader->tasks, &tsk->tasks);
		list_replace_init(&leader->sibling, &tsk->sibling);

		tsk->group_leader = tsk;
		leader->group_leader = tsk;

		tsk->exit_signal = SIGCHLD;
		leader->exit_signal = -1;

		BUG_ON(leader->exit_state != EXIT_ZOMBIE);
		leader->exit_state = EXIT_DEAD;

		/*
		 * We are going to release_task()->ptrace_unlink() silently,
		 * the tracer can sleep in do_wait(). EXIT_DEAD guarantees
		 * the tracer wont't block again waiting for this thread.
		 */
		if (unlikely(leader->ptrace))
			kgr__wake_up_parent(leader, leader->parent);
		write_unlock_irq(kgr_tasklist_lock);
		kgr_threadgroup_change_end(tsk);

		kgr_release_task(leader);
	}

	sig->group_exit_task = NULL;
	sig->notify_count = 0;

no_thread_group:
	/* we have changed execution domain */
	tsk->exit_signal = SIGCHLD;

	kgr_exit_itimers(sig);
	kgr_flush_itimer_signals();

	if (atomic_read(&oldsighand->count) != 1) {
		struct sighand_struct *newsighand;
		/*
		 * This ->sighand is shared with the CLONE_SIGHAND
		 * but not CLONE_THREAD task, switch to the new one.
		 */
		newsighand = kmem_cache_alloc(*kgr_sighand_cachep, GFP_KERNEL);
		if (!newsighand)
			return -ENOMEM;

		atomic_set(&newsighand->count, 1);
		memcpy(newsighand->action, oldsighand->action,
		       sizeof(newsighand->action));

		write_lock_irq(kgr_tasklist_lock);
		spin_lock(&oldsighand->siglock);
		rcu_assign_pointer(tsk->sighand, newsighand);
		spin_unlock(&oldsighand->siglock);
		write_unlock_irq(kgr_tasklist_lock);

		kgr__cleanup_sighand(oldsighand);
	}

	BUG_ON(!thread_group_leader(tsk));
	return 0;

killed:
	/* protects against exit_notify() and __exit_signal() */
	read_lock(kgr_tasklist_lock);
	sig->group_exit_task = NULL;
	sig->notify_count = 0;
	read_unlock(kgr_tasklist_lock);
	return -EAGAIN;
}


/* Patched */
static inline void kgr_switch_mm(struct mm_struct *prev, struct mm_struct *next,
				 struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
	/*
	 * Fix CVE-2017-5754
	 *  +2 lines
	 */
	pgd_t *user_pgd;
	unsigned long user_cr3, kern_cr3;

	if (likely(prev != next)) {
#ifdef CONFIG_SMP
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		this_cpu_write(cpu_tlbstate.active_mm, next);
#endif
		cpumask_set_cpu(cpu, mm_cpumask(next));

		/*
		 * Re-load page tables.
		 *
		 * This logic has an ordering constraint:
		 *
		 *  CPU 0: Write to a PTE for 'next'
		 *  CPU 0: load bit 1 in mm_cpumask.  if nonzero, send IPI.
		 *  CPU 1: set bit 1 in next's mm_cpumask
		 *  CPU 1: load from the PTE that CPU 0 writes (implicit)
		 *
		 * We need to prevent an outcome in which CPU 1 observes
		 * the new PTE value and CPU 0 observes bit 1 clear in
		 * mm_cpumask.  (If that occurs, then the IPI will never
		 * be sent, and CPU 0's TLB will contain a stale entry.)
		 *
		 * The bad outcome can occur if either CPU's load is
		 * reordered before that CPU's store, so both CPUs must
		 * execute full barriers to prevent this from happening.
		 *
		 * Thus, switch_mm needs a full barrier between the
		 * store to mm_cpumask and any operation that could load
		 * from next->pgd.  TLB fills are special and can happen
		 * due to instruction fetches or for no reason at all,
		 * and neither LOCK nor MFENCE orders them.
		 * Fortunately, load_cr3() is serializing and gives the
		 * ordering guarantee we need.
		 *
		 */
		/*
		 * Fix CVE-2017-5754
		 *  +10 lines
		 */
		user_pgd = NULL;
		if (kgr_meltdown_active())
			user_pgd = kgr_mm_user_pgd(next);
		user_cr3 = kern_cr3 = 0;
		if (user_pgd) {
			user_cr3 = __pa(user_pgd);
			kern_cr3 = __pa(next->pgd);
		}
		kgr_kaiser_set_user_cr3(user_cr3);
		kgr_kaiser_set_kern_cr3(kern_cr3);

		load_cr3(next->pgd);

		kgr_trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);

		/* Stop flush ipis for the previous mm */
		cpumask_clear_cpu(cpu, mm_cpumask(prev));

		/* Load per-mm CR4 state */
		kgr_load_mm_cr4(next);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
		/*
		 * Load the LDT, if the LDT is different.
		 *
		 * It's possible that prev->context.ldt doesn't match
		 * the LDT register.  This can happen if leave_mm(prev)
		 * was called and then modify_ldt changed
		 * prev->context.ldt but suppressed an IPI to this CPU.
		 * In this case, prev->context.ldt != NULL, because we
		 * never set context.ldt to NULL while the mm still
		 * exists.  That means that next->context.ldt !=
		 * prev->context.ldt, because mms never share an LDT.
		 */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_mm_ldt(next);
#endif
	}
#ifdef CONFIG_SMP
	  else {
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(this_cpu_read(cpu_tlbstate.active_mm) != next);

		if (!cpumask_test_cpu(cpu, mm_cpumask(next))) {
			/*
			 * On established mms, the mm_cpumask is only changed
			 * from irq context, from ptep_clear_flush() while in
			 * lazy tlb mode, and here. Irqs are blocked during
			 * schedule, protecting us from simultaneous changes.
			 */
			cpumask_set_cpu(cpu, mm_cpumask(next));

			/*
			 * We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload CR3
			 * to make sure to use no freed page tables.
			 *
			 * As above, load_cr3() is serializing and orders TLB
			 * fills with respect to the mm_cpumask write.
			 */
			load_cr3(next->pgd);
			/*
			 * Fix CVE-2017-5754
			 *  +1 line
			 */
			kaiser_flush_tlb_on_return_to_user();
			kgr_trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);
			kgr_load_mm_cr4(next);
			load_mm_ldt(next);
		}
	}
#endif
}

/* Patched, calls patched switch_mm() macro */
#define kgr_activate_mm(prev, next)		\
do {						\
	paravirt_activate_mm((prev), (next));	\
	kgr_switch_mm((prev), (next), NULL);	\
} while (0);

/* Patched, inlined, calles patched activate_mm() macro */
static int kgr_exec_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk;
	struct mm_struct *old_mm, *active_mm;

	/* Notify parent that we're no longer interested in the old VM */
	tsk = current;
	old_mm = current->mm;
	kgr_mm_release(tsk, old_mm);

	if (old_mm) {
		kgr_sync_mm_rss(old_mm);
		/*
		 * Make sure that if there is a core dump in progress
		 * for the old mm, we get out and die instead of going
		 * through with the exec.  We must hold mmap_sem around
		 * checking core_state and changing tsk->mm.
		 */
		down_read(&old_mm->mmap_sem);
		if (unlikely(old_mm->core_state)) {
			up_read(&old_mm->mmap_sem);
			return -EINTR;
		}
	}
	task_lock(tsk);
	active_mm = tsk->active_mm;
	tsk->mm = mm;
	tsk->active_mm = mm;
	kgr_activate_mm(active_mm, mm);
	tsk->mm->vmacache_seqnum = 0;
	vmacache_flush(tsk);
	task_unlock(tsk);
	if (old_mm) {
		up_read(&old_mm->mmap_sem);
		BUG_ON(active_mm != old_mm);
		setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
		kgr_mm_update_next_owner(old_mm);
		mmput(old_mm);
		return 0;
	}
	mmdrop(active_mm);
	return 0;
}

/* Patched, calls inlined exec_mmap() */
int kgr_flush_old_exec(struct linux_binprm * bprm)
{
	int retval;

	/*
	 * Make sure we have a private signal table and that
	 * we are unassociated from the previous thread group.
	 */
	retval = kgr_de_thread(current);
	if (retval)
		goto out;

	/*
	 * Must be called _before_ exec_mmap() as bprm->mm is
	 * not visibile until then. This also enables the update
	 * to be lockless.
	 */
	kgr_set_mm_exe_file(bprm->mm, bprm->file);

	/*
	 * Release all of the old mmap stuff
	 */
	kgr_acct_arg_size(bprm, 0);
	retval = kgr_exec_mmap(bprm->mm);
	if (retval)
		goto out;

	bprm->mm = NULL;		/* We're using it now */

	set_fs(USER_DS);
	current->flags &= ~(PF_RANDOMIZE | PF_FORKNOEXEC | PF_KTHREAD |
					PF_NOFREEZE | PF_NO_SETAFFINITY);
	kgr_flush_thread();
	current->personality &= ~bprm->per_clear;

	/*
	 * We have to apply CLOEXEC before we change whether the process is
	 * dumpable (in setup_new_exec) to avoid a race with a process in userspace
	 * trying to access the should-be-closed file descriptors of a process
	 * undergoing exec(2).
	 */
	kgr_do_close_on_exec(current->files);
	return 0;

out:
	return retval;
}
