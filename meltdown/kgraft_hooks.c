#include <linux/sched.h>
#include <linux/kgraft.h>
#include <linux/module.h>
#include "kgraft_hooks_kallsyms.h"
#include "kgraft_hooks.h"

struct workqueue_struct **kgr_kgr_wq;
struct delayed_work *kgr_kgr_work;
struct mutex *kgr_kgr_in_progress_lock;
struct list_head *kgr_kgr_patches;
bool __percpu * *kgr_kgr_irq_use_new;
bool *kgr_kgr_in_progress;
bool *kgr_kgr_initialized;
struct kgr_patch **kgr_kgr_patch;
bool *kgr_kgr_revert;
unsigned long (*kgr_kgr_immutable)[];
rwlock_t *kgr_tasklist_lock;

int (*kgr_kgr_patch_code)(struct kgr_patch_fun *patch_fun, bool final,
			  bool revert, bool replace_revert);
bool (*kgr_kgr_patch_contains)(const struct kgr_patch *p,
			const struct kgr_patch_fun *patch_fun);
void (*kgr_kgr_patching_failed)(struct kgr_patch *patch,
			struct kgr_patch_fun *patch_fun, bool process_all);
void (*kgr_kgr_handle_irq_cpu)(struct work_struct *work);

void (*kgr_signal_wake_up_state)(struct task_struct *t, unsigned int state);
int (*kgr_schedule_on_each_cpu)(work_func_t func);


/* from linux/sched.h */
/* calls non-exported signal_wake_up_state() */
static inline void kgr_signal_wake_up(struct task_struct *t, bool resume)
{
	kgr_signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
}


/* from kernel/kgraft.c */
/* inlined */
static void kgr_kgr_refs_inc(void)
{
	struct kgr_patch *p;

	list_for_each_entry(p, kgr_kgr_patches, list)
		p->refs++;
}

/* inlined */
static void kgr_kgr_refs_dec(void)
{
	struct kgr_patch *p;

	list_for_each_entry(p, kgr_kgr_patches, list)
		p->refs--;
}

/* inlined */
static const char *kgr_kgr_get_objname(const struct kgr_patch_fun *pf)
{
	return pf->objname ? pf->objname : "vmlinux";
}

/* inlined */
static bool kgr_kgr_still_patching(void)
{
	struct task_struct *p, *t;
	bool failed = false;

	read_lock(kgr_tasklist_lock);
	for_each_process_thread(p, t) {
		/*
		 * Ignore zombie tasks, that is task with ->state == TASK_DEAD.
		 * We also need to check their ->on_cpu to be sure that they are
		 * not running any code and they are really almost dead.
		 */
		if (klp_kgraft_task_in_progress(t) && (t->state != TASK_DEAD ||
		    t->on_cpu != 0)) {
			failed = true;
			goto unlock;
		}
	}
unlock:
	read_unlock(kgr_tasklist_lock);
	return failed;
}

/* inlined */
static void kgr_kgr_remove_patches_fast(void)
{
	struct kgr_patch *p, *tmp;

	list_for_each_entry_safe(p, tmp, kgr_kgr_patches, list) {
		list_del_init(&p->list);
		module_put(p->owner);
	}
}

/* inlined */
static void kgr_kgr_finalize_replaced_funs(void)
{
	struct kgr_patch_fun *pf;
	struct kgr_patch *p;
	int ret;

	list_for_each_entry(p, kgr_kgr_patches, list)
		kgr_for_each_patch_fun(p, pf) {
			/*
			 * Function was not reverted, but is no longer used.
			 * Mark it as reverted so the user would not be confused
			 * by sysfs reporting of states.
			 */
			if (pf->state == KGR_PATCH_APPLIED) {
				pf->state = KGR_PATCH_REVERTED;
				continue;
			}

			ret = kgr_kgr_patch_code(pf, true, true, true);
			if (ret < 0) {
				/*
				 * Note: This should not happen. We only disable
				 * slow stubs and if this failed we would BUG in
				 * kgr_switch_fops called by kgr_patch_code. But
				 * leave it here to be sure.
				 */
				pr_err("finalization for %s:%s,%lu failed (%d). System in inconsistent state with no way out.\n",
					kgr_kgr_get_objname(pf), pf->name,
					pf->sympos, ret);
				BUG();
			}
		}
}

/* inlined */
static void kgr_kgr_finalize(void)
{
	struct kgr_patch_fun *patch_fun;
	int ret;

	mutex_lock(kgr_kgr_in_progress_lock);

	kgr_for_each_patch_fun((*kgr_kgr_patch), patch_fun) {
		ret = kgr_kgr_patch_code(patch_fun, true, *kgr_kgr_revert, false);

		if (ret < 0) {
			pr_err("finalization for %s:%s,%lu failed (%d). System in inconsistent state with no way out.\n",
				kgr_kgr_get_objname(patch_fun), patch_fun->name,
				patch_fun->sympos, ret);
			BUG();
		}

		/*
		 * When applying the replace_all patch all older patches are
		 * removed. We need to update loc_old and point it to the
		 * original function for the patch_funs from replace_all patch.
		 * The change is safe because the fast stub is used now. The
		 * correct value might be needed later when the patch is
		 * reverted.
		 */
		if ((*kgr_kgr_patch)->replace_all && !*kgr_kgr_revert)
			patch_fun->loc_old = patch_fun->loc_name;
	}

	if ((*kgr_kgr_patch)->replace_all && !*kgr_kgr_revert) {
		kgr_kgr_finalize_replaced_funs();
		kgr_kgr_remove_patches_fast();
	}

	free_percpu(*kgr_kgr_irq_use_new);

	if (*kgr_kgr_revert) {
		kgr_kgr_refs_dec();
		module_put((*kgr_kgr_patch)->owner);
	} else {
		list_add_tail(&(*kgr_kgr_patch)->list, kgr_kgr_patches);
		/*
		 * Fix CVE-2017-5754
		 *  call post patch handler
		 *  +1 line
		 */
		kgr_post_patch_callback();
	}

	*kgr_kgr_patch = NULL;
	*kgr_kgr_in_progress = false;

	pr_info("patching succeeded\n");

	mutex_unlock(kgr_kgr_in_progress_lock);
}

/* inlined */
static void kgr_kgr_send_fake_signal(void)
{
	struct task_struct *p, *t;

	read_lock(kgr_tasklist_lock);
	for_each_process_thread(p, t) {
		if (!klp_kgraft_task_in_progress(t))
			continue;

		/*
		 * There is a small race here. We could see TIF_KGR_IN_PROGRESS
		 * set and decide to wake up a kthread or send a fake signal.
		 * Meanwhile the thread could migrate itself and the action
		 * would be meaningless.  It is not serious though.
		 */
		if (t->flags & PF_KTHREAD) {
			/*
			 * Wake up a kthread which still has not been migrated.
			 */
			wake_up_process(t);
		} else {
			/*
			 * Send fake signal to all non-kthread tasks which are
			 * still not migrated.
			 */
			spin_lock_irq(&t->sighand->siglock);
			kgr_signal_wake_up(t, 0);
			spin_unlock_irq(&t->sighand->siglock);
		}
	}
	read_unlock(kgr_tasklist_lock);
}

/* inlined */
static void kgr_kgr_handle_processes(void)
{
	struct task_struct *p, *t;

	read_lock(kgr_tasklist_lock);
	for_each_process_thread(p, t) {
		klp_kgraft_mark_task_in_progress(t);
	}
	read_unlock(kgr_tasklist_lock);
}

/* inlined */
static void kgr_kgr_wakeup_kthreads(void)
{
	struct task_struct *p, *t;

	read_lock(kgr_tasklist_lock);
	for_each_process_thread(p, t) {
		/*
		 * Wake up kthreads, they will clean the progress flag.
		 *
		 * There is a small race here. We could see TIF_KGR_IN_PROGRESS
		 * set and decide to wake up a kthread. Meanwhile the kthread
		 * could migrate itself and the waking up would be meaningless.
		 * It is not serious though.
		 */
		if ((t->flags & PF_KTHREAD) &&
				klp_kgraft_task_in_progress(t)) {
			/*
			 * this is incorrect for kthreads waiting still for
			 * their first wake_up.
			 */
			wake_up_process(t);
		}
	}
	read_unlock(kgr_tasklist_lock);
}

/* inlined */
static void kgr_kgr_handle_irqs(void)
{
	kgr_schedule_on_each_cpu(kgr_kgr_handle_irq_cpu);
}


/* inlined */
static int kgr_kgr_revert_replaced_funs(struct kgr_patch *patch)
{
	struct kgr_patch *p;
	struct kgr_patch_fun *pf;
	unsigned long loc_old_temp;
	int ret;

	list_for_each_entry(p, kgr_kgr_patches, list)
		kgr_for_each_patch_fun(p, pf)
			if (!kgr_kgr_patch_contains(patch, pf)) {
				/*
				 * Calls from new universe to all functions
				 * being reverted are redirected to loc_old in
				 * the slow stub. We need to call the original
				 * functions and not the previous ones in terms
				 * of stacking, so loc_old is changed to
				 * loc_name.  Fast stub is still used, so change
				 * of loc_old is safe.
				 */
				loc_old_temp = pf->loc_old;
				pf->loc_old = pf->loc_name;

				ret = kgr_kgr_patch_code(pf, false, true, true);
				if (ret < 0) {
					pr_err("cannot revert function %s:%s,%lu in patch %s (%d)\n",
						kgr_kgr_get_objname(pf), pf->name,
						pf->sympos, p->name, ret);
					pf->loc_old = loc_old_temp;
					kgr_kgr_patching_failed(p, pf, true);
					return ret;
				}
			}

	return 0;
}


/* patched */
void kgr_kgr_work_fn(struct work_struct *work)
{
	static bool printed = false;

	if (kgr_kgr_still_patching()) {
		if (!printed) {
			pr_info("still in progress after timeout, will keep"
					" trying every %d seconds\n",
				KGR_TIMEOUT);
			printed = true;
		}
		/* send fake signal */
		kgr_kgr_send_fake_signal();
		/* recheck again later */
		queue_delayed_work(*kgr_kgr_wq, kgr_kgr_work, KGR_TIMEOUT * HZ);
		return;
	}

	/*
	 * victory, patching finished, put everything back in shape
	 * with as less performance impact as possible again
	 */
	kgr_kgr_finalize();
	printed = false;
}

/* patched */
int kgr_kgr_modify_kernel(struct kgr_patch *patch, bool revert)
{
	struct kgr_patch_fun *patch_fun;
	int ret;

	if (!*kgr_kgr_initialized) {
		pr_err("can't patch, not initialized\n");
		return -EINVAL;
	}

	mutex_lock(kgr_kgr_in_progress_lock);
	if (patch->refs) {
		pr_err("can't patch, this patch is still referenced\n");
		ret = -EBUSY;
		goto err_unlock;
	}

	if (*kgr_kgr_in_progress) {
		pr_err("can't patch, another patching not yet finalized\n");
		ret = -EAGAIN;
		goto err_unlock;
	}

	if (revert && list_empty(&patch->list)) {
		pr_err("can't patch, this one was already reverted\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	*kgr_kgr_irq_use_new = alloc_percpu(bool);
	if (!*kgr_kgr_irq_use_new) {
		pr_err("can't patch, cannot allocate percpu data\n");
		ret = -ENOMEM;
		goto err_unlock;
	}

	add_taint_module(patch->owner, TAINT_LIVEPATCH, LOCKDEP_STILL_OK);

	pr_info("%sing patch '%s'\n", revert ? "revert" : "apply",
			patch->name);

	set_bit(0, (*kgr_kgr_immutable));
	wmb(); /* set_bit before kgr_handle_processes */

	/*
	 * Set kgr_patch before it can be used in kgr_patching_failed if
	 * something bad happens.
	 */
	*kgr_kgr_patch = patch;

	/*
	 * We need to revert patches of functions not patched in replace_all
	 * patch. Do that only while applying the replace_all patch.
	 */
	if (patch->replace_all && !revert) {
		ret = kgr_kgr_revert_replaced_funs(patch);
		if (ret)
			goto err_free;
	}

	kgr_for_each_patch_fun(patch, patch_fun) {
		patch_fun->patch = patch;

		ret = kgr_kgr_patch_code(patch_fun, false, revert, false);
		if (ret < 0) {
			kgr_kgr_patching_failed(patch, patch_fun,
				patch->replace_all && !revert);
			goto err_free;
		}
	}
	*kgr_kgr_in_progress = true;
	*kgr_kgr_revert = revert;
	if (revert)
		list_del_init(&patch->list); /* init for list_empty() above */
	else if (!patch->replace_all)
		/* block all older patches if they are not replaced */
		kgr_kgr_refs_inc();
	mutex_unlock(kgr_kgr_in_progress_lock);

	/*
	 * Fix CVE-2017-5754
	 *  call pre revert handler
	 *  +2 lines
	 */
	if (revert)
		kgr_pre_revert_callback();

	kgr_kgr_handle_irqs();
	kgr_kgr_handle_processes();

	wmb(); /* clear_bit after kgr_handle_processes */
	clear_bit(0, (*kgr_kgr_immutable));

	/*
	 * There is no need to have an explicit barrier here. wake_up_process()
	 * implies a write barrier. That is every woken up task sees
	 * kgr_immutable cleared.
	 */
	kgr_kgr_wakeup_kthreads();
	/*
	 * give everyone time to exit kernel, and check after a while
	 */
	queue_delayed_work(*kgr_kgr_wq, kgr_kgr_work, KGR_TIMEOUT * HZ);

	return 0;
err_free:
	*kgr_kgr_patch = NULL;
	/* No need for barrier as there are no slow stubs involved */
	clear_bit(0, (*kgr_kgr_immutable));
	free_percpu(*kgr_kgr_irq_use_new);
err_unlock:
	mutex_unlock(kgr_kgr_in_progress_lock);

	return ret;
}
