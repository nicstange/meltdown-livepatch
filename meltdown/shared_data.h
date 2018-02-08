#ifndef _SHARED_DATA_H
#define _SHARED_DATA_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/compiler.h>
#include <asm/barrier.h>
#include "patch_entry.h"

struct meltdown_patcher
{
	struct list_head list;
	struct module *mod;
};

/* Data shared among KGraft patches */
struct meltdown_shared_data
{
	enum patch_state {
		ps_disabled = 0, /* Disabled */
		ps_enabled, /* Intermediate state: not disabled but
			     * also not active. */
		ps_active, /* KGraft patch has been applied _globally_
			    * or a transition to a new one also patching
			    * meltdown is in progress. */
	} ps;

	struct kgr_pcpu_pgds __percpu *pcpu_pgds;


	struct saved_idt orig_idt;

	spinlock_t lock;
	pgd_t* shadow_pgd;


	unsigned long refcnt; /* protected by module_mutex */
	struct list_head patchers; /* see kgr_pre_replace_callback() */
	void (*prev_patch_entry_drain_start)(void);
	bool dirty;
};

extern struct meltdown_shared_data *kgr_meltdown_shared_data;

extern bool kgr_meltdown_local_disabled;


int kgr_meltdown_shared_data_init(void);
void kgr_meltdown_shared_data_cleanup(void);
int kgr_meltdown_shared_data_reset(void);

static inline void kgr_meltdown_shared_data_lock(void)
{
	spin_lock(&kgr_meltdown_shared_data->lock);
}

static inline void kgr_meltdown_shared_data_unlock(void)
{
	spin_unlock(&kgr_meltdown_shared_data->lock);
}

static inline enum patch_state kgr_meltdown_patch_state(void)
{
	enum patch_state ps = (!kgr_meltdown_local_disabled ?
			       READ_ONCE(kgr_meltdown_shared_data->ps) :
			       ps_disabled);
	/* paired with smp_wmb() in __kgr_meltdown_set_patch_state() */
	smp_rmb();
	return ps;
}

static inline bool kgr_meltdown_active(void)
{
	return kgr_meltdown_patch_state() == ps_active;
}

static inline void __kgr_meltdown_set_patch_state(const enum patch_state ps)
{
	/* paired with smp_rmb() in kgr_meltdown_patch_state() */
	smp_wmb();
	WRITE_ONCE(kgr_meltdown_shared_data->ps, ps);
}

static inline void kgr_meltdown_set_patch_state(const enum patch_state ps)
{
	/*
	 * Module's _init()'s are not synchronized and thus,
	 * the transition inactive->enabled could race with
	 * other state transitions.
	 */
	kgr_meltdown_shared_data_lock();
	__kgr_meltdown_set_patch_state(ps);
	kgr_meltdown_shared_data_unlock();
}

static inline void __kgr_meltdown_register_patcher(struct meltdown_patcher *p)
{
	list_add_tail(&p->list, &kgr_meltdown_shared_data->patchers);
}

static inline void kgr_meltdown_unregister_patcher(struct meltdown_patcher *p)
{
	kgr_meltdown_shared_data_lock();
	list_del(&p->list);
	kgr_meltdown_shared_data_unlock();
}

static inline bool kgr_is_meltdown_patcher(struct module *m)
{
	bool is_patcher = false;
	struct meltdown_patcher *p;

	kgr_meltdown_shared_data_lock();
	list_for_each_entry(p, &kgr_meltdown_shared_data->patchers, list) {
		if (p->mod == m) {
			is_patcher = true;
			goto out;
		}
	}
out:
	kgr_meltdown_shared_data_unlock();
	return is_patcher;
}

static inline void kgr_meltdown_shared_data_mark_dirty(void)
{
	kgr_meltdown_shared_data->dirty = true;
}

int kgr_meltdown_shared_data_reset(void);


#endif
