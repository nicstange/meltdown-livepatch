#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include "kgraft_hooks_kallsyms.h"
#include "kgraft_hooks.h"
#include "entry_64_kallsyms.h"
#include "entry_64_compat_kallsyms.h"
#include "patch_entry.h"
#include "patch_entry_kallsyms.h"
#include "schedule_tail_kallsyms.h"
#include "patch_state.h"

int kgr_meltdown_active;

static struct {
	char *name;
	char **addr;
} kgr_funcs[] = {
	KGRAFT_HOOKS_KALLSYMS
	ENTRY_64_KALLSYMS
	ENTRY_64_COMPAT_KALLSYMS
	PATCH_ENTRY_KALLSYMS
	SCHEDULE_TAIL_KALLSYMS
};

static int __init kgr_patch_meltdown_kallsyms(void)
{
	unsigned long addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(kgr_funcs); i++) {
		addr = kallsyms_lookup_name(kgr_funcs[i].name);
		if (!addr) {
			pr_err("kgraft-patch: symbol %s not resolved\n",
				kgr_funcs[i].name);
			return -ENOENT;
		}

		*(kgr_funcs[i].addr) = (void *)addr;
	}

	return 0;
}

static void __install_idt_table_repl(void *info)
{
	patch_entry_apply_finish_cpu();
}

static void __uninstall_idt_table_repl(struct work_struct *w)
{
	patch_entry_unapply_finish_cpu();
}


void kgr_post_patch_callback(void)
{
	pr_debug("kgr_post_patch_callback\n");

	if (!kgr_meltdown_patch_state())
		return;

	patch_entry_apply_start(!kgr_meltdown_shared_data->orig_idt.idt ?
				&kgr_meltdown_shared_data->orig_idt : NULL);

	/* Load the new idt on all cpus. */
	on_each_cpu(__install_idt_table_repl, NULL, true);

	if (kgr_meltdown_shared_data->prev_patch_entry_drain_start) {
		kgr_meltdown_shared_data->prev_patch_entry_drain_start();
		kgr_meltdown_shared_data->prev_patch_entry_drain_start = NULL;
	}

	kgr_meltdown_set_patch_state(ps_active);
}

void kgr_pre_revert_callback(void)
{
	pr_debug("kgr_pre_revert_callback\n");

	if (!kgr_meltdown_patch_state())
		return;

	kgr_meltdown_set_patch_state(ps_enabled);
	patch_entry_unapply_start(&kgr_meltdown_shared_data->orig_idt);
	kgr_schedule_on_each_cpu(__uninstall_idt_table_repl);
	patch_entry_drain_start();
}

void kgr_pre_replace_callback(struct module *new_mod)
{
	pr_debug("kgr_pre_replace_callback\n");

	if (!kgr_meltdown_patch_state())
		return;

	/*
	 * We have to decide whether what follows is a livepatch which
	 * fixes meltdown or not: depending on that, the replacement
	 * has to be treated either as a handover or as a revert.
	 */
	if (kgr_is_meltdown_patcher(new_mod)) {
		/*
		 * The KGraft module stacked on top will install its
		 * own IDT replacement from its
		 * kgr_post_patch_callback(). All we have to do is to
		 * tell the new patch to start draining us when it has
		 * done that.
		 */
		patch_entry_draining = true;
		kgr_meltdown_shared_data->prev_patch_entry_drain_start =
			patch_entry_drain_start;
	} else {
		/*
		 * Ok, we're about to get replaced by a replace_all
		 * livepatch which won't patch meltdown. Treat this
		 * like a revert.
		 */
		kgr_pre_revert_callback();
	}
}

struct meltdown_shared_data *kgr_meltdown_shared_data;

static int __kgr_find_meltdown_shared_data(void *data, const char *name,
						struct module *mod,
						unsigned long addr)
{
	struct meltdown_shared_data **p;

	if (!mod || mod == THIS_MODULE)
		return 0;

	if (strcmp(__stringify(kgr_meltdown_shared_data), name))
		return 0;

	p = (struct meltdown_shared_data **)data;

	if (!(*p))
		return 0;

	if (!(*p)->refcnt)
		return 0;

	++(*p)->refcnt;
	kgr_meltdown_shared_data = *p;
	return 1;
}

static int kgr_meltdown_shared_data_init(void)
{
	int r = 0;

	mutex_lock(&module_mutex);
	if (kallsyms_on_each_symbol(__kgr_find_meltdown_shared_data,
					NULL)) {
		goto out;
	}

	kgr_meltdown_shared_data =
		kzalloc(sizeof(*kgr_meltdown_shared_data), GFP_KERNEL);

	if (!kgr_meltdown_shared_data) {
		r = -ENOMEM;
		goto out;
	}

	kgr_meltdown_shared_data->ps = ps_inactive;
	spin_lock_init(&kgr_meltdown_shared_data->lock);
	kgr_meltdown_shared_data->refcnt = 1;
	INIT_LIST_HEAD(&kgr_meltdown_shared_data->patchers);
out:
	mutex_unlock(&module_mutex);
	return r;
}

static struct meltdown_patcher this_meltdown_patcher = {
	.mod = THIS_MODULE,
};

int __init kgr_patch_meltdown_init(void)
{
	int ret = kgr_patch_meltdown_kallsyms();
	if (ret)
		return ret;

	ret = patch_entry_init();
	if (ret)
		return ret;

	ret = kgr_meltdown_shared_data_init();
	if (ret)
		return ret;

	kgr_meltdown_register_patcher(&this_meltdown_patcher);

	return 0;
}

void kgr_patch_meltdown_cleanup(void)
{
	bool free_gd;
	struct meltdown_shared_data *gd;

	kgr_meltdown_unregister_patcher(&this_meltdown_patcher);

	gd = kgr_meltdown_shared_data;
	mutex_lock(&module_mutex);
	free_gd = !--gd->refcnt;
	kgr_meltdown_shared_data = NULL;
	mutex_unlock(&module_mutex);

	if (free_gd) {
		kfree(gd);
	}
}
