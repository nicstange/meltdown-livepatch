#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/smp.h>
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
	pr_info("kgr_post_patch_callback\n");
}

void kgr_pre_revert_callback(void)
{
	pr_info("kgr_pre_revert_callback\n");
	kgr_meltdown_active = 0;
	patch_entry_unapply();
	kgr_schedule_on_each_cpu(__uninstall_idt_table_repl);
}

int __init kgr_patch_meltdown_init(void)
{
	int ret = kgr_patch_meltdown_kallsyms();
	if (ret)
		return ret;

	ret = patch_entry_init();
	if (ret)
		return ret;

	patch_entry_apply();

	/* Load the new idt on all cpus. */
	on_each_cpu(__install_idt_table_repl, NULL, true);

	kgr_meltdown_active = 1;
	return 0;
}

void kgr_patch_meltdown_cleanup(void)
{
}
