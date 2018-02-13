#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include "shared_data.h"
#include "shared_data_kallsyms.h"
#include "kaiser.h"

void __percpu * (*kgr__alloc_reserved_percpu)(size_t size, size_t align);
struct meltdown_shared_data *kgr_meltdown_shared_data;
bool kgr_meltdown_local_disabled = false;

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

static void __shared_data_free(struct meltdown_shared_data *sd)
{
	if (!sd)
		return;
	if (sd->shadow_pgd)
		kgr_kaiser_free_shadow_pgd(sd->shadow_pgd);
	if (sd->pcpu_cr3s)
		free_percpu(sd->pcpu_cr3s);
	kfree(sd);
}

static struct meltdown_shared_data *__init __shared_data_alloc(void)
{
	struct meltdown_shared_data *sd;

	sd = kzalloc(sizeof(*kgr_meltdown_shared_data), GFP_KERNEL);

	if (!sd)
		return NULL;

	kgr_meltdown_shared_data->pcpu_cr3s =
		kgr__alloc_reserved_percpu(sizeof(struct kgr_pcpu_cr3s),
					   4 * sizeof(long));
	if (!kgr_meltdown_shared_data->pcpu_cr3s) {
		__shared_data_free(sd);
		return NULL;
	}

	kgr_meltdown_shared_data->ps = ps_disabled;
	spin_lock_init(&kgr_meltdown_shared_data->lock);
	kgr_meltdown_shared_data->refcnt = 1;
	INIT_LIST_HEAD(&kgr_meltdown_shared_data->patchers);

	sd->shadow_pgd = kgr_kaiser_create_shadow_pgd();
	if (!sd->shadow_pgd) {
		__shared_data_free(sd);
		return NULL;
	}

	return sd;
}

int __init kgr_meltdown_shared_data_init(void)
{
	struct meltdown_shared_data *sd;

	mutex_lock(&module_mutex);
	if (kallsyms_on_each_symbol(__kgr_find_meltdown_shared_data,
					NULL)) {
		mutex_unlock(&module_mutex);
		pr_debug("Found other shared_data instance\n");
		return 0;
	}
	mutex_unlock(&module_mutex);

	pr_debug("Didn't find any other shared_data instance\n");
	sd = __shared_data_alloc();
	if (!sd)
		return -ENOMEM;

	mutex_lock(&module_mutex);
	if (kallsyms_on_each_symbol(__kgr_find_meltdown_shared_data,
					NULL)) {
		mutex_unlock(&module_mutex);
		pr_debug("Found other shared_data instance\n");
		__shared_data_free(sd);
		return 0;
	}
	kgr_meltdown_shared_data = sd;
	mutex_unlock(&module_mutex);
	return 0;
}

void kgr_meltdown_shared_data_cleanup(void)
{
	struct meltdown_shared_data *sd;

	sd = kgr_meltdown_shared_data;
	mutex_lock(&module_mutex);
	if (--sd->refcnt)
		sd = NULL;
	kgr_meltdown_shared_data = NULL;
	mutex_unlock(&module_mutex);

	__shared_data_free(sd);
}

int kgr_meltdown_shared_data_reset(void)
{
	if (!kgr_meltdown_shared_data->dirty)
		return 0;

	kgr_meltdown_shared_data->shadow_pgd =
		(kgr_kaiser_reset_shadow_pgd
			(kgr_meltdown_shared_data->shadow_pgd));
	kgr_meltdown_shared_data->dirty = false;

	if (!kgr_meltdown_shared_data->shadow_pgd)
		return -ENOMEM;
	return 0;
}
