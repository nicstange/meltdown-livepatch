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

int kgr_meltdown_shared_data_init(void)
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


	kgr_meltdown_shared_data->pcpu_pgds =
		kgr__alloc_reserved_percpu(sizeof(struct kgr_pcpu_pgds),
					   4 * sizeof(long));
	if (!kgr_meltdown_shared_data->pcpu_pgds) {
		kfree(kgr_meltdown_shared_data);
		kgr_meltdown_shared_data = NULL;
		return -ENOMEM;
	}

	kgr_meltdown_shared_data->ps = ps_disabled;
	spin_lock_init(&kgr_meltdown_shared_data->lock);
	kgr_meltdown_shared_data->refcnt = 1;
	INIT_LIST_HEAD(&kgr_meltdown_shared_data->patchers);
out:
	mutex_unlock(&module_mutex);
	return r;
}

void kgr_meltdown_shared_data_cleanup(void)
{
	bool free_gd;
	struct meltdown_shared_data *gd;

	gd = kgr_meltdown_shared_data;
	mutex_lock(&module_mutex);
	free_gd = !--gd->refcnt;
	kgr_meltdown_shared_data = NULL;
	mutex_unlock(&module_mutex);

	if (free_gd) {
		free_percpu(gd->pcpu_pgds);
		kfree(gd);
	}
}
