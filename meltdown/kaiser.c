#include "kaiser.h"
#include "shared_data.h"

struct kgr_pcpu_pgds __percpu *__kgr_pcpu_pgds;
/*
 * Provide a dummy indirect pointer to __kgr_pcpu_pgds
 * in order to allow patch_entry to patch in the references to
 * it.
 */
struct kgr_pcpu_pgds __percpu **kgr_pcpu_pgds = &__kgr_pcpu_pgds;

int kgr_kaiser_init(void)
{
	__kgr_pcpu_pgds = kgr_meltdown_shared_data->pcpu_pgds;
	return 0;
}

void kgr_kaiser_cleanup(void)
{}
