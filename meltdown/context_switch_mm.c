#include <asm/tlbflush.h>
#include <linux/tracepoint.h>
#include <asm/cpufeature.h>
#include "shared_data.h"
#include "kaiser.h"

/*
 * Called from context_switch() through trace_sched_switch() right
 * before switch_mm() with irqs disabled. The work done in KPTI's
 * load_new_mm_cr3() is done here as switch_mm() cannot be
 * KGraft-patched (as can't any of its callers up to and including
 * __schedule()).
 */
static void sched_switch_tracer(void *data,
				bool preempt,
				struct task_struct *prev,
				struct task_struct *next)
{
	struct mm_struct *prev_mm, *next_mm;
	struct kgr_pcpu_pgds *cpu_pgds;
	unsigned int cpu;
	pgd_t *user_pgd = NULL;

	next_mm = next->mm;
	user_pgd = kgr_mm_user_pgd(next_mm);
	if (!kgr_meltdown_active() ||
	    !next_mm ||	/* No userspace task and we don't care. */
	    !user_pgd) {
		cpu_pgds->user_pgd = 0;
		cpu_pgds->kern_pgd = 0;
		return;
	}

	cpu_pgds = kgr_this_cpu_pgds();
	prev_mm = prev->active_mm;
	/* Be careful to retain an unset X86_CR3_PCID_NOFLUSH at the user_pgd. */
	if (next_mm != prev_mm) {
		cpu_pgds->user_pgd = __pa(user_pgd);
		cpu_pgds->kern_pgd = __pa(next_mm->pgd);
	}

	if (!likely(this_cpu_has(X86_FEATURE_PCID)))
		return;

	cpu_pgds->user_pgd |= X86_CR3_PCID_USER_NOFLUSH;
	cpu_pgds->kern_pgd |= X86_CR3_PCID_KERN_NOFLUSH;

	if (next_mm != prev_mm) {
		kaiser_flush_tlb_on_return_to_user();
	} else {
		/*
		 * The write of TLBSTATE_OK will stabilize
		 * cpumask_test_cpu(cpu, mm_cpumask(next_mm)), c.f.
		 * flush_tlb_func(). This isn't strictly needed as
		 * interrupts are disabled and AFAICS,
		 * flush_tlb_func() will never get called from an NMI.
		 * But better be safe than sorry.
		 * Note that the write is redundant with the one in
		 * switch_mm() and doesn't harm.
		 */
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		barrier();
		cpu = smp_processor_id();
		if (!cpumask_test_cpu(cpu, mm_cpumask(next_mm))) {
			/*
			 * Ugh, we have been in lazy TLB mode and
			 * called leave_mm(), i.e. TLB flush IPIs have
			 * arrived meanwhile.
			 */
			kaiser_flush_tlb_on_return_to_user();
		}
	}
}

struct tracepoint *kgr__tracepoint_sched_switch;

int __init context_switch_mm_init(void)
{
	int ret;

	ret = tracepoint_probe_register(kgr__tracepoint_sched_switch,
					sched_switch_tracer, NULL);
	if (ret) {
		pr_err("failed to register sched switch probe: %d\n", ret);
		return ret;
	}

	return ret;
}

void context_switch_mm_cleanup(void)
{
	int ret;

	ret = tracepoint_probe_unregister(kgr__tracepoint_sched_switch,
					  sched_switch_tracer, NULL);
	if (ret) {
		/*
		 * That's impossible, but for debugging purposes,
		 * print an error.
		 */
		pr_err("failed to unregister sched switch probe: %d\n", ret);
	}
}
