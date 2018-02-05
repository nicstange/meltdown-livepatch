#include <asm/cpufeature.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <linux/irqflags.h>
#include <asm/paravirt.h>

void kgr_pcid_enable_cpu(void)
{
	unsigned long cr4, orig_cr4;
	unsigned long flags;

	local_irq_save(flags);
	cr4 = orig_cr4 = this_cpu_read(cpu_tlbstate.cr4);
	cr4 &= ~X86_CR4_PGE;
	if (this_cpu_has(X86_FEATURE_PCID)) {
		cr4 |= X86_CR4_PCIDE;
	}

	if (orig_cr4 != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		__write_cr4(cr4);
	}
	local_irq_restore(flags);
}

void kgr_pcid_disable_cpu(void)
{
	unsigned long cr4, orig_cr4;
	unsigned long flags;

	local_irq_save(flags);
	cr4 = orig_cr4 = this_cpu_read(cpu_tlbstate.cr4);
	cr4 &= ~X86_CR4_PCIDE;
	if (cpu_has_pge) {
		cr4 |= X86_CR4_PGE;
	}

	if (orig_cr4 != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		__write_cr4(cr4);
	}
	local_irq_restore(flags);
}
