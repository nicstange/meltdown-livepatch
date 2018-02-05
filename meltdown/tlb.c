#include <asm/tlbflush.h>
#include <asm/processor.h>

#include "kaiser.h"
#include "shared_data.h"
#include "tlb.h"


static inline void __invpcid(unsigned long pcid, unsigned long addr,
			     unsigned long type)
{
	struct { u64 d[2]; } desc = { { pcid, addr } };
	/*
	 * The memory clobber is because the whole point is to invalidate
	 * stale TLB entries and, especially if we're flushing global
	 * mappings, we don't want the compiler to reorder any subsequent
	 * memory accesses before the TLB flush.
	 *
	 * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
	 * invpcid (%rcx), %rax in long mode.
	 */
	asm volatile (".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
		: : "m" (desc), "a" (type), "c" (&desc) : "memory");
}

#define INVPCID_TYPE_INDIV_ADDR	0
#define INVPCID_TYPE_SINGLE_CTXT	1
#define INVPCID_TYPE_ALL_INCL_GLOBAL	2
#define INVPCID_TYPE_ALL_NON_GLOBAL	3

/* Flush all mappings for a given pcid and addr, not including globals. */
static inline void invpcid_flush_one(unsigned long pcid,
				     unsigned long addr)
{
	__invpcid(pcid, addr, INVPCID_TYPE_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals. */
static inline void invpcid_flush_single_context(unsigned long pcid)
{
	__invpcid(pcid, 0, INVPCID_TYPE_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs. */
static inline void invpcid_flush_all(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs except globals. */
static inline void invpcid_flush_all_nonglobals(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_NON_GLOBAL);
}



/* Patched, inlined */
static inline void kgr__native_flush_tlb(void)
{
	/*
	 * If current->mm == NULL then we borrow a mm which may change during a
	 * task switch and therefore we must not be preempted while we write CR3
	 * back:
	 */
	preempt_disable();
	/*
	 * Fix CVE-2017-5754
	 *  +2 lines
	 */
	if (kgr_meltdown_active())
		kaiser_flush_tlb_on_return_to_user();
	native_write_cr3(native_read_cr3());
	preempt_enable();
}

/* Patched, inlined */
static inline void kgr__native_flush_tlb_global_irq_disabled(void)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	/*
	 * Fix CVE-2017-5754
	 *  -4 lines, +9 lines
	 */
	if (unlikely(cr4 & X86_CR4_PGE)) {
		/* clear PGE and flush TLB of all entries */
		native_write_cr4(cr4 & ~X86_CR4_PGE);
		/* restore PGE as it was before */
		native_write_cr4(cr4);
	} else {
		/* do it with cr3, letting kaiser flush user PCID */
		kgr__native_flush_tlb();
	}
}

/* Patched, inlined */
static inline void kgr__native_flush_tlb_global(void)
{
	unsigned long flags;

	/*
	 * Fix CVE-2017-5754
	 *  +17 lines
	 * It is important that invpcid below works with CR4.PCIDE=0.
	 */
	if (this_cpu_has(X86_FEATURE_INVPCID)) {
		/*
		 * Using INVPCID is considerably faster than a pair of writes
		 * to CR4 sandwiched inside an IRQ flag save/restore.
		 *
		 * Note, this works with CR4.PCIDE=0 or 1.
		 */
		invpcid_flush_all();
		return;
	}

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	raw_local_irq_save(flags);

	kgr__native_flush_tlb_global_irq_disabled();

	raw_local_irq_restore(flags);
}

/* Patched, inlined */
static inline void kgr__native_flush_tlb_single(unsigned long addr)
{
	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +everything here
	 */
	/*
	 * SIMICS #GP's if you run INVPCID with type 2/3
	 * and X86_CR4_PCIDE clear.  Shame!
	 *
	 * The ASIDs used below are hard-coded.  But, we must not
	 * call invpcid(type=1/2) before CR4.PCIDE=1.  Just call
	 * invlpg in the case we are called early.
	 */
	unsigned long cr4 = this_cpu_read(cpu_tlbstate.cr4);
	if (!this_cpu_has(X86_FEATURE_INVPCID) || !(cr4 & X86_CR4_PCIDE)) {
		if (kgr_meltdown_active())
			kaiser_flush_tlb_on_return_to_user();
		asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
		return;
	}
	/* Flush the address out of both PCIDs. */
	/*
	 * An optimization here might be to determine addresses
	 * that are only kernel-mapped and only flush the kernel
	 * ASID.  But, userspace flushes are probably much more
	 * important performance-wise.
	 *
	 * Make sure to do only a single invpcid when KAISER is
	 * disabled and we have only a single ASID.
	 */
	if (kgr_meltdown_active())
		invpcid_flush_one(X86_CR3_PCID_ASID_USER, addr);
	invpcid_flush_one(X86_CR3_PCID_ASID_KERN, addr);
}

/* Patched upstream, but not by us -- here only for documentation. */
static __attribute__((unused)) inline void kgr__flush_tlb_all(void)
{
	/*
	 * Upstream stable 4.4. patches this.
	 * However, __flush_tlb_all() is heavily inlined everywhere
	 * and the functionality is equivalent.
	 * The original (and kept) implementation is
	 *
	 *	if (cpu_has_pge)
	 *		__flush_tlb_global();
	 *	else
	 *		__flush_tlb();
	 *
	 * With paravirt this translates to
	 *
	 *	if (cpu_has_pge)
	 *		native_flush_tlb_global();
	 *	else
	 *		native_flush_tlb();
	 *
	 * After KGraft-patching, this becomes
	 *
	 *	if (cpu_has_pge)
	 *		kgr_native_flush_tlb_global();
	 *	else
	 *		kgr_native_flush_tlb();
	 *
	 * i.e.
	 *
	 *	if (cpu_has_pge)
	 *		kgr__native_flush_tlb_global();
	 *	else
	 *		kgr__native_flush_tlb();
	 *
	 * The patched upstream implementation contains only
	 * a plain call to __flush_tlb_global().
	 * Thus, it has to be proven that if !cpu_has_pge, then
	 * kgr__native_flush_tlb_global() and kgr__native_flush_tlb()
	 * behave equivalently.
	 *
	 * !cpu_has_pge() implies !(cr4 & X86_CR4_PGE).
	 * Consider two case:
	 * 1. !this_cpu_has(X86_FEATURE_INVPCID):
	 *    In this case, kgr__native_flush_tlb_global() collapses
	 *    to
	 *	raw_local_irq_save(flags);
	 *	kgr__native_flush_tlb();
	 *	raw_local_irq_restore(flags);
	 *    and kgr__native_flush_tlb_global() is indeed equivalent
	 *    to kgr__native_flush_tlb().
	 * 2. this_cpu_has(X86_FEATURE_INVPCID):
	 *    In this case kgr__native_flush_tlb_global()
	 *    is equivalent to invpcid_flush_all(), that is to
	 *    __invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL).
	 *    Given that with !cpu_has_pge there is no such thing
	 *    like global pages, this means that invpcid_flush_all()
	 *    flushes the TLB entries for both, the user- and
	 *    kernelspace PCIDs. The only difference to
	 *    kgr__native_flush_tlb() is that the latter will delay
	 *    the flush of the userspace mappings to exit-to-user.
	 */
	/*
	 * Fix CVE-2017-5754
	 *  -4 lines, +1 line
	 */
	kgr__native_flush_tlb_global();
}



/* Patched, calls inlined __native_flush() */
void kgr_native_flush_tlb(void)
{
	kgr__native_flush_tlb();
}

/* Patched, calls inlined __native_flush_tlb_global() */
void kgr_native_flush_tlb_global(void)
{
	kgr__native_flush_tlb_global();
}

/* Patched, calls inlined __native_flush_tlb_single() */
void kgr_native_flush_tlb_single(unsigned long addr)
{
	kgr__native_flush_tlb_single(addr);
}
