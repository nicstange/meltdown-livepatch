#include <asm/paravirt.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include <linux/spinlock.h>
#include "kaiser.h"
#include "pgtable-generic.h"
#include "memory.h"
#include "memory_kallsyms.h"

#if CONFIG_PGTABLE_LEVELS <= 3
#error "Livepatch supports only CONFIG_PGTABLE_LEVELS > 3."
#endif

#if defined(__PAGETABLE_PUD_FOLDED)
#error "Livepatch supports only !defined(__PAGETABLE_PUD_FOLDED)."
#endif

#if defined(__ARCH_HAS_4LEVEL_HACK)
#error "Livepatch supports only !defined(__ARCH_HAS_4LEVEL_HACK)."
#endif

void (*kgr___pte_free_tlb)(struct mmu_gather *tlb, struct page *pte);
void (*kgr___pmd_free_tlb)(struct mmu_gather *tlb, pmd_t *pmd);
void (*kgr___pud_free_tlb)(struct mmu_gather *tlb, pud_t *pud);
void (*kgr_pud_clear_bad)(pud_t *);
void (*kgr_pmd_clear_bad)(pmd_t *);

/* from arch/x86/include/asm/pgalloc.h */
/* line 62 */
static inline void kgr__pte_free_tlb(struct mmu_gather *tlb, struct page *pte,
				  unsigned long address)
{
	kgr___pte_free_tlb(tlb, pte);
}

/* line 108 */
static inline void kgr__pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				  unsigned long address)
{
	kgr___pmd_free_tlb(tlb, pmd);
}

/* line 138 */
static inline void kgr__pud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				  unsigned long address)
{
	kgr___pud_free_tlb(tlb, pud);
}

/* from include/asm-generic/tlb.h */
/* line 204 */
#define kgr_pte_free_tlb(tlb, ptep, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		kgr__pte_free_tlb(tlb, ptep, address);		\
	} while (0)

/* line 211 */
#define kgr_pud_free_tlb(tlb, pudp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		kgr__pud_free_tlb(tlb, pudp, address);		\
	} while (0)

/* line 213 */
#define kgr_pmd_free_tlb(tlb, pmdp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		kgr__pmd_free_tlb(tlb, pmdp, address);		\
	} while (0)


/* from include/asm-generic/pgtable.h */
/* line 394 */
static inline int kgr_pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if (unlikely(pgd_bad(*pgd))) {
		kgr_pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

/* line 373 */
static inline int kgr_pud_none_or_clear_bad(pud_t *pud)
{
	if (pud_none(*pud))
		return 1;
	if (unlikely(pud_bad(*pud))) {
		kgr_pud_clear_bad(pud);
		return 1;
	}
	return 0;
}

/* line 384 */
static inline int kgr_pmd_none_or_clear_bad(pmd_t *pmd)
{
	if (pmd_none(*pmd))
		return 1;
	if (unlikely(pmd_bad(*pmd))) {
		kgr_pmd_clear_bad(pmd);
		return 1;
	}
	return 0;
}


/* from mm/memory.c */
/* line 395 */
/* inlined */
static void kgr_free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	kgr_pte_free_tlb(tlb, token, addr);
	atomic_long_dec(&tlb->mm->nr_ptes);
}

/* inlined */
/* line 404 */
static inline void kgr_free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (kgr_pmd_none_or_clear_bad(pmd))
			continue;
		kgr_free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	kgr_pmd_free_tlb(tlb, pmd, start);
	mm_dec_nr_pmds(tlb->mm);
}



/* Patched, inlined, calls inlined native_set_pgd() */
static inline void kgr_pgd_populate(struct mm_struct *mm, pgd_t *pgd,
				    pud_t *pud)
{
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	kgr_set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
}

/* Patched, calls pgd_populate() */
int kgr__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		kgr_pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

/* Patched, inlined, calls pgd_clear() */
static inline void kgr_free_pud_range(struct mmu_gather *tlb, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (kgr_pud_none_or_clear_bad(pud))
			continue;
		kgr_free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(pgd, start);
	kgr_pgd_clear(pgd);
	kgr_pud_free_tlb(tlb, pud, start);
}

/* Patched, calls free_pud_range() */
void kgr_free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
			return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;

	pgd = pgd_offset(tlb->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (kgr_pgd_none_or_clear_bad(pgd))
			continue;
		kgr_free_pud_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}
