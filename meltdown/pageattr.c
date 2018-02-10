#include <asm/pgalloc.h>
#include "pageattr.h"

static void kgr_unmap_pte_range(pmd_t *pmd, unsigned long start,
				unsigned long end)
{
	pte_t *pte;

	if (pmd_none(*pmd))
		return;

	pte = pte_offset_kernel(pmd, start);

	while (start < end) {
		set_pte(pte, __pte(0));

		start += PAGE_SIZE;
		pte++;
	}
}

static void kgr_unmap_pmd_range(pud_t *pud, unsigned long start,
				unsigned long end)
{
	pmd_t *pmd;

	if (pud_none(*pud))
		return;

	pmd = pmd_offset(pud, start);

	/*
	 * Not on a 2MB page boundary?
	 */
	if (start & (PMD_SIZE - 1)) {
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;
		unsigned long pre_end = min_t(unsigned long, end, next_page);

		kgr_unmap_pte_range(pmd, start, pre_end);

		start = pre_end;
		pmd++;
	}

	/*
	 * Try to unmap in 2M chunks.
	 */
	while (end - start >= PMD_SIZE) {
		if (pmd_large(*pmd))
			pmd_clear(pmd);
		else
			kgr_unmap_pte_range(pmd, start, start + PMD_SIZE);

		start += PMD_SIZE;
		pmd++;
	}

	/*
	 * 4K leftovers?
	 */
	if (start < end)
		kgr_unmap_pte_range(pmd, start, end);
}

static void kgr__unmap_pud_range(pgd_t *pgd, unsigned long start,
				 unsigned long end)
{
	pud_t *pud = pud_offset(pgd, start);

	/*
	 * Not on a GB page boundary?
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;
		unsigned long pre_end	= min_t(unsigned long, end, next_page);

		kgr_unmap_pmd_range(pud, start, pre_end);

		start = pre_end;
		pud++;
	}

	/*
	 * Try to unmap in 1G chunks?
	 */
	while (end - start >= PUD_SIZE) {

		if (pud_large(*pud))
			pud_clear(pud);
		else
			kgr_unmap_pmd_range(pud, start, start + PUD_SIZE);

		start += PUD_SIZE;
		pud++;
	}

	/*
	 * 2M leftovers?
	 */
	if (start < end)
		kgr_unmap_pmd_range(pud, start, end);
}

void kgr_unmap_pud_range_nofree(pgd_t *pgd, unsigned long start,
				unsigned long end)
{
	/*
	 * With KAISER pagetables, this can't happen. But for the sake
	 * of consistency and safety...
	 */
	if (pgd_none(*pgd))
		return;

	kgr__unmap_pud_range(pgd, start, end);
}
