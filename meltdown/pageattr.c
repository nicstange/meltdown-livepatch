#include <asm/pgalloc.h>
#include "pageattr.h"

/* from arch/x86/mm/pageattr.c */

struct cpa_data {
	unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	int		flags;
	unsigned long	pfn;
	unsigned	force_split : 1;
	int		curpage;
	struct page	**pages;
};

#define CPA_FREE_PAGETABLES 8

static bool kgr_try_to_free_pte_page(struct cpa_data *cpa, pte_t *pte)
{
	int i;

	if (!(cpa->flags & CPA_FREE_PAGETABLES))
		return false;

	for (i = 0; i < PTRS_PER_PTE; i++)
		if (!pte_none(pte[i]))
			return false;

	free_page((unsigned long)pte);
	return true;
}

static bool kgr_try_to_free_pmd_page(struct cpa_data *cpa, pmd_t *pmd)
{
	int i;

	if (!(cpa->flags & CPA_FREE_PAGETABLES))
		return false;

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_none(pmd[i]))
			return false;

	free_page((unsigned long)pmd);
	return true;
}

static bool kgr_unmap_pte_range(struct cpa_data *cpa, pmd_t *pmd,
				unsigned long start, unsigned long end)
{
	pte_t *pte;

	if (pmd_none(*pmd))
		return true;

	pte = pte_offset_kernel(pmd, start);

	while (start < end) {
		set_pte(pte, __pte(0));

		start += PAGE_SIZE;
		pte++;
	}

	if (kgr_try_to_free_pte_page(cpa, (pte_t *)pmd_page_vaddr(*pmd))) {
		pmd_clear(pmd);
		return true;
	}
	return false;
}

static void kgr__unmap_pmd_range(struct cpa_data *cpa, pud_t *pud, pmd_t *pmd,
				 unsigned long start, unsigned long end)
{
	if (kgr_unmap_pte_range(cpa, pmd, start, end))
		if (kgr_try_to_free_pmd_page(cpa, (pmd_t *)pud_page_vaddr(*pud)))
			pud_clear(pud);
}

static void kgr_unmap_pmd_range(struct cpa_data *cpa, pud_t *pud,
				unsigned long start, unsigned long end)
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

		kgr__unmap_pmd_range(cpa, pud, pmd, start, pre_end);

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
			kgr__unmap_pmd_range(cpa, pud, pmd, start, start + PMD_SIZE);

		start += PMD_SIZE;
		pmd++;
	}

	/*
	 * 4K leftovers?
	 */
	if (start < end)
		return kgr__unmap_pmd_range(cpa, pud, pmd, start, end);

	/*
	 * Try again to free the PMD page if haven't succeeded above.
	 */
	if (!pud_none(*pud))
		if (kgr_try_to_free_pmd_page(cpa, (pmd_t *)pud_page_vaddr(*pud)))
			pud_clear(pud);
}

static void kgr__unmap_pud_range(struct cpa_data *cpa, pgd_t *pgd,
				 unsigned long start, unsigned long end)
{
	pud_t *pud = pud_offset(pgd, start);

	/*
	 * Not on a GB page boundary?
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;
		unsigned long pre_end	= min_t(unsigned long, end, next_page);

		kgr_unmap_pmd_range(cpa, pud, start, pre_end);

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
			kgr_unmap_pmd_range(cpa, pud, start, start + PUD_SIZE);

		start += PUD_SIZE;
		pud++;
	}

	/*
	 * 2M leftovers?
	 */
	if (start < end)
		kgr_unmap_pmd_range(cpa, pud, start, end);

	/*
	 * No need to try to free the PUD page because we'll free it in
	 * populate_pgd's error path
	 */
}

void kgr_unmap_pud_range_nofree(pgd_t *pgd, unsigned long start,
				unsigned long end)
{
	struct cpa_data cpa = {
		.flags = 0,
	};

	/*
	 * With KAISER pagetables, this can't happen. But for the sake
	 * of consistency and safety...
	 */
	if (pgd_none(*pgd))
		return;

	kgr__unmap_pud_range(&cpa, pgd, start, end);
}
