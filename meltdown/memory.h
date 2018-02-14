#ifndef _KGR_MEMORY_H
#define _KGR_MEMORY_H

#include <asm/page.h>

struct mmu_gather;

int kgr__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
void kgr_free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling);

#endif
