#ifndef _MEMORY_KALLSYMS_H
#define _MEMORY_KALLSYMS_H

#include <asm/page.h>

struct mmu_gather;
struct page;

extern void (*kgr___pte_free_tlb)(struct mmu_gather *tlb, struct page *pte);
extern void (*kgr___pmd_free_tlb)(struct mmu_gather *tlb, pmd_t *pmd);
extern void (*kgr___pud_free_tlb)(struct mmu_gather *tlb, pud_t *pud);
extern void (*kgr_pud_clear_bad)(pud_t *);
extern void (*kgr_pmd_clear_bad)(pmd_t *);

#define MEMORY_KALLSYMS						\
	{ "___pte_free_tlb", (void *)&kgr___pte_free_tlb },		\
	{ "___pmd_free_tlb", (void *)&kgr___pmd_free_tlb },		\
	{ "___pud_free_tlb", (void *)&kgr___pud_free_tlb },		\
	{ "pud_clear_bad", (void *)&kgr_pud_clear_bad },		\
	{ "pmd_clear_bad", (void *)&kgr_pmd_clear_bad },		\

#endif
