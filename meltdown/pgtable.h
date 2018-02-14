#ifndef _KGR_PGTABLE_H
#define _KGR_PGTABLE_H

#include <asm/page.h>

struct mm_struct;

pgd_t *kgr_pgd_alloc(struct mm_struct *mm);
void kgr_pgd_free(struct mm_struct *mm, pgd_t *pgd);

void kgr_free_all_user_pgds(void);

#endif
