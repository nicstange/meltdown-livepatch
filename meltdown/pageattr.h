#ifndef _KGR_PAGEATTR_H
#define _KGR_PAGEATTR_H

void kgr_unmap_pud_range_nofree(pgd_t *pgd, unsigned long start,
				unsigned long end);

#endif
