#include "kaiser.h"
#include "pgtable-generic.h"

/* Patched, calls pgd_clear() */
void kgr_pgd_clear_bad(pgd_t *pgd)
{
	pgd_ERROR(*pgd);
	kgr_pgd_clear(pgd);
}
