#include <linux/mm.h>
#include <linux/spinlock.h>
#include <asm/paravirt.h>
#include <asm/pgalloc.h>
#include "shared_data.h"
#include "kaiser.h"
#include "pgtable.h"
#include "pgtable_kallsyms.h"

#if IS_ENABLED(CONFIG_X86_PAE)
#error "Livepatch supports only CONFIG_X86_PAE=n"
#endif

spinlock_t *kgr_pgd_lock;
struct list_head *kgr_pgd_list;
pgd_t (*kgr_init_level4_pgt)[];

/* from arch/x86/mm/pgtable.c */
/* line 10 */
#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO

/* line 87 */
/* inlined */
static inline void kgr_pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_add(&page->lru, kgr_pgd_list);
}

/* line 94 */
/* inlined */
static inline void kgr_pgd_list_del(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_del(&page->lru);
}

/* line 105 */
/* inlined */
static void kgr_pgd_set_mm(pgd_t *pgd, struct mm_struct *mm)
{
	BUILD_BUG_ON(sizeof(virt_to_page(pgd)->index) < sizeof(mm));
	virt_to_page(pgd)->index = (pgoff_t)mm;
}

/* line 116 */
/* inlined */
static void kgr_pgd_ctor(struct mm_struct *mm, pgd_t *pgd)
{
	/* If the pgd points to a shared pagetable level (either the
	   ptes in non-PAE, or shared PMD in PAE), then just copy the
	   references from swapper_pg_dir. */
	if (CONFIG_PGTABLE_LEVELS == 2 ||
	    (CONFIG_PGTABLE_LEVELS == 3 && SHARED_KERNEL_PMD) ||
	    CONFIG_PGTABLE_LEVELS == 4) {
		clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
				(*kgr_init_level4_pgt) + KERNEL_PGD_BOUNDARY,
				KERNEL_PGD_PTRS);
	}

	/* list required to sync kernel mapping updates */
	if (!SHARED_KERNEL_PMD) {
		kgr_pgd_set_mm(pgd, mm);
		kgr_pgd_list_add(pgd);
	}
}

/* line 135 */
/* inlined */
static void kgr_pgd_dtor(pgd_t *pgd)
{
	if (SHARED_KERNEL_PMD)
		return;

	spin_lock(kgr_pgd_lock);
	kgr_pgd_list_del(pgd);
	spin_unlock(kgr_pgd_lock);
}

/* line 191 */
#define PREALLOCATED_PMDS	0

/* line 194 */
/* inlined */
static void kgr_free_pmds(struct mm_struct *mm, pmd_t *pmds[])
{
	int i;

	for(i = 0; i < PREALLOCATED_PMDS; i++)
		if (pmds[i]) {
			pgtable_pmd_page_dtor(virt_to_page(pmds[i]));
			free_page((unsigned long)pmds[i]);
			mm_dec_nr_pmds(mm);
		}
}

/* line 206 */
/* inlined */
static int kgr_preallocate_pmds(struct mm_struct *mm, pmd_t *pmds[])
{
	int i;
	bool failed = false;

	for(i = 0; i < PREALLOCATED_PMDS; i++) {
		pmd_t *pmd = (pmd_t *)__get_free_page(PGALLOC_GFP);
		if (!pmd)
			failed = true;
		if (pmd && !pgtable_pmd_page_ctor(virt_to_page(pmd))) {
			free_page((unsigned long)pmd);
			pmd = NULL;
			failed = true;
		}
		if (pmd)
			mm_inc_nr_pmds(mm);
		pmds[i] = pmd;
	}

	if (failed) {
		kgr_free_pmds(mm, pmds);
		return -ENOMEM;
	}

	return 0;
}

/* line 239 */
/* inlined */
static void kgr_pgd_mop_up_pmds(struct mm_struct *mm, pgd_t *pgdp)
{
	int i;

	for(i = 0; i < PREALLOCATED_PMDS; i++) {
		pgd_t pgd = pgdp[i];

		if (pgd_val(pgd) != 0) {
			pmd_t *pmd = (pmd_t *)pgd_page_vaddr(pgd);

			pgdp[i] = native_make_pgd(0);

			paravirt_release_pmd(pgd_val(pgd) >> PAGE_SHIFT);
			pmd_free(mm, pmd);
			mm_dec_nr_pmds(mm);
		}
	}
}

/* line 258 */
/* inlined */
static void kgr_pgd_prepopulate_pmd(struct mm_struct *mm, pgd_t *pgd,
				    pmd_t *pmds[])
{
	pud_t *pud;
	int i;

	if (PREALLOCATED_PMDS == 0) /* Work around gcc-3.4.x bug */
		return;

	pud = pud_offset(pgd, 0);

	for (i = 0; i < PREALLOCATED_PMDS; i++, pud++) {
		pmd_t *pmd = pmds[i];

		if (i >= KERNEL_PGD_BOUNDARY)
			memcpy(pmd, (pmd_t *)pgd_page_vaddr((*kgr_init_level4_pgt)[i]),
			       sizeof(pmd_t) * PTRS_PER_PMD);

		pud_populate(mm, pud, pmd);
	}
}

/* line 343 */
/* inlined */
static inline pgd_t *kgr__pgd_alloc(void)
{
	return (pgd_t *)__get_free_page(PGALLOC_GFP);
}

/* line 348 */
/* inlined */
static inline void kgr__pgd_free(pgd_t *pgd)
{
	free_page((unsigned long)pgd);
}


/* Patched */
pgd_t *kgr_pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	pgd_t *user_pgd = NULL;
	pmd_t *pmds[PREALLOCATED_PMDS];

	pgd = kgr__pgd_alloc();

	if (pgd == NULL)
		goto out;

	/*
	 * Fix CVE-2017-5754
	 *  +5 lines
	 */
	if (kgr_meltdown_active()) {
		user_pgd = kgr__pgd_alloc();
		if (!user_pgd)
			goto out_free_pgd;
	}

	mm->pgd = pgd;

	if (kgr_preallocate_pmds(mm, pmds) != 0)
		/*
		 * Fix CVE-2017-5754
		 *  -1 line, +1 line
		 */
		goto out_free_user_pgd;

	if (paravirt_pgd_alloc(mm) != 0)
		goto out_free_pmds;

	/*
	 * Make sure that pre-populating the pmds is atomic with
	 * respect to anything walking the pgd_list, so that they
	 * never see a partially populated pgd.
	 */
	spin_lock(kgr_pgd_lock);
	/*
	 * Fix CVE-2017-5754
	 *  +8 lines
	 */
	if (kgr_meltdown_active() && user_pgd) {
		memcpy(user_pgd + KERNEL_PGD_BOUNDARY,
		     kgr_meltdown_shared_data->shadow_pgd + KERNEL_PGD_BOUNDARY,
		     KERNEL_PGD_PTRS * sizeof(pgd_t));
		mm->suse_kabi_padding = user_pgd;
	} else if (user_pgd) {
		kgr__pgd_free(user_pgd);
	}

	kgr_pgd_ctor(mm, pgd);
	kgr_pgd_prepopulate_pmd(mm, pgd, pmds);

	spin_unlock(kgr_pgd_lock);

	return pgd;

out_free_pmds:
	kgr_free_pmds(mm, pmds);
	/*
	 * Fix CVE-2017-5754
	 *  +3 lines
	 */
out_free_user_pgd:
	if (user_pgd)
		kgr__pgd_free(user_pgd);
out_free_pgd:
	kgr__pgd_free(pgd);
out:
	return NULL;
}

/* Patched */
void kgr_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	kgr_pgd_mop_up_pmds(mm, pgd);
	kgr_pgd_dtor(pgd);
	/*
	 * Fix CVE-2017-5754
	 *  +3 lines
	 */
	if (mm->suse_kabi_padding) {
		kgr__pgd_free(mm->suse_kabi_padding);
		mm->suse_kabi_padding = NULL;
	}
	paravirt_pgd_free(mm, pgd);
	kgr__pgd_free(pgd);
}


static void __free_all_user_pgds(struct rcu_head *head)
{
	struct page *user_pgd_page, *next_user_pgd_page;

	user_pgd_page = container_of(head, struct page, rcu_head);
	while (user_pgd_page) {
		next_user_pgd_page = (struct page *)user_pgd_page->index;
		user_pgd_page->index = 0;
		kgr__pgd_free(pfn_to_kaddr(page_to_pfn(user_pgd_page)));
		user_pgd_page = next_user_pgd_page;
	}
}

void kgr_free_all_user_pgds(void)
{
	struct page *pgd_page, *user_pgd_page;
	void *user_pgd;
	struct mm_struct *mm;
	struct page *first_user_pgd_page = NULL;

	spin_lock(kgr_pgd_lock);
	list_for_each_entry(pgd_page, kgr_pgd_list, lru) {
		mm = (struct mm_struct *)pgd_page->index;
		if (!mm)
			continue;

		user_pgd = mm->suse_kabi_padding;
		if (!user_pgd)
			continue;

		user_pgd_page = virt_to_page(user_pgd);
		user_pgd_page->index = (unsigned long)first_user_pgd_page;
		first_user_pgd_page = user_pgd_page;
		rcu_assign_pointer(mm->suse_kabi_padding, NULL);
	}
	spin_unlock(kgr_pgd_lock);

	if (!first_user_pgd_page)
		return;

	call_rcu(&first_user_pgd_page->rcu_head, __free_all_user_pgds);
}
