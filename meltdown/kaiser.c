#include <linux/gfp.h>
#include <asm/pgalloc.h>
#include <asm/hw_irq.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <linux/list.h>
#include <asm/page.h>
#include "kaiser.h"
#include "shared_data.h"
#include "patch_entry.h"

struct kgr_pcpu_pgds __percpu *__kgr_pcpu_pgds;
/*
 * Provide a dummy indirect pointer to __kgr_pcpu_pgds
 * in order to allow patch_entry to patch in the references to
 * it.
 */
struct kgr_pcpu_pgds __percpu **kgr_pcpu_pgds = &__kgr_pcpu_pgds;


struct mm_struct *kgr_init_mm;

/* from asm/pagetable.h */
#define kgr_pgd_offset_k(address) pgd_offset(kgr_init_mm, (address))


static inline unsigned long get_pa_from_mapping(unsigned long vaddr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = kgr_pgd_offset_k(vaddr);
	/*
	 * We made all the kernel PGDs present in kaiser_init().
	 * We expect them to stay that way.
	 */
	BUG_ON(pgd_none(*pgd));
	/*
	 * PGDs are either 512GB or 128TB on all x86_64
	 * configurations.  We don't handle these.
	 */
	BUG_ON(pgd_large(*pgd));

	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pud_large(*pud))
		return (pud_pfn(*pud) << PAGE_SHIFT) | (vaddr & ~PUD_PAGE_MASK);

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pmd_large(*pmd))
		return (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_PAGE_MASK);

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	return (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
}


static unsigned long __alloc_pagetable_page(gfp_t gfp,
					    struct list_head *freelist)
{
	unsigned long addr;

	if (freelist && !list_empty(freelist)) {
		struct page *p = list_first_entry(freelist, struct page, lru);
		list_del_init(&p->lru);
		addr = (unsigned long)pfn_to_kaddr(page_to_pfn(p));
		memset((void*)addr, 0, PAGE_SIZE);
		return addr;
	}

	addr = get_zeroed_page(gfp);
	return (unsigned long)addr;
}

static void __free_pagetable_page(unsigned long addr,
				  struct list_head *freelist)
{
	if (freelist) {
		struct page *p = virt_to_page(addr);
		list_add(&p->lru, freelist);
		return;
	}

	free_page(addr);
}

static pte_t *kgr_kaiser_pagetable_walk(pgd_t *shadow_pgd,
					unsigned long address,
					struct list_head *freelist)
{
	pmd_t *pmd;
	pud_t *pud;
	pgd_t *pgd = shadow_pgd + pgd_index(address);
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK);

	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "All shadow pgds should have been populated");
		return NULL;
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	pud = pud_offset(pgd, address);
	/* The shadow page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page =
			__alloc_pagetable_page(gfp, freelist);
		if (!new_pmd_page)
			return NULL;
		kgr_meltdown_shared_data_lock();
		if (pud_none(*pud)) {
			set_pud(pud, __pud(_KERNPG_TABLE | __pa(new_pmd_page)));
			__inc_zone_page_state(virt_to_page((void *)
					      new_pmd_page), NR_PAGETABLE);
		} else
			__free_pagetable_page(new_pmd_page, freelist);
		kgr_meltdown_shared_data_unlock();
	}

	pmd = pmd_offset(pud, address);
	/* The shadow page tables do not use large mappings: */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}
	if (pmd_none(*pmd)) {
		unsigned long new_pte_page =
			__alloc_pagetable_page(gfp, freelist);
		if (!new_pte_page)
			return NULL;
		kgr_meltdown_shared_data_lock();
		if (pmd_none(*pmd)) {
			set_pmd(pmd, __pmd(_KERNPG_TABLE | __pa(new_pte_page)));
			__inc_zone_page_state(virt_to_page((void *)
						new_pte_page), NR_PAGETABLE);
		} else
			__free_pagetable_page(new_pte_page, freelist);
		kgr_meltdown_shared_data_unlock();
	}

	return pte_offset_kernel(pmd, address);
}

static int kgr_kaiser_add_user_map(pgd_t *shadow_pgd,
				   const void *__start_addr, unsigned long size,
				   unsigned long flags,
				   struct list_head *freelist)
{
	int ret = 0;
	pte_t *pte;
	unsigned long start_addr = (unsigned long )__start_addr;
	unsigned long address = start_addr & PAGE_MASK;
	unsigned long end_addr = PAGE_ALIGN(start_addr + size);
	unsigned long target_address;

	/*
	 * It is convenient for callers to pass in __PAGE_KERNEL etc,
	 * and there is no actual harm from setting _PAGE_GLOBAL, so
	 * long as CR4.PGE is not set.  But it is nonetheless troubling
	 * to see Kaiser itself setting _PAGE_GLOBAL (now that "nokaiser"
	 * requires that not to be #defined to 0): so mask it off here.
	 */
	flags &= ~_PAGE_GLOBAL;

	for (; address < end_addr; address += PAGE_SIZE) {
		target_address = get_pa_from_mapping(address);
		if (target_address == -1) {
			ret = -EIO;
			break;
		}
		pte = kgr_kaiser_pagetable_walk(shadow_pgd, address, freelist);
		if (!pte) {
			ret = -ENOMEM;
			break;
		}
		if (pte_none(*pte)) {
			set_pte(pte, __pte(flags | target_address));
		} else {
			pte_t tmp;
			set_pte(&tmp, __pte(flags | target_address));
			WARN_ON_ONCE(!pte_same(*pte, tmp));
		}
	}
	return ret;
}

static int kgr_kaiser_add_user_map_ptrs(pgd_t *shadow_pgd,
					const void *start, const void *end,
					unsigned long flags,
					struct list_head *freelist)
{
	unsigned long size = end - start;

	return kgr_kaiser_add_user_map(shadow_pgd, start, size, flags,
				       freelist);
}


char (*kgr__irqentry_text_start)[];
char (*kgr__irqentry_text_end)[];

char (*kgr_exception_stacks)
	[(N_EXCEPTION_STACKS - 1) * EXCEPTION_STKSZ + DEBUG_STKSZ];

vector_irq_t *kgr_vector_irq;

#define MAX_PEBS_EVENTS		8
struct debug_store {
	u64	bts_buffer_base;
	u64	bts_index;
	u64	bts_absolute_maximum;
	u64	bts_interrupt_threshold;
	u64	pebs_buffer_base;
	u64	pebs_index;
	u64	pebs_absolute_maximum;
	u64	pebs_interrupt_threshold;
	u64	pebs_event_reset[MAX_PEBS_EVENTS];
};

struct debug_store *kgr_cpu_debug_store;

static int kgr_kaiser_prepopulate_shadow_pgd(pgd_t *shadow_pgd,
					     struct list_head *freelist)
{
	int r;
	int cpu;

	r = kgr_kaiser_add_user_map_ptrs(shadow_pgd, __kgr_entry_text_begin,
					 __kgr_entry_text_end,
					 __PAGE_KERNEL_RX, freelist);
	if (r)
		return r;

	r = kgr_kaiser_add_user_map(shadow_pgd, kgr_idt_table,
				    sizeof(kgr_idt_table), __PAGE_KERNEL_RO,
				    freelist);
	if (r)
		return r;

	r = kgr_kaiser_add_user_map(shadow_pgd, kgr_debug_idt_table,
				    sizeof(kgr_debug_idt_table),
				    __PAGE_KERNEL_RO, freelist);
	if (r)
		return r;

	r = kgr_kaiser_add_user_map(shadow_pgd, kgr_trace_idt_table,
				    sizeof(kgr_trace_idt_table),
				    __PAGE_KERNEL_RO, freelist);
	if (r)
		return r;

	r = kgr_kaiser_add_user_map_ptrs(shadow_pgd, kgr__irqentry_text_start,
					 kgr__irqentry_text_end,
					__PAGE_KERNEL_RX, freelist);
	if (r)
		return r;

	for_each_possible_cpu(cpu) {
		r = kgr_kaiser_add_user_map(shadow_pgd,
			per_cpu_ptr(kgr_meltdown_shared_data->pcpu_pgds, cpu),
			sizeof(struct kgr_pcpu_pgds), __PAGE_KERNEL,
			freelist);
		if (r)
			return r;

		r = kgr_kaiser_add_user_map(shadow_pgd,
					    per_cpu_ptr(&cpu_tss, cpu),
					    sizeof(cpu_tss),
					    __PAGE_KERNEL, freelist);
		if (r)
			return r;

		r = kgr_kaiser_add_user_map(shadow_pgd,
					    per_cpu_ptr(&gdt_page, cpu),
					    sizeof(gdt_page),
					    __PAGE_KERNEL, freelist);
		if (r)
			return r;

		r = kgr_kaiser_add_user_map(shadow_pgd,
					per_cpu_ptr(kgr_exception_stacks, cpu),
					sizeof(*kgr_exception_stacks),
					__PAGE_KERNEL, freelist);
		if (r)
			return r;

		r = kgr_kaiser_add_user_map(shadow_pgd,
					    per_cpu_ptr(kgr_vector_irq, cpu),
					    sizeof(*kgr_vector_irq),
					    __PAGE_KERNEL, freelist);
		if (r)
			return r;

		r = kgr_kaiser_add_user_map(shadow_pgd,
					per_cpu_ptr(kgr_cpu_debug_store, cpu),
					sizeof(*kgr_cpu_debug_store),
					__PAGE_KERNEL, freelist);
		if (r)
			return r;
	}

	return 0;
}

static void __kgr_kaiser_free_shadow_pgd(pgd_t *shadow_pgd,
					 struct list_head *freelist)
{
	unsigned int i, j, k;
	pud_t *pud;
	pmd_t *pmd;

	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		if (pgd_none(shadow_pgd[i]))
			continue;

		pud = (pud_t *)pgd_page_vaddr(shadow_pgd[i]);
		for (j = 0; j < PTRS_PER_PUD; ++j) {
			if (pud_none(pud[j]))
				continue;

			pmd = (pmd_t *)pud_page_vaddr(pud[j]);
			for (k = 0; k < PTRS_PER_PMD; ++k) {
				if (pmd_none(pmd[k]))
					continue;
				dec_zone_page_state(pmd_page(*pmd),
						    NR_PAGETABLE);
				__free_pagetable_page(pmd_page_vaddr(pmd[k]),
						      freelist);
			}

			dec_zone_page_state(virt_to_page(pmd), NR_PAGETABLE);
			__free_pagetable_page((unsigned long)pmd, freelist);
		}

		dec_zone_page_state(virt_to_page(pud), NR_PAGETABLE);
		__free_pagetable_page((unsigned long)pud, freelist);
	}

	dec_zone_page_state(virt_to_page(shadow_pgd), NR_PAGETABLE);
	__free_pagetable_page((unsigned long)shadow_pgd, freelist);
}

/* This resembles kaiser_init(). */
static pgd_t* __kgr_kaiser_create_shadow_pgd(struct list_head *freelist)
{
	pgd_t *shadow_pgd;
	int i = 0;
	int r;

	shadow_pgd = (pgd_t *)__alloc_pagetable_page(GFP_KERNEL, freelist);
	if (!shadow_pgd)
		return NULL;
	inc_zone_page_state(virt_to_page(shadow_pgd), NR_PAGETABLE);

	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		pgd_t new_pgd;
		pud_t *pud =
			(pud_t *)__alloc_pagetable_page(GFP_KERNEL|__GFP_REPEAT,
							freelist);
		if (!pud) {
			__kgr_kaiser_free_shadow_pgd(shadow_pgd, freelist);
			return NULL;
		}
		inc_zone_page_state(virt_to_page(pud), NR_PAGETABLE);

		new_pgd = __pgd(_KERNPG_TABLE |__pa(pud));
		set_pgd(shadow_pgd + i, new_pgd);
	}

	r = kgr_kaiser_prepopulate_shadow_pgd(shadow_pgd, freelist);
	if (r) {
		__kgr_kaiser_free_shadow_pgd(shadow_pgd, freelist);
		return NULL;
	}

	return shadow_pgd;
}

pgd_t* kgr_kaiser_create_shadow_pgd()
{
	return __kgr_kaiser_create_shadow_pgd(NULL);
}

void kgr_kaiser_free_shadow_pgd(pgd_t *shadow_pgd)
{
	__kgr_kaiser_free_shadow_pgd(shadow_pgd, NULL);
}

pgd_t* kgr_kaiser_reset_shadow_pgd(pgd_t *old_shadow_pgd)
{
	pgd_t *new_shadow_pgd;
	LIST_HEAD(freelist);

	/*
	 * Free the old_shadow_pgd's recursively and put the pages on
	 * freelist: under the assumption that old_shadow_pgd had been
	 * prepopulated, the subsequent __kgr_kaiser_free_shadow_pgd()
	 * can't fail then.
	 */
	__kgr_kaiser_free_shadow_pgd(old_shadow_pgd, &freelist);
	new_shadow_pgd = __kgr_kaiser_create_shadow_pgd(&freelist);

	while (!list_empty(&freelist)) {
		struct page *p = list_first_entry(&freelist, struct page, lru);
		list_del_init(&p->lru);
		free_page((unsigned long)pfn_to_kaddr(page_to_pfn(p)));
	}

	return new_shadow_pgd;
}

int __init kgr_kaiser_init(void)
{
	__kgr_pcpu_pgds = kgr_meltdown_shared_data->pcpu_pgds;
	return 0;
}

void kgr_kaiser_cleanup(void)
{}
