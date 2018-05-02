/*
 * kaiser.c
 *
 * Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/gfp.h>
#include <asm/pgalloc.h>
#include <asm/hw_irq.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <linux/list.h>
#include <asm/page.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bit_spinlock.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <uapi/asm/vsyscall.h>
#include "kaiser.h"
#include "kaiser_kallsyms.h"
#include "shared_data.h"
#include "patch_entry.h"

#if !IS_ENABLED(CONFIG_X86_VSYSCALL_EMULATION)
#error "Livepatch supports only CONFIG_X86_VSYSCALL_EMULATION=y\n"
#endif


struct kgr_pcpu_cr3s __percpu *__kgr_pcpu_cr3s;
/*
 * Provide a dummy indirect pointer to __kgr_pcpu_pgds
 * in order to allow patch_entry to patch in the references to
 * it.
 */
struct kgr_pcpu_cr3s __percpu **kgr_pcpu_cr3s = &__kgr_pcpu_cr3s;


struct mm_struct *kgr_init_mm;

/* from asm/pagetable.h */
#define kgr_pgd_offset_k(address) pgd_offset(kgr_init_mm, (address))


/*
 * For livepatching, we have to deal with user mappings of kmalloc()ed
 * regions, that is partial pages.
 *
 * Only LDTs and perf_event_intel_ds need this and thus, this case is
 * uncommon and can be slow.
 *
 * An additional complication is that in the transition period, it's
 * possible to receive a request for unmapping a region which has
 * never been registered before and these must be ignored. It follows
 * that a simple reference count per mapped page with partial
 * allocations in it is not enough.
 *
 * Instead we have to keep track of a page's regions which have
 * actually been requested to get user-mapped. This is done in units
 * of eight bytes, because that's SLAB's minimum allocation size,
 * c.f. struct page_alloc_tracking below.
 *
 * If any of a PTE page's entries requires allocation tracking, an
 * additional page holding one pointer per entry will be allocated and
 * made available through the PTE page's struct page ->index. The
 * lowest bit of those pointers will be used as a bit_spinlock
 * protecting both, the pointer value itself and the struct
 * page_alloc_tracking they point to. The lower twelve bits of the PTE
 * page's ->index serves as a reference count, i.e. it equals the
 * number of PTE entries with an associated
 * struct page_alloc_tracking.
 */

#define PAGE_ALLOC_TRACKING_BITS (PAGE_SIZE / 8)

struct page_alloc_tracking
{
	unsigned long allocated[PAGE_ALLOC_TRACKING_BITS / BITS_PER_LONG];
};


#define PTE_PAGE_ALLOC_TRACKINGS_COUNT_MASK	\
	(~PAGE_MASK)

#define PTE_PAGE_ALLOC_TRACKINGS_PTR_MASK	\
	~PTE_PAGE_ALLOC_TRACKINGS_COUNT_MASK

#define PAGE_ALLOC_TRACKING_LOCK_BIT	0
#define PAGE_ALLOC_TRACKING_PTR_MASK	~BIT(PAGE_ALLOC_TRACKING_LOCK_BIT)


static unsigned long* read_alloc_tracks_ptr(struct page const *p)
{
	long p_index;

	/* Mimic a rcu_dereference() */
	p_index = atomic_long_read((atomic_long_t *)&p->index);
	smp_read_barrier_depends();
	return (unsigned long *)((unsigned long)p_index &
				 PTE_PAGE_ALLOC_TRACKINGS_PTR_MASK);
}

static struct page_alloc_tracking* get_page_alloc_track_locked(pte_t const *pte,
							       bool create)
{
	struct page *pte_page = virt_to_page(pte);
	unsigned int pte_index;
	unsigned long *trackings;
	struct page_alloc_tracking *tracking;

	pte_index = pte - (pte_t *)((unsigned long)pte & PAGE_MASK);

	rcu_read_lock();
	trackings = read_alloc_tracks_ptr(pte_page);
	if (!trackings) {
		rcu_read_unlock();
		if (!create)
			return NULL;
		goto alloc_trackings;
	}

	bit_spin_lock(PAGE_ALLOC_TRACKING_LOCK_BIT, &trackings[pte_index]);
	tracking = (struct page_alloc_tracking *)(trackings[pte_index] &
						  PAGE_ALLOC_TRACKING_PTR_MASK);
	if (!tracking) {
		bit_spin_unlock(PAGE_ALLOC_TRACKING_LOCK_BIT,
				&trackings[pte_index]);
		rcu_read_unlock();

		if (!create)
			return NULL;

		lock_page(pte_page);
		trackings = read_alloc_tracks_ptr(pte_page);
		if (!trackings) {
			unlock_page(pte_page);
			goto alloc_trackings;
		}

		goto alloc_tracking;
	}

	rcu_read_unlock();
	return tracking;


alloc_trackings:
	trackings = (unsigned long *)get_zeroed_page(GFP_KERNEL);
	if (!trackings)
		return ERR_PTR(-ENOMEM);
	lock_page(pte_page);
	if (!pte_page->index) {
		/* Should be rcu_assign_pointer() */
		smp_store_release(&pte_page->index, (unsigned long)trackings);
	} else {
		free_page((unsigned long)trackings);
		trackings = read_alloc_tracks_ptr(pte_page);
	}

alloc_tracking:
	tracking = kzalloc(sizeof(*tracking), GFP_KERNEL);
	if (!tracking) {
		unlock_page(pte_page);
		return ERR_PTR(-ENOMEM);
	}

	bit_spin_lock(PAGE_ALLOC_TRACKING_LOCK_BIT, &trackings[pte_index]);
	if (trackings[pte_index] & PAGE_ALLOC_TRACKING_PTR_MASK) {
		kfree(tracking);
		tracking =
		   (struct page_alloc_tracking *)(trackings[pte_index] &
						  PAGE_ALLOC_TRACKING_PTR_MASK);
		unlock_page(pte_page);
		return tracking;
	}

	WRITE_ONCE(trackings[pte_index],
		   (unsigned long)tracking | BIT(PAGE_ALLOC_TRACKING_LOCK_BIT));
	atomic_long_inc((atomic_long_t *)&pte_page->index);

	unlock_page(pte_page);
	return tracking;
}

static void unlock_page_alloc_track(pte_t const *pte)
{
	struct page *pte_page = virt_to_page(pte);
	unsigned int pte_index;
	unsigned long *trackings;

	/*
	 * No need to RCU-protect here: we know that the trackings
	 * pointer page can't go away.
	 */
	pte_index = pte - (pte_t *)((unsigned long)pte & PAGE_MASK);
	trackings = read_alloc_tracks_ptr(pte_page);
	bit_spin_unlock(PAGE_ALLOC_TRACKING_LOCK_BIT, &trackings[pte_index]);
}

static void __free_alloc_tracks_rcu(struct rcu_head *head)
{
	struct page *p = container_of(head, struct page, rcu_head);

	free_page((unsigned long)pfn_to_kaddr(page_to_pfn(p)));
}

static void put_page_alloc_track(pte_t const *pte)
{
	struct page *pte_page = virt_to_page(pte);
	unsigned int pte_index;
	unsigned long *trackings;
	struct page_alloc_tracking *tracking;
	unsigned long trackings_count;

	pte_index = pte - (pte_t *)((unsigned long)pte & PAGE_MASK);

	rcu_read_lock();
	trackings = read_alloc_tracks_ptr(pte_page);
	WARN_ON(!bit_spin_is_locked(PAGE_ALLOC_TRACKING_LOCK_BIT,
				    &trackings[pte_index]));
	tracking = (struct page_alloc_tracking *)(trackings[pte_index] &
						  PAGE_ALLOC_TRACKING_PTR_MASK);

	trackings_count =
		(unsigned long)atomic_long_dec_return_relaxed
					((atomic_long_t *)&pte_page->index);
	trackings_count &= PTE_PAGE_ALLOC_TRACKINGS_COUNT_MASK;

	/* Store zero. This implies an unlock. */
	smp_store_release(&trackings[pte_index], 0);
	rcu_read_unlock();

	kfree(tracking);

	if (trackings_count)
		return;

	lock_page(pte_page);
	trackings_count =
	     (unsigned long)atomic_long_read((atomic_long_t *)&pte_page->index);
	trackings_count &= PTE_PAGE_ALLOC_TRACKINGS_COUNT_MASK;

	if (trackings_count) {
		unlock_page(pte_page);
		return;
	}

	trackings = read_alloc_tracks_ptr(pte_page);
	if (!trackings) {
		unlock_page(pte_page);
		return;
	}
	WRITE_ONCE(pte_page->index, 0);
	unlock_page(pte_page);

	call_rcu(&virt_to_page(trackings)->rcu_head, __free_alloc_tracks_rcu);
	return;
}

static void page_alloc_track_add_range(struct page_alloc_tracking *tracking,
				       unsigned long addr, unsigned long size)
{
	WARN_ON(addr % 8);
	size = ALIGN(size, 8);

	addr &= ~PAGE_MASK;
	size = min_t(unsigned long, size, PAGE_SIZE - addr);

	addr /= 8;
	size /= 8;

	bitmap_set(tracking->allocated, addr, size);
}

static void page_alloc_track_remove_range(struct page_alloc_tracking *tracking,
					  unsigned long addr,
					  unsigned long size)
{
	WARN_ON(addr % 8);
	size = ALIGN(size, 8);

	addr &= ~PAGE_MASK;
	size = min_t(unsigned long, size, PAGE_SIZE - addr);

	addr /= 8;
	size /= 8;

	bitmap_clear(tracking->allocated, addr, size);
}

static bool page_alloc_track_empty(struct page_alloc_tracking const *tracking)
{
	return bitmap_empty(tracking->allocated, PAGE_ALLOC_TRACKING_BITS);
}

static bool page_alloc_contains_range(struct page_alloc_tracking *tracking,
				      unsigned long addr,
				      unsigned long size)
{
	unsigned long range[PAGE_ALLOC_TRACKING_BITS / BITS_PER_LONG];

	WARN_ON(addr % 8);
	size = ALIGN(size, 8);

	addr &= ~PAGE_MASK;
	size = min_t(unsigned long, size, PAGE_SIZE - addr);

	addr /= 8;
	size /= 8;

	bitmap_set(range, addr, size);

	return bitmap_subset(range, tracking->allocated,
			     PAGE_ALLOC_TRACKING_BITS);
}


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

static void __free_pte_page_alloc_tracks(struct page *pte_page,
					 struct list_head *freelist)
{
	unsigned long *trackings;
	unsigned int i;

	WARN_ON(PageLocked(pte_page));

	if (likely(!pte_page->index))
		return;
	trackings = read_alloc_tracks_ptr(pte_page);
	for (i = 0; i < PTRS_PER_PTE; ++i) {
		if (!trackings[i])
			continue;
		WARN_ON(bit_spin_is_locked(PAGE_ALLOC_TRACKING_LOCK_BIT,
					   &trackings[i]));
		kfree((void *)trackings[i]);
	}

	if (freelist) {
		list_add(&virt_to_page(trackings)->lru, freelist);
		return;
	}

	free_page((unsigned long)trackings);
}

static void __free_pagetable_page(unsigned long addr,
				  struct list_head *freelist)
{
	struct page *p = virt_to_page(addr);

	__free_pte_page_alloc_tracks(p, freelist);

	if (freelist) {
		list_add(&p->lru, freelist);
		return;
	}

	free_page(addr);
}

static pte_t *kgr_kaiser_pagetable_walk(pgd_t *shadow_pgd,
					unsigned long address,
					bool create, bool user,
					struct list_head *freelist)
{
	pmd_t *pmd;
	pud_t *pud;
	pgd_t *pgd = shadow_pgd + pgd_index(address);
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK);
	unsigned long prot = _KERNPG_TABLE;

	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "All shadow pgds should have been populated");
		return ERR_PTR(-ENOENT);
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	if (user) {
		/*
		 * The vsyscall page is the only page that will have
		 *  _PAGE_USER set. Catch everything else.
		 */
		BUG_ON(address != VSYSCALL_ADDR);

		set_pgd(pgd, __pgd(pgd_val(*pgd) | _PAGE_USER));
		prot = _PAGE_TABLE;
	}

	pud = pud_offset(pgd, address);
	/* The shadow page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return ERR_PTR(-EFBIG);
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page;

		if (!create)
			return NULL;

		new_pmd_page = __alloc_pagetable_page(gfp, freelist);
		if (!new_pmd_page)
			return ERR_PTR(-ENOMEM);
		kgr_meltdown_shared_data_lock();
		if (pud_none(*pud)) {
			set_pud(pud, __pud(prot | __pa(new_pmd_page)));
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
		return ERR_PTR(-EFBIG);
	}
	if (pmd_none(*pmd)) {
		unsigned long new_pte_page;

		if (!create)
			return NULL;

		new_pte_page = __alloc_pagetable_page(gfp, freelist);
		if (!new_pte_page)
			return ERR_PTR(-ENOMEM);
		kgr_meltdown_shared_data_lock();
		if (pmd_none(*pmd)) {
			set_pmd(pmd, __pmd(prot | __pa(new_pte_page)));
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
	unsigned long start_addr = (unsigned long)__start_addr;
	unsigned long end_addr = start_addr + size;
	unsigned long addr;
	unsigned long target_address;
	struct page_alloc_tracking *alloc_track = NULL;

	/*
	 * It is convenient for callers to pass in __PAGE_KERNEL etc,
	 * and there is no actual harm from setting _PAGE_GLOBAL, so
	 * long as CR4.PGE is not set.  But it is nonetheless troubling
	 * to see Kaiser itself setting _PAGE_GLOBAL (now that "nokaiser"
	 * requires that not to be #defined to 0): so mask it off here.
	 */
	flags &= ~_PAGE_GLOBAL;

	for (addr = start_addr; addr < end_addr;
	     addr &= PAGE_MASK, addr += PAGE_SIZE) {
		target_address = get_pa_from_mapping(addr) & PAGE_MASK;
		if (target_address == -1) {
			ret = -EIO;
			break;
		}
		pte = kgr_kaiser_pagetable_walk(shadow_pgd, addr, true,
						flags & _PAGE_USER,
						freelist);
		if (IS_ERR(pte)) {
			ret = PTR_ERR(pte);
			break;
		}

		if (addr & ~PAGE_MASK || end_addr - addr < PAGE_SIZE) {
			/* Partial page allocation */
			unsigned long alloc_size;

			alloc_size = min_t(unsigned long,
					   PAGE_SIZE - (addr & ~PAGE_MASK),
					   end_addr - addr);

			alloc_track = get_page_alloc_track_locked(pte, true);
			if (IS_ERR(alloc_track))
				return PTR_ERR(alloc_track);
			page_alloc_track_add_range(alloc_track, addr,
						   alloc_size);
		}

		if (pte_none(*pte)) {
			set_pte(pte, __pte(flags | target_address));
		} else {
			pte_t tmp;
			set_pte(&tmp, __pte(flags | target_address));
			WARN_ON_ONCE(!pte_same(*pte, tmp));
		}

		if (alloc_track)
			unlock_page_alloc_track(pte);
	}

	kgr_kaiser_flush_tlb_on_return_to_user();
	return ret;
}


static void kgr_kaiser_remove_user_map(pgd_t *shadow_pgd,
				       const void *__start_addr,
				       unsigned long size)
{
	pte_t *pte;
	unsigned long start_addr = (unsigned long)__start_addr;
	unsigned long end_addr = start_addr + size;
	unsigned long addr;

	for (addr = start_addr; addr < end_addr;
	     addr &= PAGE_MASK, addr += PAGE_SIZE) {
		pte = kgr_kaiser_pagetable_walk(shadow_pgd, addr, false, false,
						NULL);
		if (!pte)
			continue;

		if (unlikely(addr & ~PAGE_MASK ||
			     end_addr - addr < PAGE_SIZE)) {
			/* Partial page allocation */
			struct page_alloc_tracking *alloc_track;
			unsigned long alloc_size;

			alloc_track = get_page_alloc_track_locked(pte, false);
			if (!alloc_track) {
				WARN_ON(!pte_none(*pte));
				continue;
			}

			alloc_size = min_t(unsigned long,
					   PAGE_SIZE - (addr & ~PAGE_MASK),
					   end_addr - addr);
			page_alloc_track_remove_range(alloc_track, addr,
						      alloc_size);
			if (page_alloc_track_empty(alloc_track)) {
				set_pte(pte, __pte(0));
				put_page_alloc_track(pte);
			} else {
				unlock_page_alloc_track(pte);
			}
		} else {
			set_pte(pte, __pte(0));
		}
	}

	kgr_kaiser_flush_tlb_on_return_to_user();
}

static bool kgr_kaiser_is_user_mapped(pgd_t *shadow_pgd,
				      const void *__start_addr,
				      unsigned long size)
{
	pte_t *pte;
	unsigned long start_addr = (unsigned long)__start_addr;
	unsigned long end_addr = start_addr + size;
	unsigned long addr;

	for (addr = start_addr; addr < end_addr;
	     addr &= PAGE_MASK, addr += PAGE_SIZE) {
		pte = kgr_kaiser_pagetable_walk(shadow_pgd, addr, false, false,
						NULL);
		if (!pte)
			return false;

		if (unlikely(addr & ~PAGE_MASK ||
			     end_addr - addr < PAGE_SIZE)) {
			/* Partial page allocation */
			struct page_alloc_tracking *alloc_track;
			unsigned long alloc_size;

			alloc_track = get_page_alloc_track_locked(pte, false);
			if (!alloc_track) {
				WARN_ON(!pte_none(*pte));
				return false;
			} else {
				WARN_ON(pte_none(*pte));
			}

			alloc_size = min_t(unsigned long,
					   PAGE_SIZE - (addr & ~PAGE_MASK),
					   end_addr - addr);
			if (!page_alloc_contains_range(alloc_track, addr,
						       alloc_size)) {
				unlock_page_alloc_track(pte);
				return false;
			}
			unlock_page_alloc_track(pte);
		} else {
			if (pte_none(*pte))
				return false;
		}
	}

	return true;
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

enum kgr_vsyscall_mode_enum *kgr_vsyscall_mode;

char (*kgr__entry_text_start)[];
char (*kgr__entry_text_end)[];

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

static int kgr_kaiser_prepopulate_shadow_pgd(pgd_t *shadow_pgd,
					     struct list_head *freelist)
{
	int r;
	int cpu;

	/*
	 * Note that this sets _PAGE_USER and it needs to happen when the
	 * pagetable hierarchy gets created, i.e., early. Otherwise
	 * kaiser_pagetable_walk() will encounter initialized PTEs in the
	 * hierarchy and not set the proper permissions, leading to the
	 * pagefaults with page-protection violations when trying to read the
	 * vsyscall page. For example.
	 */
	if (*kgr_vsyscall_mode != KGR_VSYSCALL_MODE_NONE) {
		r = kgr_kaiser_add_user_map(shadow_pgd, (void *)VSYSCALL_ADDR,
					    PAGE_SIZE, __PAGE_KERNEL_VSYSCALL,
					    freelist);
		if (r)
			return r;
	}

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

	r = kgr_kaiser_add_user_map_ptrs(shadow_pgd, kgr__entry_text_start,
					 kgr__entry_text_end,
					__PAGE_KERNEL_RX, freelist);
	if (r)
		return r;

	r = kgr_kaiser_add_user_map_ptrs(shadow_pgd, kgr__irqentry_text_start,
					 kgr__irqentry_text_end,
					__PAGE_KERNEL_RX, freelist);
	if (r)
		return r;

	for_each_possible_cpu(cpu) {
		r = kgr_kaiser_add_user_map(shadow_pgd,
			per_cpu_ptr(kgr_meltdown_shared_data->pcpu_cr3s, cpu),
			sizeof(struct kgr_pcpu_cr3s), __PAGE_KERNEL,
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

int kgr_kaiser_add_mapping(unsigned long addr, unsigned long size,
			   unsigned long flags)
{
	if (kgr_meltdown_patch_state() < ps_activating)
		return 0;

	return kgr_kaiser_add_user_map(kgr_meltdown_shared_data->shadow_pgd,
				       (const void *)addr, size, flags, NULL);
}

void kgr_kaiser_remove_mapping(unsigned long start, unsigned long size)
{
	if (kgr_meltdown_patch_state() < ps_activating)
		return;

	kgr_kaiser_remove_user_map(kgr_meltdown_shared_data->shadow_pgd,
				   (const void *)start, size);
}

bool kgr_kaiser_is_mapped(unsigned long start, unsigned long size)
{
	if (kgr_meltdown_patch_state() < ps_activating)
		return false;

	return kgr_kaiser_is_user_mapped(kgr_meltdown_shared_data->shadow_pgd,
					 (const void *)start, size);
}

/*
 * Page table pages are page-aligned.  The lower half of the top
 * level is used for userspace and the top half for the kernel.
 * This returns true for user pages that need to get copied into
 * both the user and kernel copies of the page tables, and false
 * for kernel pages that should only be in the kernel copy.
 */
static inline bool is_userspace_pgd(pgd_t *pgdp)
{
	return ((unsigned long)pgdp % PAGE_SIZE) < (PAGE_SIZE / 2);
}

pgd_t kgr_kaiser_set_shadow_pgd(pgd_t *kern_pgdp, pgd_t pgd)
{
	pgd_t *kern_pgd;
	pgd_t *user_pgd;
	pgd_t *user_pgdp;

	if (kgr_meltdown_patch_state() < ps_activating)
		return pgd;

	if (!(pgd.pgd & _PAGE_USER) && pgd.pgd)
		return pgd;

	if (!is_userspace_pgd(kern_pgdp))
		return pgd;

	kern_pgd = (pgd_t *)((unsigned long)kern_pgdp & PAGE_MASK);
	rcu_read_lock();
	user_pgd = kgr_user_pgd_rcu(kern_pgd);
	if (!user_pgd)
		return pgd;
	user_pgdp = user_pgd + (kern_pgdp - kern_pgd);
	user_pgdp->pgd = pgd.pgd;
	rcu_read_unlock();

	/*
	 * Note: upstream kaiser conditionally sets _PAGE_NX on the
	 * kernel's pgd instance. For livepatch
	 * revertability, we must not do that.
	 */
	return pgd;
}

int __init kgr_kaiser_init(void)
{
	__kgr_pcpu_cr3s = kgr_meltdown_shared_data->pcpu_cr3s;
	return 0;
}

void kgr_kaiser_cleanup(void)
{}
