#ifndef _KAISER_H
#define _KAISER_H

#include <linux/percpu.h>
#include <linux/mm_types.h>
#include <asm/pgtable.h>
#include <asm/page.h>


int kgr_kaiser_init(void);
void kgr_kaiser_cleanup(void);

pgd_t* kgr_kaiser_create_shadow_pgd(void);
void kgr_kaiser_free_shadow_pgd(pgd_t *pgd);
pgd_t* kgr_kaiser_reset_shadow_pgd(pgd_t *old_shadow_pgd);

struct kgr_pcpu_pgds
{
	unsigned long kern_pgd;
	unsigned long user_pgd;
};

extern struct kgr_pcpu_pgds __percpu *__kgr_pcpu_pgds;

static inline struct kgr_pcpu_pgds* kgr_this_cpu_pgds(void)
{
	return this_cpu_ptr(__kgr_pcpu_pgds);
}

/* from arch/x86/mm/pgtable.c */
static inline struct mm_struct *kgr_pgd_page_get_mm(struct page *page)
{
	return (struct mm_struct *)page->index;
}

#define kgr_mm_user_pgd(mm)				\
	((pgd_t *)(mm)->suse_kabi_padding)

#define kgr_kern_pgd_mm(kern_pgd)			\
	kgr_pgd_page_get_mm(virt_to_page(kern_pgd))

static inline pgd_t* kgr_user_pgd(pgd_t *kern_pgd)
{
	struct mm_struct *mm = kgr_kern_pgd_mm(kern_pgd);
	pgd_t *user_pgd;

	if (!mm)
		return NULL;

	user_pgd = kgr_mm_user_pgd(mm);
	if (!user_pgd)
		return NULL;

	user_pgd += (unsigned long)kern_pgd & ~PAGE_MASK;
	return user_pgd;
}

#define X86_CR3_PCID_NOFLUSH_BIT 63 /* Preserve old PCID */
#define X86_CR3_PCID_NOFLUSH    _BITULL(X86_CR3_PCID_NOFLUSH_BIT)

#define X86_CR3_PCID_ASID_KERN  (_AC(0x0,UL))
/* Let X86_CR3_PCID_ASID_USER be usable for the X86_CR3_PCID_NOFLUSH bit */
#define X86_CR3_PCID_ASID_USER (_AC(0x80,UL))

#define X86_CR3_PCID_KERN_FLUSH                (X86_CR3_PCID_ASID_KERN)
#define X86_CR3_PCID_USER_FLUSH                (X86_CR3_PCID_ASID_USER)
#define X86_CR3_PCID_KERN_NOFLUSH      (X86_CR3_PCID_NOFLUSH | X86_CR3_PCID_ASID_KERN)
#define X86_CR3_PCID_USER_NOFLUSH      (X86_CR3_PCID_NOFLUSH | X86_CR3_PCID_ASID_USER)


static inline void kaiser_flush_tlb_on_return_to_user(void)
{
	kgr_this_cpu_pgds()->user_pgd &= ~X86_CR3_PCID_NOFLUSH;
}


int kgr_kaiser_add_mapping(unsigned long addr, unsigned long size,
			   unsigned long flags);
void kgr_kaiser_remove_mapping(unsigned long start, unsigned long size);

void kgr_native_set_pgd(pgd_t *pgdp, pgd_t pgd);


#endif
