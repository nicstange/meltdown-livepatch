#ifndef _KAISER_H
#define _KAISER_H

#include <linux/percpu.h>
#include <linux/mm_types.h>
#include <asm/pgtable.h>
#include <asm/page.h>


int kgr_kaiser_init(void);
void kgr_kaiser_cleanup(void);

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

#define kgr_mm_user_pgd(mm)				\
	((pgd_t *)(mm)->suse_kabi_padding)

#define kgr_kern_pgd_mm(kern_pgd)			\
	pgd_page_get_mm(virt_to_page(kern_pgd))



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

#endif
