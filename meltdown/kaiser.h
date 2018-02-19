#ifndef _KAISER_H
#define _KAISER_H

#ifndef __ASSEMBLY__

#include <linux/percpu.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <asm/pgtable.h>
#include <asm/page.h>

int kgr_kaiser_init(void);
void kgr_kaiser_cleanup(void);

pgd_t* kgr_kaiser_create_shadow_pgd(void);
void kgr_kaiser_free_shadow_pgd(pgd_t *pgd);
pgd_t* kgr_kaiser_reset_shadow_pgd(pgd_t *old_shadow_pgd);

struct kgr_pcpu_cr3s
{
	unsigned long kern_cr3;
	unsigned long user_cr3;
	unsigned long reg_backup;
};

extern struct kgr_pcpu_cr3s __percpu *__kgr_pcpu_cr3s;

static inline struct kgr_pcpu_cr3s* kgr_this_cpu_cr3s(void)
{
	return this_cpu_ptr(__kgr_pcpu_cr3s);
}

/* from arch/x86/mm/pgtable.c */
static inline struct mm_struct *kgr_pgd_page_get_mm(struct page *page)
{
	return (struct mm_struct *)page->index;
}

static inline pgd_t* kgr_mm_user_pgd(struct mm_struct *mm)
{
	if (!mm)
		return NULL;

	return (pgd_t *)(mm)->suse_kabi_padding;
}

static inline pgd_t* kgr_mm_user_pgd_rcu(struct mm_struct *mm)
{
	if (!mm)
		return NULL;

	return rcu_dereference((mm)->suse_kabi_padding);
}

#define kgr_kern_pgd_mm(kern_pgd)			\
	kgr_pgd_page_get_mm(virt_to_page(kern_pgd))

static inline pgd_t* kgr_user_pgd_rcu(pgd_t *kern_pgd)
{
	struct mm_struct *mm = kgr_kern_pgd_mm(kern_pgd);

	return kgr_mm_user_pgd_rcu(mm);
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

static inline void kgr_kaiser_set_kern_cr3(unsigned long cr3)
{
	struct kgr_pcpu_cr3s *cpu_cr3s;
	cpu_cr3s = kgr_this_cpu_cr3s();

	if (likely(this_cpu_has(X86_FEATURE_PCID)) && cr3)
		cr3 |= X86_CR3_PCID_KERN_NOFLUSH;
	WRITE_ONCE(cpu_cr3s->kern_cr3, cr3);
}

static inline void kgr_kaiser_set_user_cr3(unsigned long cr3)
{
	struct kgr_pcpu_cr3s *cpu_cr3s;
	cpu_cr3s = kgr_this_cpu_cr3s();

	if (unlikely(!this_cpu_has(X86_FEATURE_PCID)))
		cr3 &= ~X86_CR3_PCID_USER_NOFLUSH;
	else if (cr3)
		cr3 |= X86_CR3_PCID_ASID_USER;
	WRITE_ONCE(cpu_cr3s->user_cr3, cr3);
}

static inline unsigned long kgr_kaiser_get_user_cr3(void)
{
	return READ_ONCE(kgr_this_cpu_cr3s()->user_cr3);
}

static inline void kgr_kaiser_flush_tlb_on_return_to_user(void)
{
	unsigned long user_cr3 = kgr_kaiser_get_user_cr3();

	WRITE_ONCE(kgr_this_cpu_cr3s()->user_cr3,
		   user_cr3 & ~X86_CR3_PCID_NOFLUSH);
}


int kgr_kaiser_add_mapping(unsigned long addr, unsigned long size,
			   unsigned long flags);
void kgr_kaiser_remove_mapping(unsigned long start, unsigned long size);
bool kgr_kaiser_is_mapped(unsigned long start, unsigned long size);

static inline int kgr_kaiser_map_thread_stack(void *stack)
{
	/*
	 * Map that page of kernel stack on which we enter from user context.
	 */
	return kgr_kaiser_add_mapping((unsigned long)stack +
			THREAD_SIZE - PAGE_SIZE, PAGE_SIZE, __PAGE_KERNEL);
}

static inline void kgr_kaiser_unmap_thread_stack(void *stack)
{
	/*
	 * Note: may be called even when kaiser_map_thread_stack() failed.
	 */
	kgr_kaiser_remove_mapping((unsigned long)stack +
				  THREAD_SIZE - PAGE_SIZE, PAGE_SIZE);
}

static inline bool kgr_kaiser_is_thread_stack_mapped(void *stack)
{
	return kgr_kaiser_is_mapped((unsigned long)stack +
				    THREAD_SIZE - PAGE_SIZE, PAGE_SIZE);
}


pgd_t kgr_kaiser_set_shadow_pgd(pgd_t *kern_pgdp, pgd_t pgd);


/* Patched, inlined */
static inline void kgr_native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	*pgdp = kgr_kaiser_set_shadow_pgd(pgdp, pgd);
}

#define kgr_set_pgd kgr_native_set_pgd

/* Patched, inlined, calls native_set_pgd() */
static inline void kgr_pgd_clear(pgd_t *pgdp)
{
	kgr_set_pgd(pgdp, __pgd(0));
}

#else /* !__ASSEMBLY__ */

#include "patch_entry.h"

#define KGR_CPU_CR3S_KERN_OFF		0x0
#define KGR_CPU_CR3S_USER_OFF		0x8
#define KGR_CPU_CR3S_REG_BACKUP_OFF	0x10


.macro KGR_MOV_TO_CR reg_code cr
.ifge \reg_code - 8
.error "reg_code must be < 8"
.endif
.byte 0x0f, 0x22 /* opcode */
.byte ((\cr & 0x07) << 3) | \reg_code  /* Mod/RM */
.endm

.macro KGR_TEST_REG64 reg_code
.ifge \reg_code - 8
.error "reg_code must be < 8"
.endif
.byte 0x48  /* 64 bit operand size REX prefix */
.byte 0x85 /* opcode */
.byte (0x3 << 6) | ((\reg_code & 0x07) << 3) | \reg_code /* Mod/RM */
.endm


.macro _KGR_SWITCH_TO_KERNEL_CR3 reg_code
	KGR_CPU_VAR_LOAD64 __kgr_pcpu_cr3s \reg_code KGR_CPU_CR3S_KERN_OFF
	KGR_TEST_REG64 \reg_code
	jz 48473f
	KGR_MOV_TO_CR \reg_code 3
48473:
.endm

.macro KGR_SWITCH_TO_KERNEL_CR3
	pushq %rax
	_KGR_SWITCH_TO_KERNEL_CR3 KGR_REG_CODE_AX
	popq %rax
.endm

.macro KGR_SWITCH_TO_KERNEL_CR3_NO_STACK
	KGR_CPU_VAR_STORE64 KGR_REG_CODE_AX __kgr_pcpu_cr3s KGR_CPU_CR3S_REG_BACKUP_OFF
	_KGR_SWITCH_TO_KERNEL_CR3 KGR_REG_CODE_AX
	KGR_CPU_VAR_LOAD64 __kgr_pcpu_cr3s KGR_REG_CODE_AX KGR_CPU_CR3S_REG_BACKUP_OFF
.endm

.macro _KGR_SWITCH_TO_USER_CR3 reg_code
	KGR_CPU_VAR_LOAD64 __kgr_pcpu_cr3s \reg_code KGR_CPU_CR3S_USER_OFF
	KGR_TEST_REG64 \reg_code
	jz 48475f
	js 48474f
	/* If PCID enabled, FLUSH this time, reset to NOFLUSH for next time */
	KGR_CPU_VAR_STORE8_OR \reg_code __kgr_pcpu_cr3s KGR_CPU_CR3S_USER_OFF+7
48474:
	KGR_MOV_TO_CR \reg_code 3
48475:
.endm

.macro KGR_SWITCH_TO_USER_CR3
	pushq %rax
	_KGR_SWITCH_TO_USER_CR3 KGR_REG_CODE_AX
	popq %rax
.endm

#endif /* __ASSEMBLY__ */

#endif
