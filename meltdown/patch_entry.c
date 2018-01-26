#include <linux/init.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <asm/cacheflush.h>
#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/hypervisor.h>
#include "patch_entry_kallsyms.h"

struct kgr_call_reloc
{
	unsigned long location;
	unsigned long *address;
};

struct kgr_cpu_var_reloc
{
	unsigned long location;
	unsigned long *address;
	unsigned short offset;
	unsigned short pad1;
	unsigned int pad2;
};

extern const  struct kgr_call_reloc __kgr_call_relocs_begin __initconst;
extern const struct kgr_call_reloc __kgr_call_relocs_end __initconst;

static const struct kgr_call_reloc *kgr_call_relocs_begin __initconst =
	&__kgr_call_relocs_begin;
static const struct kgr_call_reloc *kgr_call_relocs_end __initconst=
	&__kgr_call_relocs_end;


extern const struct kgr_cpu_var_reloc __kgr_cpu_var_relocs_begin __initconst;
extern const struct kgr_cpu_var_reloc __kgr_cpu_var_relocs_end __initconst;

static const struct kgr_cpu_var_reloc *kgr_cpu_var_relocs_begin __initconst=
	&__kgr_cpu_var_relocs_begin;
static const struct kgr_cpu_var_reloc *kgr_cpu_var_relocs_end __initconst=
	&__kgr_cpu_var_relocs_end;


extern char __kgr_entry_text_begin;
extern char __kgr_entry_text_end;

unsigned long kgr_entry_text_begin __initconst =
	(unsigned long)&__kgr_entry_text_begin;
unsigned long kgr_entry_text_end __initconst =
	(unsigned long)&__kgr_entry_text_end;

int (*kgr_core_kernel_text)(unsigned long addr);
int (*kgr_set_memory_rw)(unsigned long addr, int numpages);


/* stolen from kernel/module.c */
static inline int
kgr_within(unsigned long addr, void *start, unsigned long size)
{
	return ((void *)addr >= start && (void *)addr < start + size);
}

/*
 * Check that a given address is within this module's .text,
 * c.f. is_module_text_address().
 */
static int __init kgr_this_module_text_address(unsigned long addr)
{
	return kgr_within(addr, THIS_MODULE->module_core,
			  THIS_MODULE->core_text_size);
}



static unsigned int __init
kgr_call_reloc_address(const struct kgr_call_reloc *rel)
{
	/* relative to next insn's %rip */
	unsigned long address = rel->location + 4;
	if (address < 4 ||
	    (!kgr_core_kernel_text(address) &&
	     !kgr_this_module_text_address(address))) {
		pr_err("attempted to patch call to non-text address\n");
		return 0;
	}

	address = *rel->address - address;
	/*
	 * disp32 gets sign-extended. Check that all 32 high bits
	 * match the sign bit, i.e. bit 31.
	 */
	if (((address & (1UL << 31)) && (address >> 32 != ~0U)) ||
	     (!(address & (1UL << 31)) && (address >> 32 != 0U))) {
		pr_err("relative displacement exceeds 32 bits\n");
		return 0;
	}
	return (unsigned int)address;
}

static unsigned int __init
kgr_cpu_var_reloc_address(const struct kgr_cpu_var_reloc *rel)
{
	const unsigned long address = *rel->address + rel->offset;
	/* the "disp32" gets sign-extended, disallow negative values. */
	if (address < rel->offset || (address & (1UL << 31))) {
		pr_err("per-cpu var address exceeds 32 bits\n");
		return 0;
	}
	return (unsigned int)address;
}


static int __init patch_entry_text(void)
{
	const struct kgr_call_reloc *call_rel;
	const struct kgr_cpu_var_reloc *pcpu_rel;
	const int nr_text_pages =
		(kgr_entry_text_end - kgr_entry_text_begin) >> PAGE_SHIFT;
	int ret;

	/* Sanity check: make sure that all addresses are valid */
	if ((kgr_entry_text_begin & ~PAGE_MASK) ||
	    (kgr_entry_text_end & ~PAGE_MASK)) {
		pr_err("unexpected alignment of KGraft entry code\n");
		return -EINVAL;
	}

	for (call_rel = kgr_call_relocs_begin;
	     call_rel != kgr_call_relocs_end; ++call_rel) {
		const unsigned int address = kgr_call_reloc_address(call_rel);
		if (!address)
			return -EINVAL;
		if (!kgr_this_module_text_address(call_rel->location)) {
			pr_err("call patch location not in KGraft module\n");
			return -EINVAL;
		}
	}

	for (pcpu_rel = kgr_cpu_var_relocs_begin;
	     pcpu_rel != kgr_cpu_var_relocs_end; ++pcpu_rel) {
		const unsigned int address =
			kgr_cpu_var_reloc_address(pcpu_rel);
		if (!address)
			return -EINVAL;
		if (!kgr_this_module_text_address(pcpu_rel->location)) {
			pr_err("per-cpu var patch location not in KGraft module\n");
			return -EINVAL;
		}
	}

	/* Actually patch the code */
	ret = kgr_set_memory_rw(kgr_entry_text_begin, nr_text_pages);
	if (ret)
		return ret;
	for (call_rel = kgr_call_relocs_begin;
	     call_rel != kgr_call_relocs_end; ++call_rel) {
		const unsigned int address = kgr_call_reloc_address(call_rel);
		memcpy((void*)call_rel->location, &address, sizeof(address));
	}
	for (pcpu_rel = kgr_cpu_var_relocs_begin;
	     pcpu_rel != kgr_cpu_var_relocs_end; ++pcpu_rel) {
		const unsigned int address =
			kgr_cpu_var_reloc_address(pcpu_rel);
		memcpy((void*)pcpu_rel->location, &address, sizeof(address));
	}
	ret = set_memory_x(kgr_entry_text_begin, nr_text_pages);
	if (ret)
		return ret;

	/*
	 * TODO: that's a NOP on x86, sufficient?
	 * Because the pages had been executable before and speculative
	 * execution might have put something into the icache?
	 */
	flush_icache_range(kgr_entry_text_begin, kgr_entry_text_end);

	return 0;
}

sys_call_ptr_t kgr_replaced_sys_call_table[__NR_syscall_max+1];
sys_call_ptr_t (*kgr_sys_call_table)[__NR_syscall_max+1];

extern long kgr_stub_execve(unsigned long, unsigned long, unsigned long,
			    unsigned long, unsigned long, unsigned long);
extern long kgr_stub_execveat(unsigned long, unsigned long, unsigned long,
			      unsigned long, unsigned long, unsigned long);
extern long kgr_stub_rt_sigreturn(unsigned long, unsigned long, unsigned long,
				  unsigned long, unsigned long, unsigned long);

static __init void syscalls_init(void)
{
	memcpy(&kgr_replaced_sys_call_table[0],
		&(*kgr_sys_call_table)[0],
		sizeof(kgr_replaced_sys_call_table));
	kgr_replaced_sys_call_table[__NR_execve] = kgr_stub_execve;
	kgr_replaced_sys_call_table[__NR_execveat] = kgr_stub_execveat;
	kgr_replaced_sys_call_table[__NR_rt_sigreturn] = kgr_stub_rt_sigreturn;
}

static gate_desc kgr_idt_table[NR_VECTORS] __page_aligned_bss;
static gate_desc kgr_debug_idt_table[NR_VECTORS] __page_aligned_bss;
static gate_desc kgr_trace_idt_table[NR_VECTORS] __page_aligned_bss;

/* from arch/x86/include/asm/desc.h */
static inline void kgr_set_nmi_gate(int gate, void *addr)
{
	gate_desc s;

	pack_gate(&s, GATE_INTERRUPT, (unsigned long)addr, 0, 0, __KERNEL_CS);
	write_idt_entry(kgr_debug_idt_table, gate, &s);
}

static inline void kgr_write_trace_idt_entry(int entry, const gate_desc *gate)
{
	write_idt_entry(kgr_trace_idt_table, entry, gate);
}

static inline void _kgr_trace_set_gate(int gate, unsigned type, void *addr,
				       unsigned dpl, unsigned ist, unsigned seg)
{
	gate_desc s;

	pack_gate(&s, type, (unsigned long)addr, dpl, ist, seg);
	/*
	 * does not need to be atomic because it is only done once at
	 * setup time
	 */
	kgr_write_trace_idt_entry(gate, &s);
}

static inline void _kgr_set_gate(int gate, unsigned type, void *addr,
				unsigned dpl, unsigned ist, unsigned seg)
{
	gate_desc s;

	pack_gate(&s, type, (unsigned long)addr, dpl, ist, seg);
	/*
	 * does not need to be atomic because it is only done once at
	 * setup time
	 */
	write_idt_entry(kgr_idt_table, gate, &s);
	kgr_write_trace_idt_entry(gate, &s);
}

/*
 * This needs to use 'idt_table' rather than 'idt', and
 * thus use the _nonmapped_ version of the IDT, as the
 * Pentium F0 0F bugfix can have resulted in the mapped
 * IDT being write-protected.
 */
#define kgr_set_intr_gate_notrace(n, addr)				\
	do {								\
		BUG_ON((unsigned)n > 0xFF);				\
		_kgr_set_gate(n, GATE_INTERRUPT, (void *)kgr_##addr, 0, 0,	\
			  __KERNEL_CS);				\
	} while (0)

#define kgr_set_intr_gate(n, addr)					\
	do {								\
		kgr_set_intr_gate_notrace(n, addr);			\
		_kgr_trace_set_gate(n, GATE_INTERRUPT, (void *)kgr_trace_##addr,\
				0, 0, __KERNEL_CS);			\
	} while (0)

/* Our own instance of vector allocation data for sanity checks */
DECLARE_BITMAP(__used_vectors, NR_VECTORS);
static int __first_system_vector = FIRST_SYSTEM_VECTOR;

static inline void kgr_alloc_system_vector(int vector)
{
	if (!test_bit(vector, __used_vectors)) {
		set_bit(vector, __used_vectors);
		if (__first_system_vector > vector)
			__first_system_vector = vector;
	} else {
		BUG();
	}
}


#define kgr_alloc_intr_gate(n, addr)				\
	do {							\
		kgr_alloc_system_vector(n);				\
		kgr_set_intr_gate(n, addr);				\
	} while (0)

static inline void kgr_set_system_intr_gate(unsigned int n, void *addr)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_INTERRUPT, addr, 0x3, 0, __KERNEL_CS);
}

static inline void kgr_set_system_trap_gate(unsigned int n, void *addr)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_TRAP, addr, 0x3, 0, __KERNEL_CS);
}

static inline void kgr_set_trap_gate(unsigned int n, void *addr)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_TRAP, addr, 0, 0, __KERNEL_CS);
}

static inline void kgr_set_task_gate(unsigned int n, unsigned int gdt_entry)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_TASK, (void *)0, 0, 0, (gdt_entry<<3));
}

static inline void kgr_set_intr_gate_ist(int n, void *addr, unsigned ist)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_INTERRUPT, addr, 0, ist, __KERNEL_CS);
}

static inline void kgr_set_system_intr_gate_ist(int n, void *addr, unsigned ist)
{
	BUG_ON((unsigned)n > 0xFF);
	_kgr_set_gate(n, GATE_INTERRUPT, addr, 0x3, ist, __KERNEL_CS);
}


/* from arch/x86/include/asm/traps.h */
asmlinkage void kgr_divide_error(void);
asmlinkage void kgr_debug(void);
asmlinkage void kgr_nmi(void);
asmlinkage void kgr_int3(void);
asmlinkage void kgr_xen_debug(void);
asmlinkage void kgr_xen_int3(void);
asmlinkage void kgr_xen_stack_segment(void);
asmlinkage void kgr_overflow(void);
asmlinkage void kgr_bounds(void);
asmlinkage void kgr_invalid_op(void);
asmlinkage void kgr_device_not_available(void);
#ifdef CONFIG_X86_64
asmlinkage void kgr_double_fault(void);
#endif
asmlinkage void kgr_coprocessor_segment_overrun(void);
asmlinkage void kgr_invalid_TSS(void);
asmlinkage void kgr_segment_not_present(void);
asmlinkage void kgr_stack_segment(void);
asmlinkage void kgr_general_protection(void);
asmlinkage void kgr_page_fault(void);
asmlinkage void kgr_async_page_fault(void);
asmlinkage void kgr_spurious_interrupt_bug(void);
asmlinkage void kgr_coprocessor_error(void);
asmlinkage void kgr_alignment_check(void);
#ifdef CONFIG_X86_MCE
asmlinkage void kgr_machine_check(void);
#endif /* CONFIG_X86_MCE */
asmlinkage void kgr_simd_coprocessor_error(void);

#ifdef CONFIG_TRACING
asmlinkage void kgr_trace_page_fault(void);
#define kgr_trace_stack_segment kgr_stack_segment
#define kgr_trace_divide_error kgr_divide_error
#define kgr_trace_bounds kgr_bounds
#define kgr_trace_invalid_op kgr_invalid_op
#define kgr_trace_device_not_available kgr_device_not_available
#define kgr_trace_coprocessor_segment_overrun kgr_coprocessor_segment_overrun
#define kgr_trace_invalid_TSS kgr_invalid_TSS
#define kgr_trace_segment_not_present kgr_segment_not_present
#define kgr_trace_general_protection kgr_general_protection
#define kgr_trace_spurious_interrupt_bug kgr_spurious_interrupt_bug
#define kgr_trace_coprocessor_error kgr_coprocessor_error
#define kgr_trace_alignment_check kgr_alignment_check
#define kgr_trace_simd_coprocessor_error kgr_simd_coprocessor_error
#define kgr_trace_async_page_fault kgr_async_page_fault
#endif

#ifndef CONFIG_X86_32
asmlinkage void smp_thermal_interrupt(void);
asmlinkage void smp_threshold_interrupt(void);
asmlinkage void smp_deferred_error_interrupt(void);
#endif


/* from arch/x86/include/asm/hw_irq.h */
/* Interrupt handlers registered during init_IRQ */
extern asmlinkage void kgr_apic_timer_interrupt(void);
extern asmlinkage void kgr_x86_platform_ipi(void);
extern asmlinkage void kgr_kvm_posted_intr_ipi(void);
extern asmlinkage void kgr_kvm_posted_intr_wakeup_ipi(void);
extern asmlinkage void kgr_error_interrupt(void);
extern asmlinkage void kgr_irq_work_interrupt(void);

extern asmlinkage void kgr_spurious_interrupt(void);
extern asmlinkage void kgr_thermal_interrupt(void);
extern asmlinkage void kgr_reschedule_interrupt(void);

extern asmlinkage void kgr_irq_move_cleanup_interrupt(void);
extern asmlinkage void kgr_reboot_interrupt(void);
extern asmlinkage void kgr_threshold_interrupt(void);
extern asmlinkage void kgr_deferred_error_interrupt(void);

extern asmlinkage void kgr_call_function_interrupt(void);
extern asmlinkage void kgr_call_function_single_interrupt(void);

#ifdef CONFIG_TRACING
/* Interrupt handlers registered during init_IRQ */
extern void kgr_trace_apic_timer_interrupt(void);
extern void kgr_trace_x86_platform_ipi(void);
extern void kgr_trace_error_interrupt(void);
extern void kgr_trace_irq_work_interrupt(void);
extern void kgr_trace_spurious_interrupt(void);
extern void kgr_trace_thermal_interrupt(void);
extern void kgr_trace_reschedule_interrupt(void);
extern void kgr_trace_threshold_interrupt(void);
extern void kgr_trace_deferred_error_interrupt(void);
extern void kgr_trace_call_function_interrupt(void);
extern void kgr_trace_call_function_single_interrupt(void);
#define kgr_trace_irq_move_cleanup_interrupt  kgr_irq_move_cleanup_interrupt
#define kgr_trace_reboot_interrupt  kgr_reboot_interrupt
#define kgr_trace_kvm_posted_intr_ipi kgr_kvm_posted_intr_ipi
#define kgr_trace_kvm_posted_intr_wakeup_ipi kgr_kvm_posted_intr_wakeup_ipi
#endif /* CONFIG_TRACING */

extern void kgr_entry_INT80_compat(void);

unsigned long (*kgr_used_vectors)[];
int *kgr_first_system_vector;

extern char kgr_irq_entries_start[];

#define kgr_trace_irq_entries_start kgr_irq_entries_start

static void __init kgr_para_trap_init(void)
{
	if (x86_hyper == &x86_hyper_kvm && kvm_para_available()) {
		/* C.f. kvm_apf_trap_init(void) */
		kgr_set_intr_gate(14, async_page_fault);
		return;
	}
}

static void __init kgr_trap_init(void)
{
	int i;


	/* c.f. early_trap_pf_init() */
	kgr_set_intr_gate(X86_TRAP_PF, page_fault);

	/* c.f. trap_init() */
	kgr_set_intr_gate(X86_TRAP_DE, divide_error);
	kgr_set_intr_gate_ist(X86_TRAP_NMI, &kgr_nmi, NMI_STACK);
	/* int4 can be called from all */
	kgr_set_system_intr_gate(X86_TRAP_OF, &kgr_overflow);
	kgr_set_intr_gate(X86_TRAP_BR, bounds);
	kgr_set_intr_gate(X86_TRAP_UD, invalid_op);
	kgr_set_intr_gate(X86_TRAP_NM, device_not_available);
#ifdef CONFIG_X86_32 /* false */
	kgr_set_task_gate(X86_TRAP_DF, GDT_ENTRY_DOUBLEFAULT_TSS);
#else
	kgr_set_intr_gate_ist(X86_TRAP_DF, &kgr_double_fault, DOUBLEFAULT_STACK);
#endif
	kgr_set_intr_gate(X86_TRAP_OLD_MF, coprocessor_segment_overrun);
	kgr_set_intr_gate(X86_TRAP_TS, invalid_TSS);
	kgr_set_intr_gate(X86_TRAP_NP, segment_not_present);
	kgr_set_intr_gate(X86_TRAP_SS, stack_segment);
	kgr_set_intr_gate(X86_TRAP_GP, general_protection);
	kgr_set_intr_gate(X86_TRAP_SPURIOUS, spurious_interrupt_bug);
	kgr_set_intr_gate(X86_TRAP_MF, coprocessor_error);
	kgr_set_intr_gate(X86_TRAP_AC, alignment_check);
#ifdef CONFIG_X86_MCE
	kgr_set_intr_gate_ist(X86_TRAP_MC, &kgr_machine_check, MCE_STACK);
#endif
	kgr_set_intr_gate(X86_TRAP_XF, simd_coprocessor_error);

	/* Reserve all the builtin and the syscall vector: */
	for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
		set_bit(i, __used_vectors);

#ifdef CONFIG_IA32_EMULATION
	kgr_set_system_intr_gate(IA32_SYSCALL_VECTOR, kgr_entry_INT80_compat);
	set_bit(IA32_SYSCALL_VECTOR, __used_vectors);
#endif

#ifdef CONFIG_X86_32 /* false */
	set_system_trap_gate(IA32_SYSCALL_VECTOR, entry_INT80_32);
	set_bit(IA32_SYSCALL_VECTOR, used_vectors);
#endif

	/*
	 * X86_TRAP_DB and X86_TRAP_BP have been set
	 * in early_trap_init(). However, ITS works only after
	 * cpu_init() loads TSS. See comments in early_trap_init().
	 */
	kgr_set_intr_gate_ist(X86_TRAP_DB, &kgr_debug, DEBUG_STACK);
	/* int3 can be called from all */
	kgr_set_system_intr_gate_ist(X86_TRAP_BP, &kgr_int3, DEBUG_STACK);

	kgr_para_trap_init();

#ifdef CONFIG_X86_64
	memcpy(&kgr_debug_idt_table, &kgr_idt_table, IDT_ENTRIES * 16);
	kgr_set_nmi_gate(X86_TRAP_DB, &kgr_debug);
	kgr_set_nmi_gate(X86_TRAP_BP, &kgr_int3);
#endif
}


static void __init kgr_smp_intr_init(void)
{
	kgr_alloc_intr_gate(RESCHEDULE_VECTOR, reschedule_interrupt);

	/* IPI for generic function call */
	kgr_alloc_intr_gate(CALL_FUNCTION_VECTOR, call_function_interrupt);

	/* IPI for generic single function call */
	kgr_alloc_intr_gate(CALL_FUNCTION_SINGLE_VECTOR,
			    call_function_single_interrupt);

	/* Low priority IPI to cleanup after moving an irq */
	kgr_set_intr_gate(IRQ_MOVE_CLEANUP_VECTOR, irq_move_cleanup_interrupt);
	set_bit(IRQ_MOVE_CLEANUP_VECTOR, __used_vectors);

	/* IPI used for rebooting/stopping */
	kgr_alloc_intr_gate(REBOOT_VECTOR, reboot_interrupt);
}

static void __init kgr_apic_intr_init(void)
{
	kgr_smp_intr_init();

	#ifdef CONFIG_X86_THERMAL_VECTOR
	kgr_alloc_intr_gate(THERMAL_APIC_VECTOR, thermal_interrupt);
#endif
#ifdef CONFIG_X86_MCE_THRESHOLD
	kgr_alloc_intr_gate(THRESHOLD_APIC_VECTOR, threshold_interrupt);
#endif

#ifdef CONFIG_X86_MCE_AMD
	kgr_alloc_intr_gate(DEFERRED_ERROR_VECTOR, deferred_error_interrupt);
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	/* self generated IPI for local APIC timer */
	kgr_alloc_intr_gate(LOCAL_TIMER_VECTOR, apic_timer_interrupt);

	/* IPI for X86 platform specific use */
	kgr_alloc_intr_gate(X86_PLATFORM_IPI_VECTOR, x86_platform_ipi);
#ifdef CONFIG_HAVE_KVM
	/* IPI for KVM to deliver posted interrupt */
	kgr_alloc_intr_gate(POSTED_INTR_VECTOR, kvm_posted_intr_ipi);
	/* IPI for KVM to deliver interrupt to wake up tasks */
	kgr_alloc_intr_gate(POSTED_INTR_WAKEUP_VECTOR, kvm_posted_intr_wakeup_ipi);
#endif

	/* IPI vectors for APIC spurious and error interrupts */
	kgr_alloc_intr_gate(SPURIOUS_APIC_VECTOR, spurious_interrupt);
	kgr_alloc_intr_gate(ERROR_APIC_VECTOR, error_interrupt);

	/* IRQ work interrupts: */
# ifdef CONFIG_IRQ_WORK
	kgr_alloc_intr_gate(IRQ_WORK_VECTOR, irq_work_interrupt);
# endif
#endif
}

static int __init kgr_native_init_IRQ(void)
{
	int i;

	kgr_apic_intr_init();

	/*
	 * Sanity check: compare vector allocation with what's
	 * currently active on the system.
	 */
	for (i = 0; i < NR_VECTORS; ++i) {
		if (test_bit(i, __used_vectors) ^
			test_bit(i, (*kgr_used_vectors))) {
			pr_err("IDT mistmatch at %d: %d vs %d\n",
				i,
				(int)test_bit(i, __used_vectors),
				(int)test_bit(i, (*kgr_used_vectors)));
			return -EINVAL;
		}
	}

	if (__first_system_vector != *kgr_first_system_vector) {
		pr_err("IDT allocation: first system vector mismatch: %d vs %d\n",
			__first_system_vector, *kgr_first_system_vector);
		return -EINVAL;
	}

	/* native_init_IRQ */
	i = FIRST_EXTERNAL_VECTOR;
#ifndef CONFIG_X86_LOCAL_APIC /* false */
#define first_system_vector NR_VECTORS
#endif
	for_each_clear_bit_from(i, (*kgr_used_vectors), (*kgr_first_system_vector)) {
		/* IA32_SYSCALL_VECTOR could be used in trap_init already. */
		kgr_set_intr_gate(i, irq_entries_start +
				  8 * (i - FIRST_EXTERNAL_VECTOR));
	}
#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, (*kgr_used_vectors), NR_VECTORS)
		kgr_set_intr_gate(i, spurious_interrupt);
#endif

	return 0;
}

static int __init kgr_xen_init_IRQ(void)
{
	/* TODO:
	 * On XEN, we had to patch callers of cvt_gate_to_trap()
	 */
	pr_err("Livepatch not supported on XEN");
	return -ENOSYS;
}

#if IS_ENABLED(CONFIG_LGUEST_GUEST)
#error "Livepatch supports only CONFIG_LGUEST_GUEST=n"
#endif

static int __init kgr_intr_init(void)
{
	if (x86_hyper == &x86_hyper_xen) {
		return kgr_xen_init_IRQ();
	}

	return kgr_native_init_IRQ();
}

static int __init idt_tables_init(void)
{
	kgr_trap_init();

	return kgr_intr_init();
}

int __init patch_entry_init(void)
{
	int ret = patch_entry_text();
	if (ret)
		return ret;

	syscalls_init();
	ret = idt_tables_init();
	if (ret)
		return ret;

	return ret;
}

static unsigned long orig_idt;
static unsigned long orig_debug_idt;
static unsigned long orig_trace_idt;

struct desc_ptr *kgr_idt_descr;
struct desc_ptr *kgr_debug_idt_descr;
struct desc_ptr *kgr_trace_idt_descr;


u32 *kgr_debug_idt_ctr;
atomic_t *kgr_trace_idt_ctr;

/* from arch/x86/include/asm/desc.h */
static inline bool kgr_is_debug_idt_enabled(void)
{
	if (*raw_cpu_ptr(kgr_debug_idt_ctr))
		return true;

	return false;
}

static inline void kgr_load_debug_idt(void)
{
	load_idt((const struct desc_ptr *)kgr_debug_idt_descr);
}

static inline bool kgr_is_trace_idt_enabled(void)
{
	if (atomic_read(kgr_trace_idt_ctr))
		return true;

	return false;
}


static inline void kgr_load_trace_idt(void)
{
	load_idt((const struct desc_ptr *)kgr_trace_idt_descr);
}

static inline void kgr_load_current_idt(void)
{
	if (kgr_is_debug_idt_enabled())
		kgr_load_debug_idt();
	else if (kgr_is_trace_idt_enabled())
		kgr_load_trace_idt();
	else
		load_idt((const struct desc_ptr *)kgr_idt_descr);
}


void patch_entry_apply(void)
{
	orig_idt = (unsigned long)&kgr_idt_table[0];
	orig_debug_idt = (unsigned long)&kgr_debug_idt_table[0];
	orig_trace_idt = (unsigned long)&kgr_trace_idt_table[0];

	orig_idt = xchg(&kgr_idt_descr->address, orig_idt);
	orig_debug_idt = xchg(&kgr_debug_idt_descr->address, orig_debug_idt);
	orig_trace_idt = xchg(&kgr_trace_idt_descr->address, orig_trace_idt);
}

void patch_entry_unapply(void)
{
	xchg(&kgr_idt_descr->address, orig_idt);
	xchg(&kgr_debug_idt_descr->address, orig_debug_idt);
	xchg(&kgr_trace_idt_descr->address, orig_trace_idt);
}


void kgr_entry_SYSCALL_64(void);
void kgr_entry_SYSCALL_compat(void);
void kgr_entry_SYSENTER_compat(void);

void (*kgr_orig_entry_SYSCALL_64)(void);
void (*kgr_orig_entry_SYSCALL_compat)(void);
void (*kgr_orig_entry_SYSENTER_compat)(void);

void patch_entry_apply_finish_cpu(void)
{
	kgr_load_current_idt();
	wrmsrl(MSR_LSTAR, (unsigned long)kgr_entry_SYSCALL_64);
	wrmsrl(MSR_CSTAR, (unsigned long)kgr_entry_SYSCALL_compat);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)kgr_entry_SYSENTER_compat);
}

void patch_entry_unapply_finish_cpu(void)
{
	kgr_load_current_idt();
	wrmsrl(MSR_LSTAR, (unsigned long)*kgr_orig_entry_SYSCALL_64);
	wrmsrl(MSR_CSTAR, (unsigned long)*kgr_orig_entry_SYSCALL_compat);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP,
		(u64)*kgr_orig_entry_SYSENTER_compat);
}
