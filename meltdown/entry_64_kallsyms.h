#ifndef _ENTRY_64_KALLSYMS_H
#define _ENTRY_64_KALLSYMS_H

struct ptr_regs;
struct bad_iret_stack;

void *kgr_rsp_scratch;
void *kgr_irq_count;
void *kgr_irq_stack_ptr;
void *kgr_cpu_tss;

unsigned long (*kgr_syscall_trace_enter_phase1)(struct pt_regs *regs, u32 arch);
long (*kgr_syscall_trace_enter_phase2)(struct pt_regs *regs, u32 arch,
				unsigned long phase1_result);
void (*kgr_syscall_return_slowpath)(struct pt_regs *regs);

long (*kgr_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
long (*kgr_sys_execveat)(int dfd, const char __user *filename,
			const char __user *const __user *argv,
			const char __user *const __user *envp, int flags);
long (*kgr_sys_rt_sigreturn)(void);
unsigned int (*kgr_do_IRQ)(struct pt_regs *regs);
void (*kgr_prepare_exit_to_usermode)(struct pt_regs *regs);
void (*kgr_enter_from_user_mode)(void);
struct pt_regs* (*kgr_sync_regs)(struct pt_regs *eregs);

void (*kgr_smp_irq_move_cleanup_interrupt)(void);
void (*kgr_smp_reboot_interrupt)(void);
void (*kgr_uv_bau_message_interrupt)(void);
void (*kgr_smp_apic_timer_interrupt)(void);
void (*kgr_smp_trace_apic_timer_interrupt)(void);
void (*kgr_smp_x86_platform_ipi)(void);
void (*kgr_smp_trace_x86_platform_ipi)(void);
void (*kgr_smp_kvm_posted_intr_ipi)(void);
void (*kgr_smp_kvm_posted_intr_wakeup_ipi)(void);
void (*kgr_smp_threshold_interrupt)(void);
void (*kgr_smp_trace_threshold_interrupt)(void);
void (*kgr_smp_deferred_error_interrupt)(void);
void (*kgr_smp_trace_deferred_error_interrupt)(void);
void (*kgr_smp_thermal_interrupt)(void);
void (*kgr_smp_trace_thermal_interrupt)(void);
void (*kgr_smp_call_function_single_interrupt)(void);
void (*kgr_smp_trace_call_function_single_interrupt)(void);
void (*kgr_smp_call_function_interrupt)(void);
void (*kgr_smp_trace_call_function_interrupt)(void);
void (*kgr_smp_reschedule_interrupt)(void);
void (*kgr_smp_trace_reschedule_interrupt)(void);
void (*kgr_smp_error_interrupt)(void);
void (*kgr_smp_trace_error_interrupt)(void);
void (*kgr_smp_spurious_interrupt)(void);
void (*kgr_smp_trace_spurious_interrupt)(void);
void (*kgr_smp_irq_work_interrupt)(void);
void (*kgr_smp_trace_irq_work_interrupt)(void);

void (*kgr_do_divide_error)(struct pt_regs *regs, long error_code);
void (*kgr_do_overflow)(struct pt_regs *regs, long error_code);
void (*kgr_do_bounds)(struct pt_regs *regs, long error_code);
void (*kgr_do_invalid_op)(struct pt_regs *regs, long error_code);
void (*kgr_do_device_not_available)(struct pt_regs *regs, long error_code);
void (*kgr_do_double_fault)(struct pt_regs *regs, long error_code);
void (*kgr_do_coprocessor_segment_overrun)(struct pt_regs *regs, long error_code);
void (*kgr_do_invalid_TSS)(struct pt_regs *regs, long error_code);
void (*kgr_do_segment_not_present)(struct pt_regs *regs, long error_code);
void (*kgr_do_spurious_interrupt_bug)(struct pt_regs *regs, long error_code);
void (*kgr_do_coprocessor_error)(struct pt_regs *regs, long error_code);
void (*kgr_do_alignment_check)(struct pt_regs *regs, long error_code);
void (*kgr_do_simd_coprocessor_error)(struct pt_regs *regs, long error_code);

void (*kgr_xen_evtchn_do_upcall)(struct pt_regs *regs);
void (*kgr_xen_maybe_preempt_hcall)(void);

void (*kgr_hyperv_vector_handler)(struct pt_regs *regs, long error_code);

void (*kgr_do_debug)(struct pt_regs *regs, long error_code);
void (*kgr_do_int3)(struct pt_regs *regs, long error_code);
void (*kgr_do_stack_segment)(struct pt_regs *regs, long error_code);
void (*kgr_do_general_protection)(struct pt_regs *regs, long error_code);
void (*kgr_do_page_fault)(struct pt_regs *regs, long error_code);
void (*kgr_trace_do_page_fault)(struct pt_regs *regs, long error_code);
void (*kgr_do_async_page_fault)(struct pt_regs *regs, long error_code);

void (*(*kgr_machine_check_vector))(struct pt_regs *, long error_code);

const char (*kgr_native_irq_return_iret)[];
const char (*kgr_gs_change)[];

struct bad_iret_stack* (*kgr_fixup_bad_iret)(struct bad_iret_stack *s);

void (*kgr_do_nmi)(struct pt_regs *regs, long error_code);


#define ENTRY_64_KALLSYMS						\
	{ "rsp_scratch", (void *)&kgr_rsp_scratch },			\
	{ "irq_count", (void *)&kgr_irq_count },			\
	{ "irq_stack_ptr", (void *)&kgr_irq_stack_ptr },		\
	{ "cpu_tss", (void *)&kgr_cpu_tss },				\
	{ "syscall_trace_enter_phase1",				\
			(void *)&kgr_syscall_trace_enter_phase1 },	\
	{ "syscall_trace_enter_phase2",				\
			(void *)&kgr_syscall_trace_enter_phase2 },	\
	{ "syscall_return_slowpath",					\
			(void *)&kgr_syscall_return_slowpath },	\
	{ "sys_execve", (void *)&kgr_sys_execve },			\
	{ "sys_execveat", (void *)&kgr_sys_execveat },			\
	{ "sys_rt_sigreturn", (void *)&kgr_sys_rt_sigreturn },		\
	{ "do_IRQ", (void *)&kgr_do_IRQ },				\
	{ "prepare_exit_to_usermode",					\
			(void *)&kgr_prepare_exit_to_usermode },	\
	{ "enter_from_user_mode",					\
			(void *)&kgr_enter_from_user_mode },		\
	{ "sync_regs", (void *)&kgr_sync_regs },			\
	{ "smp_irq_move_cleanup_interrupt",				\
			(void *)&kgr_smp_irq_move_cleanup_interrupt },	\
	{ "smp_reboot_interrupt",					\
			(void *)&kgr_smp_reboot_interrupt },		\
	{ "uv_bau_message_interrupt",					\
			(void *)&kgr_uv_bau_message_interrupt },	\
	{ "smp_apic_timer_interrupt",					\
			(void *)&kgr_smp_apic_timer_interrupt },	\
	{ "smp_trace_apic_timer_interrupt",				\
			(void *)&kgr_smp_trace_apic_timer_interrupt },	\
	{ "smp_x86_platform_ipi",					\
			(void *)&kgr_smp_x86_platform_ipi },		\
	{ "smp_trace_x86_platform_ipi",				\
			(void *)&kgr_smp_trace_x86_platform_ipi },	\
	{ "smp_kvm_posted_intr_ipi",					\
			(void *)&kgr_smp_kvm_posted_intr_ipi },	\
	{ "smp_kvm_posted_intr_wakeup_ipi",				\
			(void *)&kgr_smp_kvm_posted_intr_wakeup_ipi },	\
	{ "smp_threshold_interrupt",					\
			(void *)&kgr_smp_threshold_interrupt },	\
	{ "smp_trace_threshold_interrupt",				\
			(void *)&kgr_smp_trace_threshold_interrupt },	\
	{ "smp_deferred_error_interrupt",				\
			(void *)&kgr_smp_deferred_error_interrupt },	\
	{ "smp_trace_deferred_error_interrupt",			\
		(void *)&kgr_smp_trace_deferred_error_interrupt },	\
	{ "smp_thermal_interrupt",					\
			(void *)&kgr_smp_thermal_interrupt },		\
	{ "smp_trace_thermal_interrupt",				\
			(void *)&kgr_smp_trace_thermal_interrupt },	\
	{ "smp_call_function_single_interrupt",			\
		(void *)&kgr_smp_call_function_single_interrupt },	\
	{ "smp_trace_call_function_single_interrupt",			\
	     (void *)&kgr_smp_trace_call_function_single_interrupt },	\
	{ "smp_call_function_interrupt",				\
			(void *)&kgr_smp_call_function_interrupt },	\
	{ "smp_trace_call_function_interrupt",				\
		(void *)&kgr_smp_trace_call_function_interrupt },	\
	{ "smp_reschedule_interrupt",					\
			(void *)&kgr_smp_reschedule_interrupt },	\
	{ "smp_trace_reschedule_interrupt",				\
			(void *)&kgr_smp_trace_reschedule_interrupt },	\
	{ "smp_error_interrupt",					\
			(void *)&kgr_smp_error_interrupt },		\
	{ "smp_trace_error_interrupt",					\
			(void *)&kgr_smp_trace_error_interrupt },	\
	{ "smp_spurious_interrupt",					\
			(void *)&kgr_smp_spurious_interrupt },		\
	{ "smp_trace_spurious_interrupt",				\
			(void *)&kgr_smp_trace_spurious_interrupt },	\
	{ "smp_irq_work_interrupt",					\
			(void *)&kgr_smp_irq_work_interrupt },		\
	{ "smp_trace_irq_work_interrupt",				\
			(void *)&kgr_smp_trace_irq_work_interrupt },	\
	{ "do_divide_error", (void *)&kgr_do_divide_error },		\
	{ "do_overflow", (void *)&kgr_do_overflow },			\
	{ "do_bounds", (void *)&kgr_do_bounds },			\
	{ "do_invalid_op", (void *)&kgr_do_invalid_op },		\
	{ "do_device_not_available",					\
			(void *)&kgr_do_device_not_available },	\
	{ "do_double_fault", (void *)&kgr_do_double_fault },		\
	{ "do_coprocessor_segment_overrun",				\
			(void *)&kgr_do_coprocessor_segment_overrun },	\
	{ "do_invalid_TSS", (void *)&kgr_do_invalid_TSS },		\
	{ "do_segment_not_present",					\
			(void *)&kgr_do_segment_not_present },		\
	{ "do_spurious_interrupt_bug",					\
			(void *)&kgr_do_spurious_interrupt_bug },	\
	{ "do_coprocessor_error", (void *)&kgr_do_coprocessor_error },	\
	{ "do_alignment_check", (void *)&kgr_do_alignment_check },	\
	{ "do_simd_coprocessor_error",					\
			(void *)&kgr_do_simd_coprocessor_error },	\
	{ "xen_evtchn_do_upcall", (void *)&kgr_xen_evtchn_do_upcall },	\
	{ "xen_maybe_preempt_hcall",					\
			(void *)&kgr_xen_maybe_preempt_hcall },	\
	{ "hyperv_vector_handler",					\
			(void *)&kgr_hyperv_vector_handler },		\
	{ "do_debug", (void *)&kgr_do_debug },				\
	{ "do_int3", (void *)&kgr_do_int3 },				\
	{ "do_stack_segment", (void *)&kgr_do_stack_segment },		\
	{ "do_general_protection",					\
			(void *)&kgr_do_general_protection },		\
	{ "do_page_fault", (void *)&kgr_do_page_fault },		\
	{ "trace_do_page_fault", (void *)&kgr_trace_do_page_fault },	\
	{ "do_async_page_fault", (void *)&kgr_do_async_page_fault },	\
	{ "machine_check_vector", (void *)&kgr_machine_check_vector },	\
	{ "native_irq_return_iret",					\
			(void *)&kgr_native_irq_return_iret },		\
	{ "gs_change", (void *)&kgr_gs_change },			\
	{ "fixup_bad_iret", (void *)&kgr_fixup_bad_iret },		\
	{ "do_nmi", (void *)&kgr_do_nmi },				\

#endif
