#ifndef _PATCH_ENTRY_KALLSYMS_H
#define _PATCH_ENTRY_KALLSYMS_H

#include <asm/syscall.h>

extern int (*kgr_core_kernel_text)(unsigned long addr);
extern int (*kgr_set_memory_rw)(unsigned long addr, int numpages);
extern sys_call_ptr_t (*kgr_sys_call_table)[__NR_syscall_max+1];
extern unsigned long (*kgr_used_vectors)[];
extern int *kgr_first_system_vector;
extern struct desc_ptr *kgr_idt_descr;
extern struct desc_ptr *kgr_debug_idt_descr;
extern struct desc_ptr *kgr_trace_idt_descr;

extern u32 *kgr_debug_idt_ctr;
extern atomic_t *kgr_trace_idt_ctr;

extern void (*kgr_orig_entry_SYSCALL_64)(void);
extern void (*kgr_orig_entry_SYSCALL_compat)(void);
extern void (*kgr_orig_entry_SYSENTER_compat)(void);

#define PATCH_ENTRY_KALLSYMS						\
	{ "core_kernel_text",						\
			(void *)&kgr_core_kernel_text },		\
	{ "set_memory_rw", (void *)&kgr_set_memory_rw },		\
	{ "sys_call_table", (void *)&kgr_sys_call_table },		\
	{ "used_vectors", (void *)&kgr_used_vectors },			\
	{ "first_system_vector", (void *)&kgr_first_system_vector },	\
	{ "idt_descr", (void *)&kgr_idt_descr },			\
	{ "debug_idt_descr", (void *)&kgr_debug_idt_descr },		\
	{ "trace_idt_descr", (void *)&kgr_trace_idt_descr },		\
	{ "debug_idt_ctr", (void *)&kgr_debug_idt_ctr },		\
	{ "trace_idt_ctr", (void *)&kgr_trace_idt_ctr },		\
	{ "entry_SYSCALL_64",						\
			(void *)&kgr_orig_entry_SYSCALL_64 },		\
	{ "entry_SYSCALL_compat",					\
			(void *)&kgr_orig_entry_SYSCALL_compat },	\
	{ "entry_SYSENTER_compat",					\
			(void *)&kgr_orig_entry_SYSENTER_compat },	\

#endif
