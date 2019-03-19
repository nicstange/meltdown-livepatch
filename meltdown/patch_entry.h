#ifndef _PATCH_ENTRY_H
#define _PATCH_ENTRY_H

/*
 * Bits 5, 9, 10, 13, 14, 15, 23, 31 of struct thread_info's ->flags
 * are unused and set to zero on an unpatched kernel. Abuse them for a
 * "refcnt magic": iff one of those flags is set, the task holds a
 * reference count on the entry code. This livepatch uses bit 5 only,
 * future livepatches stacked on top can use the other bits for their
 * own reference count instances, thus allowing for up to 256 different
 * livepatch releases.
 */
#define KGR__TIF_OWNS_ENTRY_REFCNT_MASK	\
	((_AC(1, u) << 5) |			\
	 (_AC(1, u) << 9) |			\
	 (_AC(1, u) << 10) |			\
	 (_AC(1, u) << 13) |			\
	 (_AC(1, u) << 14) |			\
	 (_AC(1, u) << 15) |			\
	 (_AC(1, u) << 23) |			\
	 (_AC(1, u) << 31))

#define KGR_TIF_OWNS_ENTRY_REFCNT 5
#define KGR__TIF_OWNS_ENTRY_REFCNT		\
	(_AC(1, u) << KGR_TIF_OWNS_ENTRY_REFCNT)

#ifdef __ASSEMBLY__

#define KGR__TIF_ALLWORK_MASK					\
	(_TIF_ALLWORK_MASK & ~KGR__TIF_OWNS_ENTRY_REFCNT_MASK)


.macro KGR_CALL_RELOCS_BEGIN name
.pushsection .init.rodata, 524950
.global __kgr_call_relocs_begin_\name
.align 8
 __kgr_call_relocs_begin_\name:
.popsection
.endm

.macro KGR_CALL_RELOCS_END name
.global __kgr_call_relocs_end_\name
.pushsection .init.rodata, 524950
__kgr_call_relocs_end_\name:
.popsection
.endm

.macro KGR_CALL_PATCH fun
.byte 0xe8 /* opcode */
524950:
.int 0xdecafbad
.pushsection .init.rodata, 524950, "a"
	.quad 524950b
	.quad \fun
.popsection
.endm

.macro KGR_JMP_PATCH fun
.byte 0xe9 /* opcode */
524950:
.int 0xdecafbad
.pushsection .init.rodata, 524950, "a"
	.quad 524950b
	.quad \fun
.popsection
.endm

.macro KGR_LEA_PATCH addr reg_code
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x8d /* opcode */
.byte ((\reg_code & 0x07) << 3) | 0x5 /* Mod/RM: RIP-relative */
524950:
.int 0xdecafbad
.pushsection .init.rodata, 524950, "a"
	.quad 524950b
	.quad \addr
.popsection
.endm


.macro KGR_CPU_VAR_RELOCS_BEGIN name
.pushsection .init.rodata, 43505556, "a"
.global __kgr_cpu_var_relocs_begin_\name
.align 8
__kgr_cpu_var_relocs_begin_\name:
.popsection
.endm

.macro KGR_CPU_VAR_RELOCS_END name
.pushsection .init.rodata, 43505556, "a"
.global __kgr_cpu_var_relocs_end_\name
__kgr_cpu_var_relocs_end_\name:
.popsection
.endm

.macro KGR_CPU_VAR_RELOC var offset
43505556:
.pushsection .init.rodata, 43505556, "a"
	.quad 43505556b
	.quad \var
	.word \offset
	.word 0 /* padding */
	.int 0 /* padding */
.popsection
.int 0xdecafbad
.endm

#define KGR_REG_CODE_AX 0x0
#define KGR_REG_CODE_CX 0x1
#define KGR_REG_CODE_DX 0x2
#define KGR_REG_CODE_BX 0x3
#define KGR_REG_CODE_SP 0x4
#define KGR_REG_CODE_BP 0x5
#define KGR_REG_CODE_SI 0x6
#define KGR_REG_CODE_DI 0x7
#define KGR_REG_CODE_R8 8
#define KGR_REG_CODE_R9 9
#define KGR_REG_CODE_R10 10
#define KGR_REG_CODE_R11 11
#define KGR_REG_CODE_R12 12
#define KGR_REG_CODE_R13 13
#define KGR_REG_CODE_R14 14
#define KGR_REG_CODE_R15 15


.macro KGR_CPU_VAR_LOAD64 var reg_code offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x8b   /* opcode */
.byte 0x04 | ((\reg_code & 0x07) << 3) /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_STORE64 reg_code var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x89   /* opcode */
.byte 0x04 | ((\reg_code & 0x07) << 3) /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_PUSH64 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0xff /* opcode */
.byte 0x34 /* Mod/RM: SIB byte follows, opcode = 6 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_POP64 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x8f /* opcode */
.byte 0x04 /* Mod/RM: SIB byte follows, opcode = 0 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_INC32 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0xff /* opcode */
.byte 0x04 /* Mod/RM: SIB byte follows, opcode = 0 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_INC64 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 /* 64 bit operand size REX prefix */
.byte 0xff /* opcode */
.byte 0x04 /* Mod/RM: SIB byte follows, opcode = 0 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_DEC32 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0xff /* opcode */
.byte 0x0c /* Mod/RM: SIB byte follows, opcode = 1 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_DEC64 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 /* 64 bit operand size REX prefix */
.byte 0xff /* opcode */
.byte 0x0c /* Mod/RM: SIB byte follows, opcode = 1 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_CMP32_IMM8 imm8 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x83 /* opcode */
.byte 0x3c /* Mod/RM: SIB byte follows, opcode = 7 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.byte \imm8
.endm

.macro KGR_CPU_VAR_CLOADZ64 var reg_code offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x0f, 0x44 /* opcode */
.byte 0x04 | ((\reg_code & 0x07) << 3) /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_ADD64_IMM32 imm32 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 /* 64 bit operand size REX prefix */
.byte 0x81 /* opcode */
.byte 0x04 /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.int \imm32
.endm

.macro KGR_CPU_VAR_SUB64_IMM32 imm32 var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 /* 64 bit operand size REX prefix */
.byte 0x81 /* opcode */
.byte 0x2c /* Mod/RM: SIB byte follows, opcode=5 */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.int \imm32
.endm

.macro KGR_CPU_VAR_STORE8_OR reg_code var offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x40 | ((\reg_code & 0x8) >> 1) /* REX prefix,
					 high bit Mod/RM reg field */
.byte 0x08 /* opcode */
.byte 0x04 | ((\reg_code & 0x07) << 3) /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_CPU_VAR_LOAD64_XOR var reg_code offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x33 /* opcode */
.byte 0x04 | ((\reg_code & 0x07) << 3) /* Mod/RM: SIB byte follows */
.byte 0x25 /* SIB, use absolute offset ("disp32") */
KGR_CPU_VAR_RELOC \var \offset
.endm

.macro KGR_ENTRY_ENTER offset=0
	lock orl $KGR__TIF_OWNS_ENTRY_REFCNT, ASM_THREAD_INFO(TI_flags, %rsp, SIZEOF_PTREGS + \offset)
	KGR_CPU_VAR_INC64 entry_refcnt
.endm

.macro KGR_ENTRY_LEAVE offset=0
	lock andl $~KGR__TIF_OWNS_ENTRY_REFCNT, ASM_THREAD_INFO(TI_flags, %rsp, SIZEOF_PTREGS + \offset)
	KGR_CPU_VAR_DEC64 entry_refcnt
.endm

#else /* !__ASSEMBLY__ */

#include <linux/init.h>
#include <linux/percpu.h>
#include <asm/irq_vectors.h>
#include <asm/desc_defs.h>

int __init patch_entry_init(void);
void patch_entry_cleanup(void);

struct saved_idt
{
	unsigned long idt;
	unsigned long debug_idt;
	unsigned long trace_idt;
};

void patch_entry_apply_start(struct saved_idt *orig_idt);
void patch_entry_unapply_start(struct saved_idt const *orig_idt);
void patch_entry_apply_finish_cpu(void);
void patch_entry_unapply_finish_cpu(void);

void patch_entry_drain_start(void);

extern bool patch_entry_draining;

extern char __kgr_entry_text_begin[];
extern char __kgr_entry_text_end[];
extern char __kgr_compat_entry_text_begin[];
extern char __kgr_compat_entry_text_end[];

extern gate_desc kgr_idt_table[NR_VECTORS];
extern gate_desc kgr_debug_idt_table[NR_VECTORS];
extern gate_desc kgr_trace_idt_table[NR_VECTORS];

DECLARE_PER_CPU(long, __entry_refcnt);

#endif /* __ASSEMBLY__ */

#endif
