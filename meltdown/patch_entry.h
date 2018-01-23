#ifndef _PATCH_ENTRY_H
#define _PATCH_ENTRY_H

#ifdef __ASSEMBLY__

.macro KGR_CALL_RELOCS_BEGIN
.pushsection .init.rodata, 524950
.global __kgr_call_relocs_begin
.align 8
__kgr_call_relocs_begin:
.popsection
.endm

.macro KGR_CALL_RELOCS_END
.global __kgr_call_relocs_end
.pushsection .init.rodata, 524950
__kgr_call_relocs_end:
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


.macro KGR_CPU_VAR_RELOCS_BEGIN
.pushsection .init.rodata, 43505556, "a"
.global __kgr_cpu_var_relocs_begin
.align 8
__kgr_cpu_var_relocs_begin:
.popsection
.endm

.macro KGR_CPU_VAR_RELOCS_END
.pushsection .init.rodata, 43505556, "a"
.global __kgr_cpu_var_relocs_end
__kgr_cpu_var_relocs_end:
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

.macro KGR_CPU_VAR_DEC32 var offset=0
.byte 0x65 /* GS segment prefix */
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

.macro KGR_CPU_VAR_OR64 var reg_code offset=0
.byte 0x65 /* GS segment prefix */
.byte 0x48 | ((\reg_code & 0x8) >> 1) /* 64 bit operand size REX prefix,
					 and high bit Mod/RM reg field */
.byte 0x0b /* opcode */
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

#else /* !__ASSEMBLY__ */

#include <linux/init.h>

int __init patch_entry_init(void);
void patch_entry_apply(void);
void patch_entry_unapply(void);
void patch_entry_apply_finish_cpu(void);
void patch_entry_unapply_finish_cpu(void);

#endif /* __ASSEMBLY__ */

#endif
