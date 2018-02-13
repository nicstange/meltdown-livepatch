#ifndef _EFI_64_KALLSYMS_H
#define _EFI_64_KALLSYMS_H

#include <linux/efi.h>

extern struct efi_scratch *kgr_efi_scratch;
extern spinlock_t *kgr_rtc_lock;

extern void (*kgr_efi_sync_low_kernel_mappings)(void);
extern efi_status_t (*kgr_efi64_thunk)(u32, ...);

#define EFI_64_KALLSYMS					\
	{ "efi_scratch", (void *)&kgr_efi_scratch },		\
	{ "rtc_lock", (void *)&kgr_rtc_lock },			\
	{ "efi_sync_low_kernel_mappings",			\
		(void *)&kgr_efi_sync_low_kernel_mappings },	\
	{ "efi64_thunk", (void *)&kgr_efi64_thunk },		\

#endif
