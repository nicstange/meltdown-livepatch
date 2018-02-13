#ifndef _KGR_EFI_64_H
#define _KGR_EFI_64_H

#include <linux/efi.h>

efi_status_t kgr_efi_thunk_set_virtual_address_map(
	void *phys_set_virtual_address_map,
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map);
efi_status_t kgr_efi_thunk_get_time(efi_time_t *tm, efi_time_cap_t *tc);
efi_status_t kgr_efi_thunk_set_time(efi_time_t *tm);
efi_status_t
kgr_efi_thunk_get_wakeup_time(efi_bool_t *enabled, efi_bool_t *pending,
			      efi_time_t *tm);
efi_status_t
kgr_efi_thunk_set_wakeup_time(efi_bool_t enabled, efi_time_t *tm);
efi_status_t
kgr_efi_thunk_get_variable(efi_char16_t *name, efi_guid_t *vendor,
			   u32 *attr, unsigned long *data_size, void *data);
efi_status_t
kgr_efi_thunk_set_variable(efi_char16_t *name, efi_guid_t *vendor,
			   u32 attr, unsigned long data_size, void *data);
efi_status_t
kgr_efi_thunk_get_next_variable(unsigned long *name_size,
				efi_char16_t *name,
				efi_guid_t *vendor);
efi_status_t
kgr_efi_thunk_get_next_high_mono_count(u32 *count);
void
kgr_efi_thunk_reset_system(int reset_type, efi_status_t status,
			   unsigned long data_size, efi_char16_t *data);
efi_status_t
kgr_efi_thunk_query_variable_info(u32 attr, u64 *storage_space,
				  u64 *remaining_space,
				  u64 *max_variable_size);

#endif
