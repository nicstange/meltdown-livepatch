/*
 * efi_64.c
 *
 * Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/efi.h>
#include <asm/efi.h>
#include "kaiser.h"
#include "efi_64.h"
#include "efi_64_kallsyms.h"

#if !IS_ENABLED(CONFIG_EFI_MIXED)
#error "Livepatch supports only CONFIG_EFI_MIXED=y"
#endif

struct efi_scratch *kgr_efi_scratch;
spinlock_t *kgr_rtc_lock;

void (*kgr_efi_sync_low_kernel_mappings)(void);
efi_status_t (*kgr_efi64_thunk)(u32, ...);


/* from arch/x86/platform/efi/efi_64.c */
#define runtime_service32(func)					 \
({									 \
	u32 table = (u32)(unsigned long)efi.systab;			 \
	u32 *rt, *___f;						 \
									 \
	rt = (u32 *)(table + offsetof(efi_system_table_32_t, runtime));  \
	___f = (u32 *)(*rt + offsetof(efi_runtime_services_32_t, func)); \
	*___f;								 \
})


/* Patched */
#define kgr_efi_thunk(f, ...)						\
({									\
	efi_status_t __s;						\
	unsigned long flags;						\
	u32 func;							\
									\
	kgr_efi_sync_low_kernel_mappings();				\
	local_irq_save(flags);						\
									\
	kgr_efi_scratch->prev_cr3 = read_cr3();			\
	/*								\
	 * Fix CVE-2017-5754						\
	 *  +1 line							\
	 */								\
	kgr_kaiser_set_kern_cr3(0);					\
	write_cr3((unsigned long)kgr_efi_scratch->efi_pgt);		\
	__flush_tlb_all();						\
									\
	func = runtime_service32(f);					\
	__s = kgr_efi64_thunk(func, __VA_ARGS__);			\
									\
	write_cr3(kgr_efi_scratch->prev_cr3);				\
	__flush_tlb_all();						\
	/*								\
	 * Fix CVE-2017-5754						\
	 *  +2 lines							\
	 */								\
	if (kgr_kaiser_get_user_cr3())					\
		kgr_kaiser_set_kern_cr3(kgr_efi_scratch->prev_cr3);	\
	local_irq_restore(flags);					\
									\
	__s;								\
})

/* Patched */
efi_status_t kgr_efi_thunk_set_virtual_address_map(
	void *phys_set_virtual_address_map,
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map)
{
	efi_status_t status;
	unsigned long flags;
	u32 func;

	kgr_efi_sync_low_kernel_mappings();
	local_irq_save(flags);

	kgr_efi_scratch->prev_cr3 = read_cr3();
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	kgr_kaiser_set_kern_cr3(0);
	write_cr3((unsigned long)kgr_efi_scratch->efi_pgt);
	__flush_tlb_all();

	func = (u32)(unsigned long)phys_set_virtual_address_map;
	status = kgr_efi64_thunk(func, memory_map_size, descriptor_size,
				 descriptor_version, virtual_map);

	write_cr3(kgr_efi_scratch->prev_cr3);
	__flush_tlb_all();
	/*
	 * Fix CVE-2017-5754
	 *  +2 lines
	 */
	if (kgr_kaiser_get_user_cr3())
		kgr_kaiser_set_kern_cr3(kgr_efi_scratch->prev_cr3);
	local_irq_restore(flags);

	return status;
}

/* Patched, calls patched efi_thunk() macro */
efi_status_t kgr_efi_thunk_get_time(efi_time_t *tm, efi_time_cap_t *tc)
{
	efi_status_t status;
	u32 phys_tm, phys_tc;

	spin_lock(kgr_rtc_lock);

	phys_tm = virt_to_phys(tm);
	phys_tc = virt_to_phys(tc);

	status = kgr_efi_thunk(get_time, phys_tm, phys_tc);

	spin_unlock(kgr_rtc_lock);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t kgr_efi_thunk_set_time(efi_time_t *tm)
{
	efi_status_t status;
	u32 phys_tm;

	spin_lock(kgr_rtc_lock);

	phys_tm = virt_to_phys(tm);

	status = kgr_efi_thunk(set_time, phys_tm);

	spin_unlock(kgr_rtc_lock);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_get_wakeup_time(efi_bool_t *enabled, efi_bool_t *pending,
			      efi_time_t *tm)
{
	efi_status_t status;
	u32 phys_enabled, phys_pending, phys_tm;

	spin_lock(kgr_rtc_lock);

	phys_enabled = virt_to_phys(enabled);
	phys_pending = virt_to_phys(pending);
	phys_tm = virt_to_phys(tm);

	status = kgr_efi_thunk(get_wakeup_time, phys_enabled,
			       phys_pending, phys_tm);

	spin_unlock(kgr_rtc_lock);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_set_wakeup_time(efi_bool_t enabled, efi_time_t *tm)
{
	efi_status_t status;
	u32 phys_tm;

	spin_lock(kgr_rtc_lock);

	phys_tm = virt_to_phys(tm);

	status = kgr_efi_thunk(set_wakeup_time, enabled, phys_tm);

	spin_unlock(kgr_rtc_lock);

	return status;
}


efi_status_t
kgr_efi_thunk_get_variable(efi_char16_t *name, efi_guid_t *vendor,
			   u32 *attr, unsigned long *data_size, void *data)
{
	efi_status_t status;
	u32 phys_name, phys_vendor, phys_attr;
	u32 phys_data_size, phys_data;

	phys_data_size = virt_to_phys(data_size);
	phys_vendor = virt_to_phys(vendor);
	phys_name = virt_to_phys(name);
	phys_attr = virt_to_phys(attr);
	phys_data = virt_to_phys(data);

	status = kgr_efi_thunk(get_variable, phys_name, phys_vendor,
			       phys_attr, phys_data_size, phys_data);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_set_variable(efi_char16_t *name, efi_guid_t *vendor,
			   u32 attr, unsigned long data_size, void *data)
{
	u32 phys_name, phys_vendor, phys_data;
	efi_status_t status;

	phys_name = virt_to_phys(name);
	phys_vendor = virt_to_phys(vendor);
	phys_data = virt_to_phys(data);

	/* If data_size is > sizeof(u32) we've got problems */
	status = kgr_efi_thunk(set_variable, phys_name, phys_vendor,
			       attr, data_size, phys_data);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_get_next_variable(unsigned long *name_size,
				efi_char16_t *name,
				efi_guid_t *vendor)
{
	efi_status_t status;
	u32 phys_name_size, phys_name, phys_vendor;

	phys_name_size = virt_to_phys(name_size);
	phys_vendor = virt_to_phys(vendor);
	phys_name = virt_to_phys(name);

	status = kgr_efi_thunk(get_next_variable, phys_name_size,
			       phys_name, phys_vendor);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_get_next_high_mono_count(u32 *count)
{
	efi_status_t status;
	u32 phys_count;

	phys_count = virt_to_phys(count);
	status = kgr_efi_thunk(get_next_high_mono_count, phys_count);

	return status;
}

/* Patched, calls patched kgr_efi_thunk() macro */
void
kgr_efi_thunk_reset_system(int reset_type, efi_status_t status,
			   unsigned long data_size, efi_char16_t *data)
{
	u32 phys_data;

	phys_data = virt_to_phys(data);

	kgr_efi_thunk(reset_system, reset_type, status, data_size, phys_data);
}

/* Patched, calls patched kgr_efi_thunk() macro */
efi_status_t
kgr_efi_thunk_query_variable_info(u32 attr, u64 *storage_space,
				  u64 *remaining_space,
				  u64 *max_variable_size)
{
	efi_status_t status;
	u32 phys_storage, phys_remaining, phys_max;

	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	phys_storage = virt_to_phys(storage_space);
	phys_remaining = virt_to_phys(remaining_space);
	phys_max = virt_to_phys(max_variable_size);

	status = kgr_efi_thunk(query_variable_info, attr, phys_storage,
			       phys_remaining, phys_max);

	return status;
}
