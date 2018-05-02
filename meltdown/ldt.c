/*
 * ldt.c
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

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/paravirt.h>
#include "kaiser.h"
#include "ldt.h"


#if !IS_ENABLED(CONFIG_MODIFY_LDT_SYSCALL)
#error "Livepatch supports only CONFIG_MODIFY_LDT_SYSCALL=y"
#endif

void (*kgr_flush_ldt)(void *current_mm);


/* from arch/x86/kernel/ldt.c */
/* inlined */
static void kgr_finalize_ldt_struct(struct ldt_struct *ldt)
{
	paravirt_alloc_ldt(ldt->entries, ldt->size);
}

/* context.lock is held */
/* inlined */
static void kgr_install_ldt(struct mm_struct *current_mm,
			    struct ldt_struct *ldt)
{
	/* Synchronizes with lockless_dereference in load_mm_ldt. */
	smp_store_release(&current_mm->context.ldt, ldt);

	/* Activate the LDT for all CPUs using current_mm. */
	on_each_cpu_mask(mm_cpumask(current_mm), kgr_flush_ldt,
			 current_mm, true);
}


/* New */
static void kgr__free_ldt_struct(struct ldt_struct *ldt)
{
	if (ldt->size * LDT_ENTRY_SIZE > PAGE_SIZE)
		vfree(ldt->entries);
	else
		free_page((unsigned long)ldt->entries);
	kfree(ldt);
}

/* Patched */
struct ldt_struct *kgr_alloc_ldt_struct(int size)
{
	struct ldt_struct *new_ldt;
	int alloc_size;
	/*
	 * Fix CVE-2017-5754
	 *  +1 line
	 */
	int ret;

	if (size > LDT_ENTRIES)
		return NULL;

	new_ldt = kmalloc(sizeof(struct ldt_struct), GFP_KERNEL);
	if (!new_ldt)
		return NULL;

	BUILD_BUG_ON(LDT_ENTRY_SIZE != sizeof(struct desc_struct));
	alloc_size = size * LDT_ENTRY_SIZE;

	/*
	 * Xen is very picky: it requires a page-aligned LDT that has no
	 * trailing nonzero bytes in any page that contains LDT descriptors.
	 * Keep it simple: zero the whole allocation and never allocate less
	 * than PAGE_SIZE.
	 */
	if (alloc_size > PAGE_SIZE)
		new_ldt->entries = vzalloc(alloc_size);
	else
		new_ldt->entries = (void *)get_zeroed_page(GFP_KERNEL);

	if (!new_ldt->entries) {
		kfree(new_ldt);
		return NULL;
	}

	/*
	 * Fix CVE-2017-5754
	 *  +2 lines
	 */
	ret = kgr_kaiser_add_mapping((unsigned long)new_ldt->entries,
				     alloc_size, __PAGE_KERNEL);
	new_ldt->size = size;
	if (ret) {
		kgr__free_ldt_struct(new_ldt);
		return NULL;
	}
	return new_ldt;
}

/* Patched, optimized */
static void kgr_free_ldt_struct(struct ldt_struct *ldt)
{
	if (likely(!ldt))
		return;

	/*
	 * Fix CVE-2017-5754
	 *  +2 lines
	 */
	kgr_kaiser_remove_mapping((unsigned long)ldt->entries,
				  ldt->size * LDT_ENTRY_SIZE);
	paravirt_free_ldt(ldt->entries, ldt->size);
	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	kgr__free_ldt_struct(ldt);
}

/* Patched, calls optimized kgr_free_ldt_struct() */
void kgr_destroy_context_ldt(struct mm_struct *mm)
{
	kgr_free_ldt_struct(mm->context.ldt);
	mm->context.ldt = NULL;
}

/* Patched, calls optimized kgr_free_ldt_struct() */
int kgr_write_ldt(void __user *ptr, unsigned long bytecount, int oldmode)
{
	struct mm_struct *mm = current->mm;
	struct desc_struct ldt;
	int error;
	struct user_desc ldt_info;
	int oldsize, newsize;
	struct ldt_struct *new_ldt, *old_ldt;

	error = -EINVAL;
	if (bytecount != sizeof(ldt_info))
		goto out;
	error = -EFAULT;
	if (copy_from_user(&ldt_info, ptr, sizeof(ldt_info)))
		goto out;

	error = -EINVAL;
	if (ldt_info.entry_number >= LDT_ENTRIES)
		goto out;
	if (ldt_info.contents == 3) {
		if (oldmode)
			goto out;
		if (ldt_info.seg_not_present == 0)
			goto out;
	}

	if ((oldmode && !ldt_info.base_addr && !ldt_info.limit) ||
	    LDT_empty(&ldt_info)) {
		/* The user wants to clear the entry. */
		memset(&ldt, 0, sizeof(ldt));
	} else {
		if (!IS_ENABLED(CONFIG_X86_16BIT) && !ldt_info.seg_32bit) {
			error = -EINVAL;
			goto out;
		}

		fill_ldt(&ldt, &ldt_info);
		if (oldmode)
			ldt.avl = 0;
	}

	mutex_lock(&mm->context.lock);

	old_ldt = mm->context.ldt;
	oldsize = old_ldt ? old_ldt->size : 0;
	newsize = max((int)(ldt_info.entry_number + 1), oldsize);

	error = -ENOMEM;
	new_ldt = kgr_alloc_ldt_struct(newsize);
	if (!new_ldt)
		goto out_unlock;

	if (old_ldt)
		memcpy(new_ldt->entries, old_ldt->entries, oldsize * LDT_ENTRY_SIZE);
	new_ldt->entries[ldt_info.entry_number] = ldt;
	kgr_finalize_ldt_struct(new_ldt);

	kgr_install_ldt(mm, new_ldt);
	kgr_free_ldt_struct(old_ldt);
	error = 0;

out_unlock:
	mutex_unlock(&mm->context.lock);
out:
	return error;
}
