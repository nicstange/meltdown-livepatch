#ifndef _PGTABLE_KALLSYMS_H
#define _PGTABLE_KALLSYMS_H

#include <linux/spinlock.h>
#include <asm/page.h>

extern spinlock_t *kgr_pgd_lock;
extern struct list_head *kgr_pgd_list;
extern pgd_t (*kgr_init_level4_pgt)[];

#define PGTABLE_KALLSYMS					\
	{ "pgd_lock", (void *)&kgr_pgd_lock },			\
	{ "pgd_list", (void *)&kgr_pgd_list },			\
	{ "init_level4_pgt", (void *)&kgr_init_level4_pgt },	\

#endif
