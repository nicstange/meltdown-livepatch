#ifndef _SHARED_DATA_KALLSYSMS_H
#define _SHARED_DATA_KALLSYSMS_H

#include <linux/percpu.h>

extern void __percpu * (*kgr__alloc_reserved_percpu)(size_t size, size_t align);

#define SHARED_DATA_KALLSYMS		\
	{ "__alloc_reserved_percpu", (void *)&kgr__alloc_reserved_percpu },

#endif
