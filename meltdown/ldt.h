#ifndef _KGR_LDT_H
#define _KGR_LDT_H

struct mm_struct;

struct ldt_struct *kgr_alloc_ldt_struct(int size);
void kgr_destroy_context_ldt(struct mm_struct *mm);
int kgr_write_ldt(void __user *ptr, unsigned long bytecount, int oldmode);

#endif
