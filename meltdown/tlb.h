#ifndef _KGR_TLB_H
#define _KGR_TLB_H

void kgr_native_flush_tlb(void);
void kgr_native_flush_tlb_global(void);
void kgr_native_flush_tlb_single(unsigned long addr);

#endif
