#ifndef _KGR_PERF_EVENT_INTEL_DS_H
#define _KGR_PERF_EVENT_INTEL_DS_H

void kgr_release_pebs_buffer(int cpu);
void kgr_release_bts_buffer(int cpu);
void kgr_reserve_ds_buffers(void);

#endif
