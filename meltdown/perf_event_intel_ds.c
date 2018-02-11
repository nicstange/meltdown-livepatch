#include <linux/cpu.h>
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/topology.h>
#include <linux/atomic.h>
#include <linux/ptrace.h>
#include <asm/perf_event.h>
#include <linux/mutex.h>
#include "perf_event_intel_ds.h"
#include "perf_event_intel_ds_kallsyms.h"
#include "kaiser.h"

struct cpu_hw_events __percpu *kgr_cpu_hw_events;
struct x86_pmu *kgr_x86_pmu;
void * __percpu *kgr_insn_buffer;
struct mutex *kgr_pmc_reserve_mutex;
atomic_t *kgr_pmc_refcount;

void (*kgr_release_ds_buffer)(int cpu);
void (*kgr_init_debug_store_on_cpu)(int cpu);

/* from arch/x86/kernel/cpu/perf_event.h */
/* line 16 */
#define BTS_RECORD_SIZE		24

#define BTS_BUFFER_SIZE		(PAGE_SIZE << 4)
#define PEBS_BUFFER_SIZE	(PAGE_SIZE << 4)
#define PEBS_FIXUP_SIZE		PAGE_SIZE

/* line 91 */
#define MAX_PEBS_EVENTS		8

/* line 111 */
struct debug_store {
	u64	bts_buffer_base;
	u64	bts_index;
	u64	bts_absolute_maximum;
	u64	bts_interrupt_threshold;
	u64	pebs_buffer_base;
	u64	pebs_index;
	u64	pebs_absolute_maximum;
	u64	pebs_interrupt_threshold;
	u64	pebs_event_reset[MAX_PEBS_EVENTS];
};

/* line 171 */
#define MAX_LBR_ENTRIES		32

/* line 172 */
enum {
	X86_PERF_KFREE_SHARED = 0,
	X86_PERF_KFREE_EXCL   = 1,
	X86_PERF_KFREE_MAX
};

/* line 177 */
struct cpu_hw_events {
	/*
	 * Generic x86 PMC bits
	 */
	struct perf_event	*events[X86_PMC_IDX_MAX]; /* in counter order */
	unsigned long		active_mask[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
	unsigned long		running[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
	int			enabled;

	int			n_events; /* the # of events in the below arrays */
	int			n_added;  /* the # last events in the below arrays;
					     they've never been enabled yet */
	int			n_txn;    /* the # last events in the below arrays;
					     added in the current transaction */
	int			assign[X86_PMC_IDX_MAX]; /* event to counter assignment */
	u64			tags[X86_PMC_IDX_MAX];

	struct perf_event	*event_list[X86_PMC_IDX_MAX]; /* in enabled order */
	struct event_constraint	*event_constraint[X86_PMC_IDX_MAX];

	int			n_excl; /* the number of exclusive events */

	unsigned int		txn_flags;
	int			is_fake;

	/*
	 * Intel DebugStore bits
	 */
	struct debug_store	*ds;
	u64			pebs_enabled;

	/*
	 * Intel LBR bits
	 */
	int				lbr_users;
	void				*lbr_context;
	struct perf_branch_stack	lbr_stack;
	struct perf_branch_entry	lbr_entries[MAX_LBR_ENTRIES];
	struct er_account		*lbr_sel;
	u64				br_sel;

	/*
	 * Intel host/guest exclude bits
	 */
	u64				intel_ctrl_guest_mask;
	u64				intel_ctrl_host_mask;
	struct perf_guest_switch_msr	guest_switch_msrs[X86_PMC_IDX_MAX];

	/*
	 * Intel checkpoint mask
	 */
	u64				intel_cp_status;

	/*
	 * manage shared (per-core, per-cpu) registers
	 * used on Intel NHM/WSM/SNB
	 */
	struct intel_shared_regs	*shared_regs;
	/*
	 * manage exclusive counter access between hyperthread
	 */
	struct event_constraint *constraint_list; /* in enable order */
	struct intel_excl_cntrs		*excl_cntrs;
	int excl_thread_id; /* 0 or 1 */

	/*
	 * AMD specific bits
	 */
	struct amd_nb			*amd_nb;
	/* Inverted mask of bits to clear in the perf_ctr ctrl registers */
	u64				perf_ctr_virt_mask;

	void				*kfree_on_online[X86_PERF_KFREE_MAX];
};

/* line 468 */
union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		/*
		 * PMU supports separate counter range for writing
		 * values > 32bit.
		 */
		u64	full_width_write:1;
	};
	u64	capabilities;
};

/* line 503 */
enum {
	x86_lbr_exclusive_lbr,
	x86_lbr_exclusive_bts,
	x86_lbr_exclusive_pt,
	x86_lbr_exclusive_max,
};

/* line 628 */
struct x86_pmu {
	/*
	 * Generic x86 PMC bits
	 */
	const char	*name;
	int		version;
	int		(*handle_irq)(struct pt_regs *);
	void		(*disable_all)(void);
	void		(*enable_all)(int added);
	void		(*enable)(struct perf_event *);
	void		(*disable)(struct perf_event *);
	int		(*hw_config)(struct perf_event *event);
	int		(*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
	unsigned	eventsel;
	unsigned	perfctr;
	int		(*addr_offset)(int index, bool eventsel);
	int		(*rdpmc_index)(int index);
	u64		(*event_map)(int);
	int		max_events;
	int		num_counters;
	int		num_counters_fixed;
	int		cntval_bits;
	u64		cntval_mask;
	union {
			unsigned long events_maskl;
			unsigned long events_mask[BITS_TO_LONGS(ARCH_PERFMON_EVENTS_COUNT)];
	};
	int		events_mask_len;
	int		apic;
	u64		max_period;
	struct event_constraint *
			(*get_event_constraints)(struct cpu_hw_events *cpuc,
						 int idx,
						 struct perf_event *event);

	void		(*put_event_constraints)(struct cpu_hw_events *cpuc,
						 struct perf_event *event);

	void		(*start_scheduling)(struct cpu_hw_events *cpuc);

	void		(*commit_scheduling)(struct cpu_hw_events *cpuc, int idx, int cntr);

	void		(*stop_scheduling)(struct cpu_hw_events *cpuc);

	struct event_constraint *event_constraints;
	struct x86_pmu_quirk *quirks;
	int		perfctr_second_write;
	bool		late_ack;
	unsigned	(*limit_period)(struct perf_event *event, unsigned l);

	/*
	 * sysfs attrs
	 */
	int		attr_rdpmc_broken;
	int		attr_rdpmc;
	struct attribute **format_attrs;
	struct attribute **event_attrs;

	ssize_t		(*events_sysfs_show)(char *page, u64 config);
	struct attribute **cpu_events;

	/*
	 * CPU Hotplug hooks
	 */
	int		(*cpu_prepare)(int cpu);
	void		(*cpu_starting)(int cpu);
	void		(*cpu_dying)(int cpu);
	void		(*cpu_dead)(int cpu);

	void		(*check_microcode)(void);
	void		(*sched_task)(struct perf_event_context *ctx,
				      bool sched_in);

	/*
	 * Intel Arch Perfmon v2+
	 */
	u64			intel_ctrl;
	union perf_capabilities intel_cap;

	/*
	 * Intel DebugStore bits
	 */
	unsigned int	bts		:1,
			bts_active	:1,
			pebs		:1,
			pebs_active	:1,
			pebs_broken	:1,
			pebs_prec_dist	:1;
	int		pebs_record_size;
	int		pebs_buffer_size;
	void		(*drain_pebs)(struct pt_regs *regs);
	struct event_constraint *pebs_constraints;
	void		(*pebs_aliases)(struct perf_event *event);
	int 		max_pebs_events;
	unsigned long	free_running_flags;

	/*
	 * Intel LBR
	 */
	unsigned long	lbr_tos, lbr_from, lbr_to; /* MSR base regs       */
	int		lbr_nr;			   /* hardware stack size */
	u64		lbr_sel_mask;		   /* LBR_SELECT valid bits */
	const int	*lbr_sel_map;		   /* lbr_select mappings */
	bool		lbr_double_abort;	   /* duplicated lbr aborts */

	/*
	 * Intel PT/LBR/BTS are exclusive
	 */
	atomic_t	lbr_exclusive[x86_lbr_exclusive_max];

	/*
	 * Extra registers for events
	 */
	struct extra_reg *extra_regs;
	unsigned int flags;

	/*
	 * Intel host/guest support (KVM)
	 */
	struct perf_guest_switch_msr *(*guest_get_msrs)(int *nr);
};


/* from arch/x86/kernel/cpu/perf_event_intel_ds.c */
/* line 375 */
/* inlined */
static int kgr_alloc_ds_buffer(int cpu)
{
	int node = cpu_to_node(cpu);
	struct debug_store *ds;

	ds = kzalloc_node(sizeof(*ds), GFP_KERNEL, node);
	if (unlikely(!ds))
		return -ENOMEM;

	per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds = ds;

	return 0;
}


/* New */
static void *kgr_dsalloc(size_t size, gfp_t flags, int node)
{
	void *addr;

	/*
	 * Note: upstream does a __alloc_pages_node() allocation
	 * here. For staying compatible with non-livepatched code,
	 * i.e. for allowing a kfree(), continue to reserve the
	 * memory through kmalloc().
	 */
	addr = kmalloc_node(size, flags | __GFP_ZERO, node);
	if (!addr)
		return NULL;
	if (kgr_kaiser_add_mapping((unsigned long)addr, size, __PAGE_KERNEL)) {
		kfree(addr);
		addr = 0;
	}

	return addr;
}

/* New */
static void kgr_dsfree(const void *buffer, size_t size)
{
	kgr_kaiser_remove_mapping((unsigned long)buffer, size);
	kfree(buffer);
}

/* Patched, inlined */
static int kgr_alloc_pebs_buffer(int cpu)
{
	struct debug_store *ds = per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds;
	int node = cpu_to_node(cpu);
	int max;
	void *buffer, *ibuffer;

	if (!kgr_x86_pmu->pebs)
		return 0;

	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	buffer = kgr_dsalloc(kgr_x86_pmu->pebs_buffer_size, GFP_KERNEL, node);
	if (unlikely(!buffer))
		return -ENOMEM;

	/*
	 * HSW+ already provides us the eventing ip; no need to allocate this
	 * buffer then.
	 */
	if (kgr_x86_pmu->intel_cap.pebs_format < 2) {
		ibuffer = kzalloc_node(PEBS_FIXUP_SIZE, GFP_KERNEL, node);
		if (!ibuffer) {
			/*
			 * Fix CVE-2017-5754
			 *  -1 line, +1 line
			 */
			kgr_dsfree(buffer, kgr_x86_pmu->pebs_buffer_size);
			return -ENOMEM;
		}
		*per_cpu_ptr(kgr_insn_buffer, cpu) = ibuffer;
	}

	max = kgr_x86_pmu->pebs_buffer_size / kgr_x86_pmu->pebs_record_size;

	ds->pebs_buffer_base = (u64)(unsigned long)buffer;
	ds->pebs_index = ds->pebs_buffer_base;
	ds->pebs_absolute_maximum = ds->pebs_buffer_base +
		max * kgr_x86_pmu->pebs_record_size;

	return 0;
}

/* Patched */
void kgr_release_pebs_buffer(int cpu)
{
	struct debug_store *ds = per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds;

	if (!ds || !kgr_x86_pmu->pebs)
		return;

	kfree(*per_cpu_ptr(kgr_insn_buffer, cpu));
	*per_cpu_ptr(kgr_insn_buffer, cpu) = NULL;

	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	kgr_dsfree((void *)(unsigned long)ds->pebs_buffer_base,
		    kgr_x86_pmu->pebs_buffer_size);
	ds->pebs_buffer_base = 0;
}

/* Patched, inlined */
static int kgr_alloc_bts_buffer(int cpu)
{
	struct debug_store *ds = per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds;
	int node = cpu_to_node(cpu);
	int max, thresh;
	void *buffer;

	if (!kgr_x86_pmu->bts)
		return 0;

	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	buffer = kgr_dsalloc(BTS_BUFFER_SIZE, GFP_KERNEL | __GFP_NOWARN, node);
	if (unlikely(!buffer)) {
		WARN_ONCE(1, "%s: BTS buffer allocation failure\n", __func__);
		return -ENOMEM;
	}

	max = BTS_BUFFER_SIZE / BTS_RECORD_SIZE;
	thresh = max / 16;

	ds->bts_buffer_base = (u64)(unsigned long)buffer;
	ds->bts_index = ds->bts_buffer_base;
	ds->bts_absolute_maximum = ds->bts_buffer_base +
		max * BTS_RECORD_SIZE;
	ds->bts_interrupt_threshold = ds->bts_absolute_maximum -
		thresh * BTS_RECORD_SIZE;

	return 0;
}

/* Patched */
void kgr_release_bts_buffer(int cpu)
{
	struct debug_store *ds = per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds;

	if (!ds || !kgr_x86_pmu->bts)
		return;

	/*
	 * Fix CVE-2017-5754
	 *  -1 line, +1 line
	 */
	kgr_dsfree((void *)(unsigned long)ds->bts_buffer_base, BTS_BUFFER_SIZE);
	ds->bts_buffer_base = 0;
}

/* Patched, calls inlined alloc_pebs_buffer() and alloc_bts_buffer() */
void kgr_reserve_ds_buffers(void)
{
	int bts_err = 0, pebs_err = 0;
	int cpu;

	kgr_x86_pmu->bts_active = 0;
	kgr_x86_pmu->pebs_active = 0;

	if (!kgr_x86_pmu->bts && !kgr_x86_pmu->pebs)
		return;

	if (!kgr_x86_pmu->bts)
		bts_err = 1;

	if (!kgr_x86_pmu->pebs)
		pebs_err = 1;

	get_online_cpus();

	for_each_possible_cpu(cpu) {
		if (kgr_alloc_ds_buffer(cpu)) {
			bts_err = 1;
			pebs_err = 1;
		}

		if (!bts_err && kgr_alloc_bts_buffer(cpu))
			bts_err = 1;

		if (!pebs_err && kgr_alloc_pebs_buffer(cpu))
			pebs_err = 1;

		if (bts_err && pebs_err)
			break;
	}

	if (bts_err) {
		for_each_possible_cpu(cpu)
			kgr_release_bts_buffer(cpu);
	}

	if (pebs_err) {
		for_each_possible_cpu(cpu)
			kgr_release_pebs_buffer(cpu);
	}

	if (bts_err && pebs_err) {
		for_each_possible_cpu(cpu)
			kgr_release_ds_buffer(cpu);
	} else {
		if (kgr_x86_pmu->bts && !bts_err)
			kgr_x86_pmu->bts_active = 1;

		if (kgr_x86_pmu->pebs && !pebs_err)
			kgr_x86_pmu->pebs_active = 1;

		for_each_online_cpu(cpu)
			kgr_init_debug_store_on_cpu(cpu);
	}

	put_online_cpus();
}


int kgr_perf_event_intel_map_all_ds_buffers(void)
{
	int cpu;
	struct debug_store *ds;
	int ret;

	mutex_lock(kgr_pmc_reserve_mutex);
	if (!atomic_read(kgr_pmc_refcount)) {
		mutex_unlock(kgr_pmc_reserve_mutex);
		return 0;
	}

	for_each_possible_cpu(cpu) {
		ds = per_cpu_ptr(kgr_cpu_hw_events, cpu)->ds;

		if (!ds)
			continue;

		if (ds->pebs_buffer_base) {
			ret = kgr_kaiser_add_mapping(ds->pebs_buffer_base,
						kgr_x86_pmu->pebs_buffer_size,
						__PAGE_KERNEL);
			if (ret) {
				mutex_unlock(kgr_pmc_reserve_mutex);
				return ret;
			}
		}

		if (ds->bts_buffer_base) {
			ret = kgr_kaiser_add_mapping(ds->bts_buffer_base,
						     BTS_BUFFER_SIZE,
						     __PAGE_KERNEL);
			if (ret) {
				mutex_unlock(kgr_pmc_reserve_mutex);
				return ret;
			}
		}
	}
	mutex_unlock(kgr_pmc_reserve_mutex);
	return 0;
}
