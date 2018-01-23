#ifndef _SCHEDULE_TAIL_KALLSYMS_H
#define _SCHEDULE_TAIL_KALLSYMS_H

struct task_struct;

extern struct rq* (*kgr_finish_task_switch)(struct task_struct *prev);
extern void (*kgr__balance_callback)(struct rq *rq);

#define SCHEDULE_TAIL_KALLSYMS						\
	{ "finish_task_switch", (void *)&kgr_finish_task_switch },	\
	{ "__balance_callback", (void *)&kgr__balance_callback },	\

#endif
