#ifndef _KGR_EXEC_H
#define _KGR_EXEC_H

struct linux_binprm;

int kgr_flush_old_exec(struct linux_binprm * bprm);

#endif
