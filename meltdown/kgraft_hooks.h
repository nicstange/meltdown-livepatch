#ifndef _KGRAFT_HOOKS_H
#define _KGRAFT_HOOKS_H

struct module;

void kgr_post_patch_callback(void);
void kgr_pre_replace_callback(struct module *new_mod);
void kgr_pre_revert_callback(void);

#endif
