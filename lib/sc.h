// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef KERNCALL_SC_H
#define KERNCALL_SC_H

#include <linux/types.h>

#define SC_KEY_MAX 64
#define SC_CMD_HELLO 0x1000
#define SC_CMD_SESSION 0x1001
#define SC_CMD_BATCH 0x1002
#define SC_MAGIC 0x53434831UL

#define SC_ARG_KEY 0
#define SC_ARG_CMD 1
#define SC_ARG_ARG0 2
#define SC_ARG_ARG1 3
#define SC_ARG_ARG2 4
#define SC_ARG_ARG3 5
#define SC_ARG_MAX SC_ARG_ARG3

/* the replay guard and the batch container take their own arguments here */
#define SC_ARG_NONCE SC_ARG_ARG0
#define SC_ARG_SEQ SC_ARG_ARG1
#define SC_ARG_BATCH SC_ARG_ARG2

#define SC_REPLAY_SESS_MAX 16
#define SC_FD_PERM_MAX 16
#define SC_BATCH_MAX 16
#define SC_BATCH_ARGS 4

struct file;
struct pt_regs;
struct task_struct;

/*
 * one command of a batch, the arguments land in regs[SC_ARG_ARG0..3], so a
 * handler reads a batched command exactly like a direct one
 */
struct sc_batch_entry {
	long cmd;
	unsigned long arg[SC_BATCH_ARGS];
};

/*
 * the batch descriptor, copied in and out of the caller in two copies.
 * count is read, ret is written per entry, entry holds the commands
 */
struct sc_batch {
	unsigned long count;
	long ret[SC_BATCH_MAX];
	struct sc_batch_entry entry[SC_BATCH_MAX];
};

#ifdef CONFIG_KERNSC_TP
typedef long (*sc_tp_hook_fn)(int nr, const struct pt_regs *regs);

/*
 * process tiers the tracepoint marker can select. a consumer classifies a
 * task into any of them from its own identity sources, the library only
 * filters the mask it is given
 */
#define SC_TP_TIER_ROOT_DOMAIN (1u << 0)
#define SC_TP_TIER_ZYGOTE (1u << 1)
#define SC_TP_TIER_INIT (1u << 2)
#define SC_TP_TIER_SHELL (1u << 3)
#define SC_TP_TIER_ALLOW_UID (1u << 4)
#define SC_TP_TIER_ALL \
	(SC_TP_TIER_ROOT_DOMAIN | SC_TP_TIER_ZYGOTE | SC_TP_TIER_INIT | \
	 SC_TP_TIER_SHELL | SC_TP_TIER_ALLOW_UID)
#endif

/*
 * layout discovery library injection, e.g. a type_info wrapper.
 * pointer injected so the channel never links the layout source.
 * find_slot is the empty-slot discovery method, supplied by the
 * consumer (its own logic or a layout library probe).
 */
struct sc_layout {
	unsigned long (*resolve)(const char *name);
	int (*pgd_off)(u32 *out);
	int (*find_slot)(void);
};

/*
 * command grades, also the bit numbering of the fd permission word, so a
 * command of grade G is satisfied by an fd granted SC_FD_PERM(G)
 */
enum sc_perm {
	SC_PERM_ROOT = 0,
	SC_PERM_MANAGER,
	SC_PERM_ROOT_MANAGER,
	SC_PERM_SU,
	SC_PERM_DOMAIN,
	SC_PERM_ALWAYS,
	SC_PERM_CUSTOM,
	SC_PERM_MAX
};

#define SC_FD_PERM(grade) (1u << (grade))

struct sc_cmd {
	unsigned long cmd;
	const char *name;
	long (*handler)(const struct pt_regs *regs, void *priv);
	bool (*perm_check)(const struct pt_regs *regs, void *priv);
	unsigned int perm;
	unsigned char fd_arg;
	bool no_replay;
	/*
	 * read only and side effect free, which is the whole fast path
	 * criterion: such an entry is also replay safe, so it has to carry
	 * no_replay as well and it must not depend on the fd capability.
	 * sc_init warns about an entry that misses either
	 */
	bool read_only;
};

struct sc_cfg {
	const struct sc_layout *layout;
	long (*dispatch)(long cmd, const struct pt_regs *regs, void *priv);
	int (*find_slot)(void);
	char key[SC_KEY_MAX];
	void *priv;
	bool no_patch;
	bool (*is_manager)(void);
	bool (*is_domain)(const struct task_struct *p);
	bool (*is_allow_uid)(uid_t uid);
	const struct sc_cmd *cmds;
	unsigned int ncmds;
	bool replay_enable;
	unsigned long replay_ttl_ms;
	u64 (*replay_sid)(const struct pt_regs *regs, void *priv);
#ifdef CONFIG_KERNSC_TP
	bool tp_enable;
	bool tp_mark_all;
	void (*tp_mark_cb)(struct task_struct *p, bool on);
	void (*tp_on_enter)(int id, struct pt_regs *regs);
	unsigned int tp_tier_mask;
	/*
	 * tier classifier, a mask of SC_TP_TIER_* bits. it runs from the
	 * marker with the task list under rcu_read_lock and preemption
	 * disabled, so it must not sleep, and it only decides marking while
	 * the tracepoint has no other user
	 */
	unsigned int (*tp_tier_cb)(const struct task_struct *p, void *priv);
#endif
};

int sc_init(const struct sc_cfg *cfg);
void sc_exit(void);
int sc_get_slot(void);
int sc_safe_read(void *dst, const void *src, size_t sz);

int sc_fd_perm_grant(struct file *file, unsigned int perms,
		     unsigned long ttl_ms);
void sc_fd_perm_clear(struct file *file);
unsigned int sc_fd_perm_get(struct file *file);

int sc_replay_open(u64 sid, u64 nonce);
void sc_replay_close(u64 sid);

/*
 * run the batch of regs[SC_ARG_BATCH]. the built-in SC_CMD_BATCH is this
 * call behind its own grade, a consumer table entry may use it to give the
 * container a different grade
 */
long sc_batch_run(const struct pt_regs *regs);

#ifdef CONFIG_KERNSC_TP
int sc_tp_register(int nr, sc_tp_hook_fn fn);
void sc_tp_unregister(int nr);
bool sc_tp_hooked(int nr);
long sc_tp_orig(int nr, const struct pt_regs *regs);
int sc_tp_slot(void);
int sc_tp_reg_count(void);
#endif

#ifdef CONFIG_KERNSC_DISCOVER
unsigned long sc_table_addr(void);
unsigned long sc_entry(unsigned long nr);
int sc_find_slot_scan(void);
#endif

#ifdef CONFIG_KERNSC_PATCH
int sc_patch(unsigned long nr, unsigned long handler, unsigned long *orig_out);
void sc_unpatch(unsigned long nr);
#endif

#endif
