// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef KERNCALL_SC_H
#define KERNCALL_SC_H

#include <linux/types.h>

#define SC_KEY_MAX 64
#define SC_CMD_HELLO 0x1000
#define SC_MAGIC 0x53434831UL

struct pt_regs;
struct task_struct;

#ifdef CONFIG_KERNSC_TP
typedef long (*sc_tp_hook_fn)(int nr, const struct pt_regs *regs);
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

struct sc_cfg {
	const struct sc_layout *layout;
	long (*dispatch)(long cmd, const struct pt_regs *regs, void *priv);
	int (*find_slot)(void);
	char key[SC_KEY_MAX];
	void *priv;
	bool no_patch;
#ifdef CONFIG_KERNSC_TP
	bool tp_enable;
	bool tp_mark_all;
	void (*tp_mark_cb)(struct task_struct *p, bool on);
	void (*tp_on_enter)(int id, struct pt_regs *regs);
#endif
};

int sc_init(const struct sc_cfg *cfg);
void sc_exit(void);
int sc_get_slot(void);
int sc_safe_read(void *dst, const void *src, size_t sz);

#ifdef CONFIG_KERNSC_TP
int sc_tp_register(int nr, sc_tp_hook_fn fn);
void sc_tp_unregister(int nr);
bool sc_tp_hooked(int nr);
long sc_tp_orig(int nr, const struct pt_regs *regs);
int sc_tp_slot(void);
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
