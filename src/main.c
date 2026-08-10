// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <asm/page.h>

#include "sc.h"

extern unsigned long (*kallrecon_klp)(const char *name);
extern void find_kallsyms_base(void);

static char sc_key[SC_KEY_MAX] = "kerncall";
module_param_string(key, sc_key, sizeof(sc_key), 0400);

static int find_slot_mode;
module_param(find_slot_mode, int, 0);

static unsigned long __nocfi kr_name_to_addr(const char *name)
{
	if (kallrecon_klp)
		return kallrecon_klp(name);
	return 0;
}

static bool is_task_size_cand(unsigned long v)
{
	if (v == (1UL << 39) || v == (1UL << 48) || v == (1UL << 52))
		return true;
	return false;
}

static int demo_pgd_off(u32 *out)
{
	struct mm_struct *mm;
	unsigned long v;
	unsigned long task_size_pos = 0;
	long i;
	int ret = -ENOENT;

	mm = get_task_mm(current);
	if (!mm)
		return -ENOENT;

	for (i = 0; i < 256; i++) {
		if (copy_from_kernel_nofault(&v, (char *)mm + i * 8, 8))
			break;
		if (is_task_size_cand(v)) {
			task_size_pos = i * 8;
			break;
		}
	}
	if (task_size_pos) {
		for (i = task_size_pos + 8; i < task_size_pos + 64; i += 8) {
			if (copy_from_kernel_nofault(&v, (char *)mm + i, 8))
				break;
			if (v >= 0xffff000000000000UL &&
			    !(v & (PAGE_SIZE - 1))) {
				*out = (u32)i;
				ret = 0;
				break;
			}
		}
	}
	mmput(mm);
	return ret;
}

#define SC_TEST_PATCH   0x2001
#define SC_TEST_UNPATCH 0x2002
#define SC_TEST_PATCH_DUP 0x2003
#define SC_TEST_PATCH_BAD 0x2004
#define SC_TEST_ENTRY   0x2005

static long test_handler(const struct pt_regs *regs)
{
	return 0xDEADBEEF;
}

static int demo_find_slot(void)
{
	unsigned long *sct;
	unsigned long ni;
	unsigned long ni_cfi;
	unsigned long v;
	int i;

	pr_info("[kerncall] layout find_slot called\n");
	sct = (unsigned long *)kr_name_to_addr("sys_call_table");
	ni = kr_name_to_addr("__arm64_sys_ni_syscall");
	ni_cfi = kr_name_to_addr("__arm64_sys_ni_syscall.cfi_jt");
	if (!sct || !ni)
		return -1;
	for (i = 0; i < 512; i++) {
		if (copy_from_kernel_nofault(&v, &sct[i], sizeof(v)))
			continue;
		if (v == ni || (ni_cfi && v == ni_cfi)) {
			pr_info("[kerncall] layout find_slot: slot=%d\n", i);
			return i;
		}
	}
	return -1;
}

#ifdef CONFIG_KERNSC_PATCH
static long demo_dispatch(long cmd, const struct pt_regs *regs, void *priv)
{
	unsigned long orig;

	switch (cmd) {
	case SC_TEST_PATCH:
		return sc_patch(249, (unsigned long)test_handler, &orig);
	case SC_TEST_UNPATCH:
		sc_unpatch(249);
		return 0;
	case SC_TEST_PATCH_DUP:
		return sc_patch(249, (unsigned long)test_handler, &orig);
	case SC_TEST_PATCH_BAD:
		return sc_patch(512, (unsigned long)test_handler, &orig);
#ifdef CONFIG_KERNSC_DISCOVER
	case SC_TEST_ENTRY:
		return sc_entry(regs->regs[2]);
#endif
	default:
		return -ENOSYS;
	}
}
#else
static long demo_dispatch(long cmd, const struct pt_regs *regs, void *priv)
{
	return -ENOSYS;
}
#endif

static struct sc_layout g_layout = {
	.resolve = kr_name_to_addr,
	.pgd_off = demo_pgd_off,
	.find_slot = demo_find_slot,
};

static struct sc_cfg g_cfg;

static int __init kerncall_init(void)
{
	int ret;

	find_kallsyms_base();
	if (!kr_name_to_addr("sys_call_table")) {
		pr_warn("[kerncall] kallsyms recovery failed\n");
		return -ENODATA;
	}

	if (find_slot_mode == 1) {
		g_layout.find_slot = NULL;
		g_cfg.find_slot = NULL;
	} else {
		g_cfg.find_slot = NULL;
	}
	g_cfg.layout = &g_layout;
	g_cfg.dispatch = demo_dispatch;
	strscpy(g_cfg.key, sc_key, sizeof(g_cfg.key));
	g_cfg.priv = &g_layout;

	ret = sc_init(&g_cfg);
	if (ret)
		return ret;

	pr_info("[kerncall] loaded slot=%d\n", sc_get_slot());
	return 0;
}

static void __exit kerncall_exit(void)
{
	sc_exit();
	pr_info("[kerncall] unloaded\n");
}

module_init(kerncall_init);
module_exit(kerncall_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kerncall: syscall channel library demo");
