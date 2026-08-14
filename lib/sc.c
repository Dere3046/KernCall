// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#ifdef CONFIG_KERNSC_TP
#include <linux/compat.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/srcu.h>
#include <linux/thread_info.h>
#include <linux/tracepoint.h>
#include <asm/unistd.h>
#endif

#include "sc.h"
#include "sc_slide.h"

#define SC_PATCH_MAX 16

typedef void (*clean_inval_fn)(unsigned long start, unsigned long end);

static const struct sc_cfg *g_cfg;
static const struct sc_layout *g_layout;
static clean_inval_fn g_clean_inval;

static unsigned long *sys_call_table;
static unsigned long init_mm_addr;
static unsigned long g_ni_addr;
static unsigned long g_ni_cfi;
static unsigned long spg_dir;
static int g_slot = -1;
static DEFINE_SPINLOCK(sc_lock);

static struct {
	unsigned long nr;
	unsigned long orig;
	bool used;
} g_patches[SC_PATCH_MAX];

static unsigned long resolve(const char *name)
{
	if (g_layout && g_layout->resolve)
		return g_layout->resolve(name);
	return 0;
}

int sc_safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

static bool ker_addr_ok(unsigned long v)
{
	return v >= TASK_SIZE;
}

static unsigned long find_kernel_phys(unsigned long addr)
{
	static unsigned long kimage_voffset;
	unsigned long voff;

	if (!kimage_voffset) {
		unsigned long fn = resolve("kimage_voffset");

		if (!fn || !ker_addr_ok(fn)) {
			pr_warn("[kerncall] kimage_voffset not found\n");
			return 0;
		}
		if (sc_safe_read(&voff, (void *)fn, sizeof(voff))) {
			pr_warn("[kerncall] kimage_voffset unreadable\n");
			return 0;
		}
		kimage_voffset = voff;
	}
	return (unsigned long)addr - kimage_voffset;
}

static __nocfi void call_clean_inval(unsigned long start, unsigned long end)
{
	if (!g_clean_inval) {
		g_clean_inval = (clean_inval_fn)resolve("caches_clean_inval_pou");
		if (!g_clean_inval)
			g_clean_inval = (clean_inval_fn)resolve(
				"dcache_clean_inval_poc");
		if (!g_clean_inval)
			g_clean_inval = (clean_inval_fn)resolve(
				"flush_dcache_range");
		if (!g_clean_inval) {
			pr_warn("[kerncall] no cache clean fn\n");
			return;
		}
		if (!ker_addr_ok((unsigned long)g_clean_inval)) {
			pr_warn("[kerncall] bad cache clean addr %px\n",
				g_clean_inval);
			g_clean_inval = NULL;
			return;
		}
	}
	g_clean_inval(start, end);
}


typedef void (*fixmap_fn)(unsigned long idx, phys_addr_t phys,
			  pgprot_t prot);

static fixmap_fn g_set_fixmap;

static __nocfi void call_set_fixmap(unsigned long idx, phys_addr_t phys,
				    pgprot_t prot)
{
	if (!g_set_fixmap) {
		g_set_fixmap = (fixmap_fn)resolve("__set_fixmap");
		if (!g_set_fixmap) {
			pr_warn("[kerncall] __set_fixmap not found\n");
			return;
		}
		if (!ker_addr_ok((unsigned long)g_set_fixmap)) {
			pr_warn("[kerncall] bad __set_fixmap addr %px\n",
				g_set_fixmap);
			g_set_fixmap = NULL;
			return;
		}
	}
	g_set_fixmap(idx, phys, prot);
}

static int patch_write(void *addr, unsigned long val)
{
	unsigned long phys;
	unsigned long fixmap_va;
	unsigned long flags;

	phys = find_kernel_phys((unsigned long)addr);
	if (!phys)
		return -EIO;

	spin_lock_irqsave(&sc_lock, flags);
	call_set_fixmap(FIX_TEXT_POKE0, phys & PAGE_MASK, PAGE_KERNEL);
	fixmap_va = fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK);
	*(unsigned long *)fixmap_va = val;
	dsb(ish);
	call_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));
	spin_unlock_irqrestore(&sc_lock, flags);

	call_clean_inval((unsigned long)addr, (unsigned long)addr + 8);
	return 0;
}

static long sc_handler(const struct pt_regs *regs)
{
	const char __user *key_ptr;
	long cmd;
	char kbuf[SC_KEY_MAX] = {0};
	unsigned long flags;

	key_ptr = (const char __user *)regs->regs[0];
	cmd = regs->regs[1];

	if (!g_cfg)
		return -ENOSYS;

	if (strncpy_from_user(kbuf, key_ptr, sizeof(kbuf) - 1) < 0)
		return -EFAULT;

	spin_lock_irqsave(&sc_lock, flags);
	if (strncmp(kbuf, g_cfg->key, sizeof(kbuf))) {
		spin_unlock_irqrestore(&sc_lock, flags);
		return -EACCES;
	}
	spin_unlock_irqrestore(&sc_lock, flags);

	if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return -EPERM;

	if (cmd == SC_CMD_HELLO)
		return SC_MAGIC;

	if (g_cfg->dispatch)
		return g_cfg->dispatch(cmd, regs, g_cfg->priv);
	return -ENOSYS;
}

static int find_slot_scan(void)
{
	unsigned long v;
	int i;

	if (!sys_call_table)
		return -1;
	for (i = 0; i < 512; i++) {
		if (sc_safe_read(&v, &sys_call_table[i], sizeof(v)))
			continue;
		if (v == g_ni_addr || (g_ni_cfi && v == g_ni_cfi))
			return i;
	}
	return -1;
}

static int find_slot_inner(void)
{
	if (g_cfg->find_slot)
		return g_cfg->find_slot();
	if (g_layout && g_layout->find_slot)
		return g_layout->find_slot();
	return find_slot_scan();
}

#ifdef CONFIG_KERNSC_DISCOVER
unsigned long sc_table_addr(void)
{
	return (unsigned long)sys_call_table;
}

unsigned long sc_entry(unsigned long nr)
{
	unsigned long val;

	if (!sys_call_table)
		return 0;
	if (sc_safe_read(&val, &sys_call_table[nr], sizeof(val)))
		return 0;
	return val;
}

int sc_find_slot_scan(void)
{
	return find_slot_scan();
}
#endif

static int patch_slot(unsigned long nr, unsigned long handler,
		      unsigned long *orig_out)
{
	unsigned long orig;
	int i;

	if (nr >= 512)
		return -EINVAL;
	if (!sys_call_table)
		return -ENODATA;
	if (sc_safe_read(&orig, &sys_call_table[nr], sizeof(orig)))
		return -EFAULT;

	for (i = 0; i < SC_PATCH_MAX; i++) {
		if (g_patches[i].used && g_patches[i].nr == nr)
			return -EEXIST;
	}
	for (i = 0; i < SC_PATCH_MAX; i++) {
		if (!g_patches[i].used) {
			int ret;

			g_patches[i].nr = nr;
			g_patches[i].orig = orig;
			g_patches[i].used = true;
			ret = patch_write(&sys_call_table[nr], handler);
			if (ret) {
				g_patches[i].used = false;
				return ret;
			}
			if (orig_out)
				*orig_out = orig;
			return 0;
		}
	}
	return -ENOSPC;
}

static void unpatch_slot(unsigned long nr)
{
	int i;

	for (i = 0; i < SC_PATCH_MAX; i++) {
		if (g_patches[i].used && g_patches[i].nr == nr) {
			patch_write(&sys_call_table[nr], g_patches[i].orig);
			g_patches[i].used = false;
			return;
		}
	}
}

#ifdef CONFIG_KERNSC_PATCH
int sc_patch(unsigned long nr, unsigned long handler, unsigned long *orig_out)
{
	return patch_slot(nr, handler, orig_out);
}

void sc_unpatch(unsigned long nr)
{
	unpatch_slot(nr);
}
#endif

#ifdef CONFIG_KERNSC_TP
#define TP_ORIG_NR(r) ((r)->regs[8])

/* avoid the const sys_call_table declared in asm/syscall.h */
typedef long (*syscall_fn_t)(const struct pt_regs *regs);

typedef void (*srcu_sync_fn)(struct srcu_struct *sp);

static sc_tp_hook_fn sc_tp_hooks[__NR_syscalls];
static int g_tp_slot = -1;
static struct tracepoint *g_tp_sys_enter;
static bool g_tp_mark_all = true;
static void (*g_tp_mark_cb)(struct task_struct *p, bool on);
static void (*g_tp_on_enter)(int id, struct pt_regs *regs);

static int find_slot_for_tp(void)
{
	unsigned long v;
	int i;

	if (!sys_call_table)
		return -1;
	for (i = 0; i < 512; i++) {
		if (i == g_slot)
			continue;
		if (sc_safe_read(&v, &sys_call_table[i], sizeof(v)))
			continue;
		if (v == g_ni_addr || (g_ni_cfi && v == g_ni_cfi))
			return i;
	}
	return -1;
}

static void tp_mark_proc(struct task_struct *p, bool on)
{
	if (g_tp_mark_cb) {
		g_tp_mark_cb(p, on);
		return;
	}
	if (on)
		set_tsk_thread_flag(p, TIF_SYSCALL_TRACEPOINT);
	else
		clear_tsk_thread_flag(p, TIF_SYSCALL_TRACEPOINT);
}

static void tp_mark_processes(bool on)
{
	struct task_struct *p;

	if (!g_tp_mark_all) {
		tp_mark_proc(current, on);
		return;
	}
	rcu_read_lock();
	for_each_process(p)
		tp_mark_proc(p, on);
	rcu_read_unlock();
}

static long sc_tp_dispatcher(const struct pt_regs *regs)
{
	sc_tp_hook_fn fn;
	int orig_nr;

	if (g_tp_slot < 0)
		return -ENOSYS;
	if (regs->syscallno != g_tp_slot)
		return -ENOSYS;

	orig_nr = (int)TP_ORIG_NR(regs);
	if (regs->syscallno == orig_nr)
		return -ENOSYS;

	((struct pt_regs *)regs)->syscallno = orig_nr;
	((struct pt_regs *)regs)->regs[8] = orig_nr;

	if (orig_nr >= 0 && orig_nr < __NR_syscalls) {
		fn = READ_ONCE(sc_tp_hooks[orig_nr]);
		if (fn)
			return fn(orig_nr, regs);
	}
	return -ENOSYS;
}

static void sc_tp_sys_enter(void *data, struct pt_regs *regs, long id)
{
	struct pt_regs *kregs;

	if (unlikely(is_compat_task()))
		return;
	if (g_tp_slot < 0)
		return;
	if (id < 0 || id >= __NR_syscalls)
		return;

	if (g_tp_on_enter)
		g_tp_on_enter(id, regs);

	if (id == g_tp_slot)
		return;
	if (!READ_ONCE(sc_tp_hooks[id]))
		return;

	kregs = task_pt_regs(current);
	if (!kregs)
		return;
	kregs->regs[8] = id;
	kregs->syscallno = g_tp_slot;
}

int sc_tp_register(int nr, sc_tp_hook_fn fn)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	if (!fn)
		return -EINVAL;
	if (READ_ONCE(sc_tp_hooks[nr]))
		return -EEXIST;
	WRITE_ONCE(sc_tp_hooks[nr], fn);
	return 0;
}

void sc_tp_unregister(int nr)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return;
	WRITE_ONCE(sc_tp_hooks[nr], NULL);
}

bool sc_tp_hooked(int nr)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return false;
	return READ_ONCE(sc_tp_hooks[nr]) != NULL;
}

long __nocfi sc_tp_orig(int nr, const struct pt_regs *regs)
{
	unsigned long orig;
	syscall_fn_t fn;

	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	if (!sys_call_table)
		return -ENODATA;
	if (sc_safe_read(&orig, &sys_call_table[nr], sizeof(orig)))
		return -EFAULT;
	if (!orig)
		return -ENODATA;
	fn = (syscall_fn_t)orig;
	return fn(regs);
}

int sc_tp_slot(void)
{
	return g_tp_slot;
}

static int tp_setup(void)
{
	struct tracepoint *tp;
	int slot;
	int ret;

	g_tp_mark_all = g_cfg->tp_mark_all;
	g_tp_mark_cb = g_cfg->tp_mark_cb;
	g_tp_on_enter = g_cfg->tp_on_enter;

	slot = find_slot_for_tp();
	if (slot < 0) {
		pr_warn("[kerncall] no free slot for tp dispatcher\n");
		return -EBUSY;
	}
	ret = patch_slot(slot, (unsigned long)sc_tp_dispatcher, NULL);
	if (ret) {
		pr_warn("[kerncall] tp dispatcher patch failed\n");
		return ret;
	}
	g_tp_slot = slot;

	tp = (struct tracepoint *)resolve("__tracepoint_sys_enter");
	if (!tp) {
		pr_warn("[kerncall] __tracepoint_sys_enter not found\n");
		ret = -ENODATA;
		goto fail;
	}
	g_tp_sys_enter = tp;

	ret = tracepoint_probe_register(tp, sc_tp_sys_enter, NULL);
	if (ret) {
		pr_warn("[kerncall] tracepoint register failed %d\n", ret);
		goto fail;
	}

	tp_mark_processes(true);
	pr_info("[kerncall] tp dispatcher slot=%d\n", g_tp_slot);
	return 0;

fail:
	unpatch_slot(g_tp_slot);
	g_tp_slot = -1;
	g_tp_sys_enter = NULL;
	return ret;
}

static __nocfi bool call_srcu_sync(struct srcu_struct *sp)
{
	srcu_sync_fn sync;

	sync = (srcu_sync_fn)resolve("synchronize_srcu");
	if (!sync)
		return false;
	sync(sp);
	return true;
}

static void tp_sync_probes(void)
{
	struct srcu_struct *sp;

	sp = (struct srcu_struct *)resolve("tracepoint_srcu");
	if (sp && call_srcu_sync(sp))
		return;
	/* tracepoint_srcu trimmed by TRIM_UNUSED_KSYMS on some builds */
	synchronize_rcu();
}

static void tp_teardown(void)
{
	if (g_tp_sys_enter) {
		tracepoint_probe_unregister(g_tp_sys_enter, sc_tp_sys_enter,
					   NULL);
		tp_sync_probes();
		g_tp_sys_enter = NULL;
	}
	if (g_tp_slot >= 0) {
		unpatch_slot(g_tp_slot);
		g_tp_slot = -1;
	}
	tp_mark_processes(false);
	memset(sc_tp_hooks, 0, sizeof(sc_tp_hooks));
	g_tp_mark_cb = NULL;
	g_tp_on_enter = NULL;
}

#endif

int sc_init(const struct sc_cfg *cfg)
{
	int slot;
#ifdef CONFIG_KERNSC_TP
	int ret;
#endif

	if (!cfg || !cfg->key[0])
		return -EINVAL;
	if (g_cfg)
		return -EALREADY;

	g_cfg = cfg;
	g_layout = cfg->layout;
	if (!g_layout || !g_layout->resolve) {
		pr_warn("[kerncall] no layout resolver\n");
		g_cfg = NULL;
		g_layout = NULL;
		return -EINVAL;
	}

	g_ni_addr = resolve("__arm64_sys_ni_syscall");
	if (!g_ni_addr) {
		pr_warn("[kerncall] __arm64_sys_ni_syscall not found\n");
		return -ENODATA;
	}
	g_ni_cfi = resolve("__arm64_sys_ni_syscall.cfi_jt");
	sys_call_table = (unsigned long *)resolve("sys_call_table");
	if (!sys_call_table) {
		pr_warn("[kerncall] sys_call_table not found\n");
		return -ENODATA;
	}
	init_mm_addr = resolve("init_mm");
	if (!init_mm_addr) {
		pr_warn("[kerncall] init_mm not found\n");
		return -ENODATA;
	}

	if (!cfg->no_patch) {
		slot = find_slot_inner();
		if (slot < 0) {
			pr_warn("[kerncall] no free syscall slot found\n");
			return -EBUSY;
		}

		if (patch_slot(slot, (unsigned long)sc_handler, NULL)) {
			pr_warn("[kerncall] patch failed\n");
			return -EIO;
		}
		g_slot = slot;
	}

#ifdef CONFIG_KERNSC_TP
	if (cfg->tp_enable) {
		ret = tp_setup();
		if (ret) {
			pr_warn("[kerncall] tp dispatcher setup failed %d\n",
				ret);
			return ret;
		}
	}
#endif

	if (cfg->no_patch) {
		pr_info("[kerncall] layout ready, channel not hooked\n");
		return 0;
	}

	pr_info("[kerncall] syscall channel slot=%d key=%s\n", g_slot,
		cfg->key);
	return 0;
}

void sc_exit(void)
{
	int i;

#ifdef CONFIG_KERNSC_TP
	tp_teardown();
#endif
	if (g_slot >= 0)
		unpatch_slot(g_slot);
	for (i = 0; i < SC_PATCH_MAX; i++) {
		if (g_patches[i].used)
			unpatch_slot(g_patches[i].nr);
	}
	g_slot = -1;
	g_cfg = NULL;
	g_layout = NULL;
	spg_dir = 0;
	pr_info("[kerncall] syscall channel closed\n");
}

int sc_get_slot(void)
{
	return g_slot;
}
