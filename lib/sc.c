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

static bool table_ptr_ok(unsigned long v)
{
	return v >= TASK_SIZE && !(v & (PAGE_SIZE - 1));
}

static bool pte_phys_ok(unsigned long entry)
{
	unsigned long phys = __pte_to_phys(__pte(entry));

	return phys && !(phys & (PAGE_SIZE - 1)) && phys < (1UL << 40);
}

static unsigned long *pte_walk(unsigned long addr, unsigned long va_bits)
{
	struct sc_slide_win w;
	unsigned long table = spg_dir;
	unsigned long shift;
	unsigned long entry;
	int levels;
	int level;

	levels = (va_bits - 4) / (PAGE_SHIFT - 3);
	shift = PAGE_SHIFT + (levels - 1) * 9;

	for (level = 0; level < levels - 1; level++) {
		unsigned long idx = (addr >> shift) & 0x1ff;

		if (sc_slide_init(&w, table, PAGE_SIZE, 0))
			return NULL;
		entry = *(unsigned long *)(sc_slide_ptr(&w, sc_slide_buf) +
					   idx * 8);
		if (entry & BIT(1))
			return (unsigned long *)(table + idx * 8);
		if (!table_ptr_ok((unsigned long)__va(__pte_to_phys(__pte(entry)))))
			return NULL;
		table = (unsigned long)__va(__pte_to_phys(__pte(entry)));
		shift -= 9;
	}
	{
		unsigned long idx = (addr >> shift) & 0x1ff;

		if (sc_slide_init(&w, table, PAGE_SIZE, 0))
			return NULL;
		entry = *(unsigned long *)(sc_slide_ptr(&w, sc_slide_buf) +
					   idx * 8);
		if (!pte_present(__pte(entry)))
			return NULL;
		return (unsigned long *)(table + idx * 8);
	}
}

static unsigned long va_bits_symbol(void)
{
	unsigned long fn;
	u32 v;

	fn = resolve("vabits_actual");
	if (fn && ker_addr_ok(fn) &&
	    !sc_safe_read(&v, (void *)fn, sizeof(v)) &&
	    (v == 48 || v == 52))
		return v;
	fn = resolve("pgtable_l5_enabled");
	if (fn && ker_addr_ok(fn) &&
	    !sc_safe_read(&v, (void *)fn, sizeof(v)))
		return v ? 52 : 48;
	return 0;
}

static unsigned long *find_kernel_pte(unsigned long addr)
{
	unsigned long cand[3];
	int ncand = 0;
	int i;

	if (!spg_dir) {
		u32 pgd_off;
		unsigned long pgd_val;

		if (!g_layout || !g_layout->pgd_off) {
			pr_warn("[kerncall] no pgd resolver\n");
			return NULL;
		}
		if (g_layout->pgd_off(&pgd_off)) {
			pr_warn("[kerncall] no pgd offset\n");
			return NULL;
		}
		if (sc_safe_read(&pgd_val, (void *)(init_mm_addr + pgd_off),
				 sizeof(pgd_val))) {
			pr_warn("[kerncall] no pgd\n");
			return NULL;
		}
		spg_dir = pgd_val;
		if (!spg_dir || !table_ptr_ok(spg_dir)) {
			pr_warn("[kerncall] bad pgd %px\n", (void *)spg_dir);
			spg_dir = 0;
			return NULL;
		}
	}

#if defined(CONFIG_ARM64_VA_BITS_39)
	cand[ncand++] = 39;
#elif defined(CONFIG_ARM64_VA_BITS_48)
	cand[ncand++] = 48;
#elif defined(CONFIG_ARM64_VA_BITS_52)
	cand[ncand++] = 52;
#endif
	{
		unsigned long va = va_bits_symbol();
		int j;

		if (va)
			for (j = 0; j < ncand; j++)
				if (cand[j] == va)
					va = 0;
		if (va)
			cand[ncand++] = va;
	}
	if (ncand < 3) {
		unsigned long all[] = { 39, 48, 52 };
		int j;
		int k;

		for (j = 0; j < 3; j++) {
			int dup = 0;

			for (k = 0; k < ncand; k++)
				if (cand[k] == all[j])
					dup = 1;
			if (!dup)
				cand[ncand++] = all[j];
		}
	}

	for (i = 0; i < ncand; i++) {
		unsigned long *ptep = pte_walk(addr, cand[i]);

		if (!ptep)
			continue;
		if (!pte_phys_ok(*(unsigned long *)ptep))
			continue;
		pr_info("[kerncall] pte walk va_bits=%lu\n", cand[i]);
		return ptep;
	}
	pr_warn("[kerncall] no pte for %px\n", (void *)addr);
	return NULL;
}
static __nocfi void call_clean_inval(unsigned long start, unsigned long end)
{
	if (!g_clean_inval) {
		g_clean_inval = (clean_inval_fn)resolve("caches_clean_inval_pou");
		if (!g_clean_inval) {
			pr_warn("[kerncall] caches_clean_inval_pou not found\n");
			return;
		}
		if (!ker_addr_ok((unsigned long)g_clean_inval)) {
			pr_warn("[kerncall] bad caches_clean_inval_pou addr %px\n",
				g_clean_inval);
			g_clean_inval = NULL;
			return;
		}
	}
	g_clean_inval(start, end);
}


static int patch_write(void *addr, unsigned long val)
{
	unsigned long *ptep;
	unsigned long orig;

	ptep = find_kernel_pte((unsigned long)addr);
	if (!ptep) {
		pr_warn("[kerncall] no pte for %px\n", addr);
		return -EIO;
	}

	orig = *ptep;
	*ptep = (orig | PTE_DBM) & ~PTE_RDONLY;
	dsb(ish);

	*(unsigned long *)addr = val;

	*ptep = orig;
	dsb(ish);
	flush_tlb_kernel_range((unsigned long)addr, (unsigned long)addr + 8);
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

int sc_init(const struct sc_cfg *cfg)
{
	int slot;

	if (!cfg || !cfg->key[0])
		return -EINVAL;

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

	if (cfg->no_patch) {
		pr_info("[kerncall] layout ready, channel not hooked\n");
		return 0;
	}

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

	pr_info("[kerncall] syscall channel slot=%d key=%s\n", g_slot,
		cfg->key);
	return 0;
}

void sc_exit(void)
{
	int i;

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
