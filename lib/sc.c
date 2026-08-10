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

static int sc_safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

static __nocfi void call_clean_inval(unsigned long start, unsigned long end)
{
	if (!g_clean_inval) {
		g_clean_inval = (clean_inval_fn)resolve("caches_clean_inval_pou");
		if (!g_clean_inval) {
			pr_warn("[kerncall] caches_clean_inval_pou not found\n");
			return;
		}
	}
	g_clean_inval(start, end);
}

static unsigned long *find_kernel_pte(unsigned long addr)
{
	pgd_t *pgd;
	pgd_t *pgde;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	u32 pgd_off;
	unsigned long pgd_val;

	if (!spg_dir) {
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
		if (!spg_dir) {
			pr_warn("[kerncall] no pgd\n");
			return NULL;
		}
	}

	pgde = pgd_offset_pgd((pgd_t *)spg_dir, addr);
	if (pgd_none(*pgde) || pgd_bad(*pgde))
		return NULL;
	p4d = p4d_offset(pgde, addr);
	if (p4d_none(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud))
		return (unsigned long *)pud;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd))
		return (unsigned long *)pmd;
	if (!pmd_table(*pmd))
		return NULL;
	return (unsigned long *)pte_offset_kernel(pmd, addr);
}

static void patch_write(void *addr, unsigned long val)
{
	unsigned long *ptep;
	unsigned long orig;

	ptep = find_kernel_pte((unsigned long)addr);
	if (!ptep) {
		pr_warn("[kerncall] no pte for %px\n", addr);
		return;
	}

	orig = *ptep;
	*ptep = (orig | PTE_DBM) & ~PTE_RDONLY;
	dsb(ish);

	*(unsigned long *)addr = val;

	*ptep = orig;
	dsb(ish);
	flush_tlb_kernel_range((unsigned long)addr, (unsigned long)addr + 8);
	call_clean_inval((unsigned long)addr, (unsigned long)addr + 8);
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
			g_patches[i].nr = nr;
			g_patches[i].orig = orig;
			g_patches[i].used = true;
			patch_write(&sys_call_table[nr], handler);
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
