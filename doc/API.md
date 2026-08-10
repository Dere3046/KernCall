# Kerncall API

kernel syscall channel library. hijacks a free `ni_syscall` slot in
`sys_call_table` and routes userland `syscall(nr, key, cmd, ...)`
calls to a dispatch callback. can also patch arbitrary existing
syscall slots.

## Layout injection

the library never links a layout source. all kernel layout
capabilities come from a pointer-injected `struct sc_layout`,
typically wrapping type_info (BTF first, anchor fallback) plus
KallRecon for symbol resolution. any implementation can be swapped
in, cross-source compatible.

```c
struct sc_layout {
	unsigned long (*resolve)(const char *name);
	int (*pgd_off)(u32 *out);
	int (*find_slot)(void);
};
```

- `resolve`: symbol name to address. used for `sys_call_table`,
  `__arm64_sys_ni_syscall` (+ `.cfi_jt`), `init_mm` and lazily for
  `caches_clean_inval_pou`. on old-CFI kernels the wrapper must be
  a `__nocfi` function around `kallrecon_klp`, passing the raw
  pointer makes the module's indirect call check fail with a CFI
  panic
- `pgd_off`: byte offset of `mm_struct.pgd`, for the PTE walk that
  makes the table writable. from BTF or an anchor scan
- `find_slot`: optional empty-slot discovery method supplied by the
  layout library. see Slot discovery

## Lifecycle

**int sc_init(const struct sc_cfg *cfg)**

the one call that starts everything. resolves symbols, discovers a
slot, patches in the handler. 0 on success.
-EINVAL when cfg, key or layout resolver is bad.
-ENODATA when a required symbol cannot be resolved.
-EBUSY when no slot is found. -EIO when the patch fails.
not reentrant: a second sc_init while the channel is active fails
with -EIO, call sc_exit first.

**void sc_exit(void)**

restores every patched slot and unregisters. safe to call multiple
times.

**int sc_get_slot(void)**

the channel syscall number. -1 before sc_init or after sc_exit.

## Callbacks (struct sc_cfg)

```c
struct sc_cfg {
	const struct sc_layout *layout;
	long (*dispatch)(long cmd, const struct pt_regs *regs, void *priv);
	int (*find_slot)(void);
	char key[SC_KEY_MAX];
	void *priv;
};
```

the callbacks are the customization surface. every behavior is
overridable: slot discovery, command handling, and through the
patch API the syscall table itself.

**dispatch**

command handler. called from the syscall handler after key
authentication and root check. this is where the consumer
implements its own syscall injection logic: parse commands from
regs, act on them, return a long result which becomes the syscall
return value. `priv` is the cfg.priv pointer, passed through
unchanged. may be NULL, then all non-HELLO commands return
-ENOSYS.

**find_slot**

consumer supplied slot discovery. returning -1 makes sc_init fail
with -EBUSY. see Slot discovery for the selection order. consumers
that only want to find an empty slot can supply their own method
here, or leave it unset to use the library default.

**key**

authentication key, any non-empty string chosen by the caller.
the same string is expected from the userland side as the first
syscall argument.

**priv**

caller supplied context, forwarded to dispatch.

## Slot discovery

selection order, first hit wins:

1. `cfg->find_slot`: consumer's own method (its logic, or anything
   it wants)
2. `layout->find_slot`: layout library probe
3. library default find_slot_scan: resolve `sys_call_table`
   and `__arm64_sys_ni_syscall` (plus `.cfi_jt`), then scan
   `sys_call_table[0..511]` with the safe read and match the first
   ni entry. the internal default is a static function; the
   exported wrapper `sc_find_slot_scan` is only built under
   CONFIG_KERNSC_DISCOVER

this is a consumer choice, not a fallback chain: nothing fails
over, an unset find_slot simply means the default is used. the
default is runtime based, no compile-time assumptions.

## Dispatch contract

when dispatch runs:

- the key already matched, the caller is root (euid == 0)
- regs[0] is the key pointer, regs[1] is the command, regs[2..5]
  are the remaining syscall arguments
- `priv` is the cfg.priv pointer, unchanged
- user pointers in regs must be accessed with copy_from_user /
  copy_to_user as usual

## Built-in command

**SC_CMD_HELLO / SC_MAGIC**

the only built-in command. returns SC_MAGIC (0x53434831) after key
and root checks. commonly used as a channel health check from the
userland side.

## Discovery API (CONFIG_KERNSC_DISCOVER)

**unsigned long sc_table_addr(void)**

address of `sys_call_table`, 0 when not resolved.

**unsigned long sc_entry(unsigned long nr)**

value of table entry nr via the safe read, 0 on failure.

**int sc_find_slot_scan(void)**

the library default discovery: full table scan for the first
ni_syscall entry. exported so consumers can call it directly.

## Patch API (CONFIG_KERNSC_PATCH)

the patch API lets consumers fix or replace any syscall slot,
beyond the channel's own slot. combined with the callbacks this
covers every syscall modification use case.

**int sc_patch(unsigned long nr, unsigned long handler, unsigned long *orig_out)**

replace any syscall slot with handler. reads and returns the
original entry in orig_out. -EINVAL for nr >= 512. -ENODATA when
the table is not resolved. -EFAULT when the original entry cannot
be read. -EEXIST when the slot is already patched. -ENOSPC when
the patch table (16 slots) is full. the channel itself is patched
this way internally.

**void sc_unpatch(unsigned long nr)**

restore the original entry. silent when nr is not patched.

## Behavior

**safe read**

all kernel memory reads (table entries, pgd pointer, orig values)
go through an internal `sc_safe_read` (copy_from_kernel_nofault
wrapper), so a failed read never faults.

**patch write**

makes the table entry writable by flipping the PTE
(`PTE_DBM` set, `PTE_RDONLY` cleared), writing the new value,
restoring the PTE, then TLB flushing and cache cleaning
(`caches_clean_inval_pou`, resolved lazily, skipped when the
symbol is missing). the PTE bits are arm64 hardware bits, stable
across all kernel versions.

**KCFI**

the handler is a plain function compiled by the same clang as the
kernel with the signature `long (*)(const struct pt_regs *)`, so
clang emits the matching typeid and the `invoke_syscall` KCFI
check passes. do not mark the handler `__nocfi` (empty macro on
arm64) and do not use `no_sanitize("kcfi")` (mismatching typeid).

## Build options

```
KDIR=...            kernel build dir, required
KERNSC_MINIMAL=1    minimal build: custom syscall core only
                    (sc_init + handler + default discovery),
                    patch and discovery APIs are compiled out
```
