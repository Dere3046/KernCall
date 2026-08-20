# Kerncall API

kernel syscall channel library. hijacks a free `ni_syscall` slot in
`sys_call_table` and routes userland `syscall(nr, key, cmd, ...)`
calls to a dispatch callback. can also patch arbitrary existing
syscall slots. optionally hosts a `sys_enter` tracepoint dispatcher
for runtime syscall hooks that never touch the table.

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
  `__arm64_sys_ni_syscall` (+ `.cfi_jt`), `init_mm`, and lazily
  for the patch write machinery (`kimage_voffset`, `__set_fixmap`,
  `caches_clean_inval_pou` with `dcache_clean_inval_poc` /
  `flush_dcache_range` fallbacks) and the tracepoint dispatcher
  (`__tracepoint_sys_enter`, `tracepoint_srcu`,
  `synchronize_srcu`). the wrapper must be a `__nocfi` function
  around `kallrecon_klp`, passing the raw pointer makes the module's
  indirect call check fail with a CFI panic on old-CFI kernels
- `pgd_off`: byte offset of `mm_struct.pgd`. reserved, the current
  fixmap based patch write does not use it. kept in the layout
  struct so consumers can carry it for their own page table work
- `find_slot`: optional empty-slot discovery method supplied by the
  layout library. see Slot discovery

## Lifecycle

**int sc_init(const struct sc_cfg *cfg)**

the one call that starts everything. resolves symbols, discovers a
slot, patches in the handler. 0 on success.
-EINVAL when cfg, key or layout resolver is bad.
-EALREADY when the channel is already initialized, call sc_exit
first.
-ENODATA when a required symbol cannot be resolved.
-EBUSY when no slot is found. -EIO when the patch fails.
not reentrant: a second sc_init while the channel is active fails
with -EALREADY.

with `cfg->no_patch` set, sc_init only resolves the layout
(symbols + pgd ready) and returns without discovering or patching
a channel slot. consumers use this to build their own handler on
top of the patch API, keeping the built-in channel (and its auth
error codes) out of the syscall table. `tp_enable` still works
under no_patch, giving a channel-free tracepoint dispatcher.

**void sc_exit(void)**

restores every patched slot, unregisters the tracepoint dispatcher
if enabled, and unmarks processes. safe to call multiple times.

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
	bool no_patch;
	/* tracepoint dispatcher (CONFIG_KERNSC_TP) */
	bool tp_enable;
	bool tp_mark_all;
	void (*tp_mark_cb)(struct task_struct *p, bool on);
	void (*tp_on_enter)(int id, struct pt_regs *regs);
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

## Tracepoint dispatcher (CONFIG_KERNSC_TP)

a `sys_enter` tracepoint based dispatcher. one shared `ni_syscall`
slot is patched with a dispatcher handler; the tracepoint redirects
only hooked syscalls to it, and an in-module table routes them to
per-syscall hooks. hooks register and unregister at runtime without
writing the read-only syscall table. the advantage over `sc_patch`
is one table write for any number of hooks, at the cost of marking
processes and passing every marked syscall through the tracepoint.

**lifecycle**

set `tp_enable` in cfg and pass it to sc_init. the dispatcher finds
its own free slot (excluding the channel slot and patched entries),
patches it, registers the tracepoint and marks processes. all of it
is torn down by sc_exit. works together with the channel and with
no_patch mode.

**process marking**

marked processes get `TIF_SYSCALL_TRACEPOINT` and their syscalls
fire the tracepoint. `tp_mark_all` true (default) marks every
process, false marks only the current task. `tp_mark_cb` replaces
the built-in flag toggling with a consumer callback
`void (*)(struct task_struct *p, bool on)`, for selective marking.

**tp_on_enter**

optional observer `void (*)(int id, struct pt_regs *regs)`. called
for every syscall of a marked process, before the redirect check.
use it to watch or adjust registers of unhooked syscalls.

**int sc_tp_register(int nr, sc_tp_hook_fn fn)**

route syscall nr to fn. -EINVAL for bad nr or NULL fn. -EEXIST when
nr is already hooked. no table write happens.

**void sc_tp_unregister(int nr)**

stop routing nr. silent for unhooked nr.

**bool sc_tp_hooked(int nr)**

true when nr has a registered hook.

**long sc_tp_orig(int nr, const struct pt_regs *regs)**

call the current table entry for nr. the standard way for a hook to
chain to the original syscall. the internal call is `__nocfi`, the
table entry typeid matches the syscall_fn_t signature. hook
signature:

```c
typedef long (*sc_tp_hook_fn)(int nr, const struct pt_regs *regs);
```

the typedef carries the KCFI typeid, so the dispatcher's indirect
call is check-compatible.

**int sc_tp_slot(void)**

the dispatcher slot number. -1 when disabled.

**slot discovery**

the dispatcher scans `sys_call_table` for a ni entry, skipping the
channel slot and every patched slot. consumer find_slot callbacks
are not consulted, they already own the channel slot selection.

**slot conflicts**

registering a hook on the dispatcher slot itself is allowed but
never fires: the sys_enter handler skips the redirect for the
dispatcher slot, so direct calls keep the ni behavior. registering
on the channel slot routes calls through the hook, then sc_tp_orig,
then sc_handler, so the channel stays reachable as long as the hook
passes through.

**teardown**

sc_exit unregisters the tracepoint, then resolves `tracepoint_srcu`
and calls `synchronize_srcu` to wait out in-flight probes before
freeing module memory. on kernels where those symbols are trimmed
by CONFIG_TRIM_UNUSED_KSYMS it falls back to `synchronize_rcu`.

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

## Socket protocol family (sc_sock)

a custom socket protocol family for kernel to userland event
streaming. no `/dev` node, no filesystem dependency. the family is
registered as a library component, consumers link `sc_sock.o` and
call the API directly.

**int sc_sock_init(const struct sc_sock_consumer_ops *ops)**

register the protocol and scan a free family number starting from
`AF_DECnet`. ops is optional, NULL is allowed. 0 on success,
-EADDRINUSE when no free family is found.

**void sc_sock_exit(void)**

unregister the protocol and family. module refcount is held per open
socket, so unload is blocked while sockets are alive.

**int sc_sock_family(void)**

the registered family number, -1 before init or after exit.

**int sc_sock_send_event(const void *data, size_t len)**

broadcast one event to every open sc_sock socket. -ENODEV when the
family is not registered, -EINVAL for NULL data or bad length,
-ENOMEM when skb allocation fails. `SC_SOCK_EVENT_MAX` bounds the
event size.

**int sc_sock_send_event_to(const void *data, size_t len, struct socket *sock)**

send one event to a single socket.

**void *sc_sock_priv(struct socket *sock)**

per-socket consumer private data, NULL when unset.

**int sc_sock_set_priv(struct socket *sock, void *priv)**

set per-socket consumer private data.

```c
struct sc_sock_consumer_ops {
	int (*ioctl)(struct socket *sock, unsigned int cmd,
		     unsigned long arg);
	int (*sendmsg)(struct socket *sock, struct msghdr *msg, size_t len);
	int (*mmap)(struct file *file, struct socket *sock,
		    struct vm_area_struct *vma);
	int (*setsockopt)(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen);
	int (*getsockopt)(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen);
};
```

the consumer ops are optional extension points. when NULL, ioctl,
sendmsg, mmap, setsockopt and unknown getsockopt return the default
-EOPNOTSUPP / -ENOTTY / -ENOPROTOOPT.

userspace protocol:

```c
#define SC_SOCK_PROTO 0x53
#define SC_SOCK_LEVEL 0x5343
#define SC_SOCK_OPT_HELLO 0x1000
#define SC_SOCK_OPT_FAMILY 0x1001

int fd = socket(AF_DECnet, SOCK_RAW, SC_SOCK_PROTO);
int val;
socklen_t len = sizeof(val);

getsockopt(fd, SC_SOCK_LEVEL, SC_SOCK_OPT_HELLO, &val, &len);
getsockopt(fd, SC_SOCK_LEVEL, SC_SOCK_OPT_FAMILY, &val, &len);
recv(fd, buf, sizeof(buf), 0);
```

socket creation requires `CAP_NET_BIND_SERVICE`. events are queued
per socket and read with recv. recv blocks when no event is queued
unless MSG_DONTWAIT is set.

## Build options

```
KDIR=...            kernel build dir, required
KERNSC_MINIMAL=1    minimal build: custom syscall core only
                    (sc_init + handler + default discovery),
                    patch, discovery, tracepoint dispatcher and
                    sc_sock are compiled out
```
