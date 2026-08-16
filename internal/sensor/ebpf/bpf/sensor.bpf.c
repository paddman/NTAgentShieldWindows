// SPDX-License-Identifier: GPL-2.0-only
// CO-RE tracepoint sensor. This program has no control or response path.
#include <linux/bpf.h>
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define PATH_LEN 192
#define COMM_LEN 16

#define EVENT_EXEC 1
#define EVENT_EXIT 2
#define EVENT_TCP_CONNECT 3
#define EVENT_TCP_ACCEPT 4
#define EVENT_FILE_OPEN 5
#define EVENT_FILE_WRITE 6
#define EVENT_FILE_RENAME 7
#define EVENT_FILE_UNLINK 8
#define EVENT_FILE_CHMOD 9
#define EVENT_FILE_CHOWN 10
#define EVENT_PTRACE 11
#define EVENT_SETUID 12
#define EVENT_SETGID 13
#define EVENT_MODULE_LOAD 14
#define EVENT_SETNS 15

#define TCP_ESTABLISHED 1
#define TCP_SYN_RECV 3
#define TCP_NEW_SYN_RECV 12

// The reduced declaration intentionally relies on CO-RE field relocations.
// It is not a host-kernel layout assumption.
struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u64 start_boottime_ns;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u16 type;
	__u16 family;
	__u16 protocol;
	__u16 old_state;
	__u16 new_state;
	__u16 sport;
	__u16 dport;
	__s32 result;
	__u32 arg0;
	__u32 arg1;
	char comm[COMM_LEN];
	char path[PATH_LEN];
	char path2[PATH_LEN];
	__u8 source_address[16];
	__u8 destination_address[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} losses SEC(".maps");

struct trace_exec {
	__u64 ignored;
	__u32 filename;
	__s32 pid;
	__s32 old_pid;
};

struct trace_exit {
	__u64 ignored;
	char comm[COMM_LEN];
	__s32 pid;
	__s32 prio;
};

struct trace_inet_state {
	__u64 ignored;
	const void *skaddr;
	__s32 oldstate;
	__s32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct trace_openat {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 dfd;
	const char *filename;
	__u64 flags;
	__u64 mode;
};

struct trace_open {
	__u64 ignored;
	__s64 syscall_nr;
	const char *filename;
	__u64 flags;
	__u64 mode;
};

struct trace_write {
	__u64 ignored;
	__s64 syscall_nr;
	__u64 fd;
	const void *buf;
	__u64 count;
};

struct trace_renameat2 {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 olddfd;
	const char *oldname;
	__s64 newdfd;
	const char *newname;
	__u64 flags;
};

struct trace_unlinkat {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 dfd;
	const char *pathname;
	__u64 flags;
};

struct trace_chmod {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 dfd;
	const char *filename;
	__u64 mode;
};

struct trace_chmod_direct {
	__u64 ignored;
	__s64 syscall_nr;
	const char *filename;
	__u64 mode;
};

struct trace_chown {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 dfd;
	const char *filename;
	__u64 user;
	__u64 group;
	__u64 flags;
};

struct trace_chown_direct {
	__u64 ignored;
	__s64 syscall_nr;
	const char *filename;
	__u64 user;
	__u64 group;
};

struct trace_ptrace {
	__u64 ignored;
	__s64 syscall_nr;
	__u64 request;
	__u64 pid;
	__u64 addr;
	__u64 data;
};

struct trace_setid {
	__u64 ignored;
	__s64 syscall_nr;
	__u64 id;
};

struct trace_module_load {
	__u64 ignored;
	__u32 taints;
	__u32 name;
};

struct trace_setns {
	__u64 ignored;
	__s64 syscall_nr;
	__s64 fd;
	__u64 flags;
};

static __always_inline struct event *new_event(__u16 type)
{
	struct event *event;
	struct task_struct *task;
	struct task_struct *parent;
	__u64 id;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__u32 key = 0;
		__u64 *loss = bpf_map_lookup_elem(&losses, &key);
		if (loss)
			__sync_fetch_and_add(loss, 1);
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = bpf_get_current_cgroup_id();
	id = bpf_get_current_pid_tgid();
	event->pid = id;
	event->tgid = id >> 32;
	id = bpf_get_current_uid_gid();
	event->uid = id;
	event->gid = id >> 32;
	event->type = type;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	task = bpf_get_current_task_btf();
	if (task) {
		event->start_boottime_ns = BPF_CORE_READ(task, start_boottime);
		parent = BPF_CORE_READ(task, real_parent);
		if (parent)
			event->ppid = BPF_CORE_READ(parent, tgid);
	}
	return event;
}

static __always_inline void submit_event(struct event *event)
{
	if (event)
		bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_exec *ctx)
{
	struct event *event = new_event(EVENT_EXEC);
	__u32 offset;

	if (!event)
		return 0;
	offset = ctx->filename & 0xffff;
	if (offset)
		bpf_probe_read_kernel_str(event->path, sizeof(event->path), (const void *)ctx + offset);
	submit_event(event);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(struct trace_exit *ctx)
{
	struct event *event = new_event(EVENT_EXIT);

	if (!event)
		return 0;
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), ctx->comm);
	submit_event(event);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int on_inet_state(struct trace_inet_state *ctx)
{
	struct event *event;
	__u16 type;

	if (ctx->protocol != 6 || ctx->newstate != TCP_ESTABLISHED)
		return 0;
	type = (ctx->oldstate == TCP_SYN_RECV || ctx->oldstate == TCP_NEW_SYN_RECV) ? EVENT_TCP_ACCEPT : EVENT_TCP_CONNECT;
	event = new_event(type);
	if (!event)
		return 0;
	event->family = ctx->family;
	event->protocol = ctx->protocol;
	event->old_state = ctx->oldstate;
	event->new_state = ctx->newstate;
	event->sport = ctx->sport;
	event->dport = ctx->dport;
	if (ctx->family == 2) {
		__builtin_memcpy(event->source_address, ctx->saddr, 4);
		__builtin_memcpy(event->destination_address, ctx->daddr, 4);
	} else if (ctx->family == 10) {
		__builtin_memcpy(event->source_address, ctx->saddr_v6, 16);
		__builtin_memcpy(event->destination_address, ctx->daddr_v6, 16);
	}
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_openat *ctx)
{
	struct event *event = new_event(EVENT_FILE_OPEN);

	if (!event)
		return 0;
	event->arg0 = ctx->flags;
	event->arg1 = ctx->mode;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int on_open(struct trace_open *ctx)
{
	struct event *event = new_event(EVENT_FILE_OPEN);

	if (!event)
		return 0;
	event->arg0 = ctx->flags;
	event->arg1 = ctx->mode;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int on_write(struct trace_write *ctx)
{
	struct event *event = new_event(EVENT_FILE_WRITE);

	if (!event)
		return 0;
	event->arg0 = ctx->fd;
	event->arg1 = ctx->count > 0xffffffff ? 0xffffffff : ctx->count;
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int on_renameat2(struct trace_renameat2 *ctx)
{
	struct event *event = new_event(EVENT_FILE_RENAME);

	if (!event)
		return 0;
	event->arg0 = ctx->flags;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->oldname);
	bpf_probe_read_user_str(event->path2, sizeof(event->path2), ctx->newname);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_unlinkat *ctx)
{
	struct event *event = new_event(EVENT_FILE_UNLINK);

	if (!event)
		return 0;
	event->arg0 = ctx->flags;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->pathname);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int on_chmod(struct trace_chmod *ctx)
{
	struct event *event = new_event(EVENT_FILE_CHMOD);

	if (!event)
		return 0;
	event->arg0 = ctx->mode;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int on_chmod_direct(struct trace_chmod_direct *ctx)
{
	struct event *event = new_event(EVENT_FILE_CHMOD);

	if (!event)
		return 0;
	event->arg0 = ctx->mode;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int on_chown(struct trace_chown *ctx)
{
	struct event *event = new_event(EVENT_FILE_CHOWN);

	if (!event)
		return 0;
	event->arg0 = ctx->user;
	event->arg1 = ctx->group;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int on_chown_direct(struct trace_chown_direct *ctx)
{
	struct event *event = new_event(EVENT_FILE_CHOWN);

	if (!event)
		return 0;
	event->arg0 = ctx->user;
	event->arg1 = ctx->group;
	bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_ptrace *ctx)
{
	struct event *event = new_event(EVENT_PTRACE);

	if (!event)
		return 0;
	event->arg0 = ctx->request;
	event->arg1 = ctx->pid;
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int on_setuid(struct trace_setid *ctx)
{
	struct event *event = new_event(EVENT_SETUID);

	if (!event)
		return 0;
	event->arg0 = ctx->id;
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int on_setgid(struct trace_setid *ctx)
{
	struct event *event = new_event(EVENT_SETGID);

	if (!event)
		return 0;
	event->arg0 = ctx->id;
	submit_event(event);
	return 0;
}

SEC("tracepoint/module/module_load")
int on_module_load(struct trace_module_load *ctx)
{
	struct event *event = new_event(EVENT_MODULE_LOAD);
	__u32 offset;

	if (!event)
		return 0;
	event->arg0 = ctx->taints;
	offset = ctx->name & 0xffff;
	if (offset)
		bpf_probe_read_kernel_str(event->path, sizeof(event->path), (const void *)ctx + offset);
	submit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int on_setns(struct trace_setns *ctx)
{
	struct event *event = new_event(EVENT_SETNS);

	if (!event)
		return 0;
	event->arg0 = ctx->fd;
	event->arg1 = ctx->flags;
	submit_event(event);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
