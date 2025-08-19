// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filemon_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *fname_ptr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_OPEN; 

    fname_ptr = (const char *)ctx->args[1];
    bpf_core_read_user_str(&e->filename, sizeof(e->filename), fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_WRITE; 

    e->fd = ctx->args[0];
    e->count = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *fname_ptr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_UNLINK;

    fname_ptr = (const char *)ctx->args[1];
    bpf_core_read_user_str(&e->filename, sizeof(e->filename), fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *old_fname_ptr, *new_fname_ptr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_RENAME;

    old_fname_ptr = (const char *)ctx->args[1];
    new_fname_ptr = (const char *)ctx->args[3];

    bpf_core_read_user_str(&e->old_filename, sizeof(e->old_filename), old_fname_ptr);
    bpf_core_read_user_str(&e->new_filename, sizeof(e->new_filename), new_fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *old_fname_ptr, *new_fname_ptr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_RENAME;

    old_fname_ptr = (const char *)ctx->args[1];
    new_fname_ptr = (const char *)ctx->args[3];

    bpf_core_read_user_str(&e->old_filename, sizeof(e->old_filename), old_fname_ptr);
    bpf_core_read_user_str(&e->new_filename, sizeof(e->new_filename), new_fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_READ;

    e->fd = ctx->args[0];
    e->count = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
