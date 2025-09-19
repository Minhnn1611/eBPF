// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filemon_common.h"

#define EPERM 1
#define MAY_EXEC   1   /* execute permission */
#define MAY_WRITE  2   /* write permission */
#define MAY_READ   4   /* read permission */
#define MAY_APPEND 8   /* append-only file */

static __always_inline bool str_eq(const char *s1, const char *s2)
{
    int i = 0;
    for (; s1[i] && s2[i]; i++) {
        if (s1[i] != s2[i])
            return false;
    }
    return s1[i] == s2[i];
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");


// SEC("lsm/file_open")
// int BPF_PROG(handle_file_open, struct file *file, int mask)
// {
//     struct event *e;
//     struct dentry *dentry;
//     struct qstr d_name;
//     char fname[256];

//     dentry = BPF_CORE_READ(file, f_path.dentry);
//     d_name = BPF_CORE_READ(dentry, d_name);
//     bpf_core_read_str(fname, sizeof(fname), d_name.name);

//     // Block open to "test_eBPF.txt"
//     // if (str_eq(fname, "test_eBPF.txt")) {
//     //     return -EPERM; 
//     // }

//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if (e) {
//         e->ts_ns = bpf_ktime_get_ns();
//         e->pid = bpf_get_current_pid_tgid() >> 32;
//         e->tid = (__u32)bpf_get_current_pid_tgid();
//         e->uid = bpf_get_current_uid_gid();
//         bpf_get_current_comm(&e->comm, sizeof(e->comm));
//         e->event_type = EVENT_OPEN;
//         bpf_core_read_str(&e->filename, sizeof(e->filename), d_name.name);
//         bpf_ringbuf_submit(e, 0);
//     }

//     return 0; // Allow file open
// }

// SEC("lsm/inode_unlink")
// int BPF_PROG(handle_unlink, struct inode *dir, struct dentry *dentry)
// {
//     char fname[64];
//     struct qstr d_name;
//     struct event *e;

//     d_name = BPF_CORE_READ(dentry, d_name);
//     bpf_core_read_str(fname, sizeof(fname), d_name.name);

//     if (str_eq(fname, "test_eBPF.txt")) {
//         return -EPERM;  
//     }

//     // Log ringbuffer
//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if (e) {
//         e->ts_ns = bpf_ktime_get_ns();
//         e->pid   = bpf_get_current_pid_tgid() >> 32;
//         e->tid   = (__u32)bpf_get_current_pid_tgid();
//         e->uid   = bpf_get_current_uid_gid();
//         bpf_get_current_comm(&e->comm, sizeof(e->comm));
//         e->event_type = EVENT_UNLINK;   
//         bpf_core_read_str(&e->filename, sizeof(e->filename), d_name.name);
//         bpf_ringbuf_submit(e, 0);
//     }

//     return 0;
// }

// SEC("lsm/file_permission")
// int BPF_PROG(handle_file_permission, struct file *file, int mask)
// {
//     char fname[64];
//     struct dentry *dentry;
//     struct qstr d_name;
//     struct event *e;

//     dentry = BPF_CORE_READ(file, f_path.dentry);
//     d_name = BPF_CORE_READ(dentry, d_name);
//     bpf_core_read_str(fname, sizeof(fname), d_name.name);

//     // Block read/write to "test_eBPF.txt"
//     if (str_eq(fname, "test_eBPF.txt")) {
//         if (mask & MAY_WRITE)
//             return -EPERM;  // block write
//         if (mask & MAY_READ)
//             return -EPERM;  // block read
//     }

//     // Log ringbuffer
//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if (e) {
//         e->ts_ns = bpf_ktime_get_ns();
//         e->pid   = bpf_get_current_pid_tgid() >> 32;
//         e->tid   = (__u32)bpf_get_current_pid_tgid();
//         e->uid   = bpf_get_current_uid_gid();
//         bpf_get_current_comm(&e->comm, sizeof(e->comm));
//         e->event_type = (mask & MAY_WRITE) ? EVENT_WRITE :
//                         (mask & MAY_READ)  ? EVENT_READ  : 0;
//         bpf_core_read_str(&e->filename, sizeof(e->filename), d_name.name);
//         bpf_ringbuf_submit(e, 0);
//     }

//     return 0; 
// }


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
    e->cgroup_id = bpf_get_current_cgroup_id();
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
    e->cgroup_id = bpf_get_current_cgroup_id();
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
    e->cgroup_id = bpf_get_current_cgroup_id();
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
    e->cgroup_id = bpf_get_current_cgroup_id();
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
    e->cgroup_id = bpf_get_current_cgroup_id();
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
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_READ;

    e->fd = ctx->args[0];
    e->count = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
