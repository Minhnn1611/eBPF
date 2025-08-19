// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "filemon.skel.h"
#include "filemon_common.h"
#include <fcntl.h>


static FILE *log_fp = NULL;
static char log_path[] = "./log/file_log.json";

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;

    if (e->event_type == EVENT_WRITE && log_fp) {
        if (strcmp(e->comm, "filemon") == 0) return 0;
    }
    if (strcmp(e->comm, "node") == 0) return 0;
    if (strcmp(e->comm, "ps") == 0) return 0;
    if (strcmp(e->comm, "libuv-worker") == 0) return 0;
    if (strcmp(e->comm, "sshd") == 0) return 0;

    switch (e->event_type) {
        case EVENT_OPEN:
            fprintf(log_fp, "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                            "\"comm\":\"%s\",\"filename\":\"%s\"}\n",
                            e->ts_ns, event_type_str[EVENT_OPEN], e->pid, e->tid, e->uid, e->comm, e->filename);
            break;
        case EVENT_WRITE:
            fprintf(log_fp, "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                            "\"comm\":\"%s\",\"fd\":%d,\"count\":%d}\n",
                            e->ts_ns, event_type_str[EVENT_WRITE], e->pid, e->tid, e->uid, e->comm, e->fd, e->count);
            break;
        case EVENT_UNLINK:
            fprintf(log_fp, "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                            "\"comm\":\"%s\",\"filename\":\"%s\"}\n",
                            e->ts_ns, event_type_str[EVENT_UNLINK], e->pid, e->tid, e->uid, e->comm, e->filename);
            break;
        case EVENT_RENAME:
            fprintf(log_fp, "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                            "\"comm\":\"%s\",\"old_filename\":\"%s\",\"new_filename\":\"%s\"}\n",
                            e->ts_ns, event_type_str[EVENT_RENAME], e->pid, e->tid, e->uid, e->comm,
                            e->old_filename, e->new_filename);
            break;
        case EVENT_READ:
            fprintf(log_fp, "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                            "\"comm\":\"%s\",\"fd\":%d,\"count\":%d}\n",
                            e->ts_ns, event_type_str[EVENT_READ], e->pid, e->tid, e->uid, e->comm, e->fd, e->count);
            break;
        default:
            break;
    }
    fflush(log_fp);
    return 0;
}

int main(int argc, char **argv) {
    struct filemon_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, sig_handler);

    log_fp = fopen(log_path, "a");
    if (log_fp < 0) {
        perror("open log file");
        return 1;
    }

    skel = filemon_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = filemon_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = filemon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if(log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
    ring_buffer__free(rb);
    filemon_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
