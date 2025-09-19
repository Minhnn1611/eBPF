// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "filemon.skel.h"
#include "filemon_common.h"
#include <fcntl.h>

#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


static FILE *log_fp = NULL;
static char log_path[] = "./log/file_log.json";

struct container_cache {
    unsigned long long cgroup_id;
    char id[128];
    char name[128];
    char image[128];
};

static struct container_cache cache[256];
static int cache_count = 0;

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo) {
    exiting = 1;
}

const char *lookup_container_id(pid_t pid) {
    static char container_id[128];
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char line[256];
    container_id[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "docker-");
        if (p) {
            char *end = strstr(p, ".scope");
            if (end) {
                size_t len = end - (p + 7); // 7 = strlen("docker-")
                if (len >= sizeof(container_id)) len = sizeof(container_id)-1;
                strncpy(container_id, p+7, len);
                container_id[len] = '\0';
                fclose(f);
                return container_id;
            }
        }
    }

    fclose(f);
    return NULL;
}

// Get container name from container id
const char *lookup_container_name(const char *container_id) {
    static char name[128];
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "bash -c \"/usr/bin/docker inspect -f '{{.Name}}' %s\"", container_id);

    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    if (fgets(name, sizeof(name), fp)) {
        // Delete newline
        name[strcspn(name, "\n")] = 0;
        pclose(fp);
        // Don't return leading '/'
        if (name[0] == '/') return name + 1;
        return name;
    }

    pclose(fp);
    return NULL;
}

// Get container image from container id
const char *lookup_container_image(const char *container_id) {
    static char image[128];
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "bash -c \"/usr/bin/docker inspect -f '{{.Config.Image}}' %s\"", container_id);

    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    if (fgets(image, sizeof(image), fp)) {
        image[strcspn(image, "\n")] = 0;
        pclose(fp);
        return image;
    }

    pclose(fp);
    return NULL;
}

const struct container_cache* get_container_info(pid_t pid, unsigned long long cgroup_id) {
    // Get container info from cache
    for (int i = 0; i < cache_count; i++) {
        if (cache[i].cgroup_id == cgroup_id) {
            return &cache[i];
        }
    }

    // If not in cache, look container id
    const char *container_id = lookup_container_id(pid);
    if (!container_id || container_id[0] == '\0')
        return NULL;

    struct container_cache *c = &cache[cache_count++];
    c->cgroup_id = cgroup_id;
    strncpy(c->id, container_id, sizeof(c->id));

    const char *name  = lookup_container_name(container_id);
    const char *image = lookup_container_image(container_id);

    if (name)  strncpy(c->name, name, sizeof(c->name));
    if (image) strncpy(c->image, image, sizeof(c->image));

    return c;
}

static void print_container_info(FILE *fp, const char *container_id,
                                 const char *name, const char *image)
{
    if (container_id)
        fprintf(fp, "\"container_id\":\"%s\",", container_id);
    if (name)
        fprintf(fp, "\"container_name\":\"%s\",", name);
    if (image)
        fprintf(fp, "\"container_image\":\"%s\",", image);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;

    if (strcmp(e->comm, "filemon") == 0) return 0;
    if (strcmp(e->comm, "node") == 0) return 0;
    if (strcmp(e->comm, "ps") == 0) return 0;
    if (strcmp(e->comm, "libuv-worker") == 0) return 0;
    if (strcmp(e->comm, "sshd") == 0) return 0;
    if (strcmp(e->comm, "systemd-udevd") == 0) return 0;

    const char *name = NULL;
    const char *image = NULL;
    const char *container_id = NULL;

    const struct container_cache *ci = get_container_info(e->pid, e->cgroup_id);
    if (ci) {
        container_id = ci->id;
        name = ci->name;
        image = ci->image;
    }

    switch (e->event_type) {
    case EVENT_OPEN:
        fprintf(log_fp,
                "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                "\"cgroup_id\":%llu,",
                e->ts_ns, event_type_str[EVENT_OPEN],
                e->pid, e->tid, e->uid, e->cgroup_id);
        print_container_info(log_fp, container_id, name, image);
        fprintf(log_fp,
                "\"comm\":\"%s\",\"filename\":\"%s\"}\n",
                e->comm, e->filename);
        break;

    case EVENT_WRITE:
        fprintf(log_fp,
                "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                "\"cgroup_id\":%llu,",
                e->ts_ns, event_type_str[EVENT_WRITE],
                e->pid, e->tid, e->uid, e->cgroup_id);
        print_container_info(log_fp, container_id, name, image);
        fprintf(log_fp,
                "\"comm\":\"%s\",\"fd\":%d,\"count\":%d}\n",
                e->comm, e->fd, e->count);
        break;

    case EVENT_UNLINK:
        fprintf(log_fp,
                "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                "\"cgroup_id\":%llu,",
                e->ts_ns, event_type_str[EVENT_UNLINK],
                e->pid, e->tid, e->uid, e->cgroup_id);
        print_container_info(log_fp, container_id, name, image);
        fprintf(log_fp,
                "\"comm\":\"%s\",\"filename\":\"%s\"}\n",
                e->comm, e->filename);
        break;

    case EVENT_RENAME:
        fprintf(log_fp,
                "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                "\"cgroup_id\":%llu,",
                e->ts_ns, event_type_str[EVENT_RENAME],
                e->pid, e->tid, e->uid, e->cgroup_id);
        print_container_info(log_fp, container_id, name, image);
        fprintf(log_fp,
                "\"comm\":\"%s\",\"old_filename\":\"%s\",\"new_filename\":\"%s\"}\n",
                e->comm, e->old_filename, e->new_filename);
        break;

    case EVENT_READ:
        fprintf(log_fp,
                "{\"ts_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
                "\"cgroup_id\":%llu,",
                e->ts_ns, event_type_str[EVENT_READ],
                e->pid, e->tid, e->uid, e->cgroup_id);
        print_container_info(log_fp, container_id, name, image);
        fprintf(log_fp,
                "\"comm\":\"%s\",\"fd\":%d,\"count\":%d}\n",
                e->comm, e->fd, e->count);
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
