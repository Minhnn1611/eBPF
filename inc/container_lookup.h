#ifndef CONTAINER_LOOKUP_H
#define CONTAINER_LOOKUP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct container_cache {
    unsigned long long cgroup_id;
    char id[128];
    char name[128];
    char image[128];
};

const struct container_cache* get_container_info(pid_t pid, unsigned long long cgroup_id);

#endif // CONTAINER_LOOKUP_H
