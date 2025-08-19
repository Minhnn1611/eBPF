#ifndef FILEMON_COMMON_H
#define FILEMON_COMMON_H

#define FILENAME_LEN 256
#define COMM_LEN 16

typedef enum {
    EVENT_OPEN = 0,
    EVENT_WRITE = 1,
    EVENT_UNLINK = 2,
    EVENT_RENAME = 3,
    EVENT_READ = 4,
} event_type_t;

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[COMM_LEN];
    int fd;
    int count;
    char filename[FILENAME_LEN];
    char old_filename[FILENAME_LEN];
    char new_filename[FILENAME_LEN];
    event_type_t event_type;
};

char *event_type_str[] = {"open", "write", "unlink", "rename", "read"};

#endif // FILEMON_COMMON_H