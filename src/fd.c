#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "fd.h"

static bool should_keep_fd(int fd, const int *keep_fds, size_t count) {
    if (fd <= STDERR_FILENO) {
        return true;
    }
    if (keep_fds != NULL) {
        for (size_t i = 0; i < count; i++) {
            if (fd == keep_fds[i]) {
                return true;
            }
        }
    }
    return false;
}

int fd_close_except(const int *keep_fds, size_t count) {
    /* 1. Attempt to inspect /proc/self/fd */
    DIR *dir = opendir("/proc/self/fd");
    if (dir != NULL) {
        int dfd = dirfd(dir);
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            char *endptr = NULL;
            long val = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || val < 0) {
                continue;
            }
            int fd = (int)val;
            if (fd == dfd) {
                continue;
            }
            if (!should_keep_fd(fd, keep_fds, count)) {
                close(fd);
            }
        }
        closedir(dir);
        return 0;
    }

    /* 2. Fallback if /proc is not available (e.g. before mounting /proc) */
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
        max_fd = 4096;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
        if (!should_keep_fd(fd, keep_fds, count)) {
            close(fd);
        }
    }
    return 0;
}
