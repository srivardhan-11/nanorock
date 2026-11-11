#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    printf("=== Running In-Container FD Hygiene Probe ===\n");
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        fprintf(stderr, "FAIL: cannot open /proc/self/fd: %s\n", strerror(errno));
        return 1;
    }

    int dfd = dirfd(dir);
    struct dirent *entry;
    int leaked = 0;
    int total_open = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char *endptr = NULL;
        long fd = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || fd < 0) {
            continue;
        }

        /* Ignore the directory descriptor used to read /proc/self/fd */
        if ((int)fd == dfd) {
            continue;
        }

        total_open++;

        char linkpath[64];
        char target[256];
        snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%ld", fd);
        ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
        if (len >= 0) {
            target[len] = '\0';
        } else {
            snprintf(target, sizeof(target), "(unknown error: %s)", strerror(errno));
        }

        printf("  [fd %ld] -> %s\n", fd, target);

        /* Descriptors 0, 1, 2 are standard stdio */
        if (fd <= 2) {
            continue;
        }

        /* Check for leaked nanorock-internal descriptors */
        if (strstr(target, "pipe:") != NULL ||
            strstr(target, "socket:[") != NULL ||
            strstr(target, "/sys/fs/cgroup") != NULL ||
            strstr(target, "/proc/") != NULL ||
            strstr(target, ".oldroot") != NULL) {
            fprintf(stderr, "  FAIL: nanorock internal descriptor leaked: fd %ld -> %s\n", fd, target);
            leaked++;
        }
    }

    closedir(dir);

    if (leaked > 0) {
        fprintf(stderr, "FAIL: %d nanorock internal descriptor(s) leaked into workload\n", leaked);
        return 1;
    }

    printf("PASS: FD hygiene verified - no nanorock internal descriptors leaked (total open: %d)\n", total_open);
    return 0;
}
