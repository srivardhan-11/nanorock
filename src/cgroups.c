#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroups.h"
#include "log.h"

#define CGROUP_ROOT "/sys/fs/cgroup"
#define NANOROCK_GROUP CGROUP_ROOT "/nanorock"

static int write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t len = (ssize_t)strlen(content);
    ssize_t n = write(fd, content, len);
    int saved_errno = errno;
    close(fd);
    if (n != len) {
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }
    return 0;
}

static int read_file(const char *path, char *buf, size_t max_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, max_len - 1);
    int saved_errno = errno;
    close(fd);
    if (n < 0) {
        errno = saved_errno;
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

int cgroup_validate_name(const char *name) {
    if (name == NULL || name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    size_t len = strlen(name);
    if (len > 64) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Do not allow names starting with '-' or '.' */
    if (name[0] == '-' || name[0] == '.') {
        errno = EINVAL;
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) {
            errno = EINVAL;
            return -1;
        }
    }

    return 0;
}

static bool check_controller_available(const char *controllers_buf, const char *ctrl) {
    char needle[32];
    snprintf(needle, sizeof(needle), "%s", ctrl);

    const char *p = controllers_buf;
    size_t nlen = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) {
        bool left_ok = (p == controllers_buf || isspace((unsigned char)*(p - 1)));
        bool right_ok = (p[nlen] == '\0' || isspace((unsigned char)p[nlen]));
        if (left_ok && right_ok) {
            return true;
        }
        p += nlen;
    }
    return false;
}

static int verify_controllers(const nanorock_config_t *cfg) {
    char avail[256];
    if (read_file(CGROUP_ROOT "/cgroup.controllers", avail, sizeof(avail)) != 0) {
        log_error("cannot read " CGROUP_ROOT "/cgroup.controllers: %s (cgroup v2 required)",
                  strerror(errno));
        return -1;
    }

    if (cfg->mem_limit_mb > 0 && !check_controller_available(avail, "memory")) {
        log_error("requested --mem %ld MB, but 'memory' controller is not available in cgroup v2",
                  cfg->mem_limit_mb);
        errno = ENOTSUP;
        return -1;
    }

    if (cfg->cpu_quota_pct > 0 && !check_controller_available(avail, "cpu")) {
        log_error("requested --cpu %d%%, but 'cpu' controller is not available in cgroup v2",
                  cfg->cpu_quota_pct);
        errno = ENOTSUP;
        return -1;
    }

    if (cfg->pids_max > 0 && !check_controller_available(avail, "pids")) {
        log_error("requested --pids-max %d, but 'pids' controller is not available in cgroup v2",
                  cfg->pids_max);
        errno = ENOTSUP;
        return -1;
    }

    return 0;
}

static int enable_subtree_control(const char *control_path, const char *wanted) {
    if (write_file(control_path, wanted) != 0) {
        return -1;
    }
    return 0;
}

int cgroup_create(nanorock_config_t *cfg) {
    if (cfg == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (cgroup_validate_name(cfg->container_name) != 0) {
        log_error("invalid container name '%s' (must be 1-64 alphanumeric, '_', '-', '.')",
                  cfg->container_name);
        return -1;
    }

    /* 1. Verify cgroup v2 presence and controller availability (fail closed) */
    if (verify_controllers(cfg) != 0) {
        return -1;
    }

    /* 2. Ensure parent nanorock group exists */
    if (mkdir(NANOROCK_GROUP, 0755) != 0 && errno != EEXIST) {
        log_error("cannot create parent cgroup " NANOROCK_GROUP ": %s", strerror(errno));
        return -1;
    }

    /* 3. Enable controllers in subtree control */
    char wanted[64] = "";
    if (cfg->mem_limit_mb > 0) strcat(wanted, "+memory ");
    if (cfg->cpu_quota_pct > 0) strcat(wanted, "+cpu ");
    if (cfg->pids_max > 0) strcat(wanted, "+pids ");

    if (wanted[0] != '\0') {
        enable_subtree_control(CGROUP_ROOT "/cgroup.subtree_control", wanted);
        if (enable_subtree_control(NANOROCK_GROUP "/cgroup.subtree_control", wanted) != 0) {
            log_error("failed to enable requested controllers [%s] on " NANOROCK_GROUP "/cgroup.subtree_control: %s",
                      wanted, strerror(errno));
            return -1;
        }
    }

    /* 4. Construct unique instance path: /sys/fs/cgroup/nanorock/<name>-<pid> */
    char group_path[512];
    int n = snprintf(group_path, sizeof(group_path), "%s/%s-%d",
                     NANOROCK_GROUP, cfg->container_name, (int)getpid());
    if (n < 0 || n >= (int)sizeof(group_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* 5. Ownership-safe creation: must NOT pre-exist */
    if (mkdir(group_path, 0755) != 0) {
        if (errno == EEXIST) {
            log_error("cgroup '%s' already exists; refusing to reuse unowned cgroup", group_path);
        } else {
            log_error("failed to create cgroup '%s': %s", group_path, strerror(errno));
        }
        return -1;
    }

    strncpy(cfg->cgroup_path, group_path, sizeof(cfg->cgroup_path) - 1);
    cfg->cgroup_path[sizeof(cfg->cgroup_path) - 1] = '\0';
    cfg->cgroup_owned = true;

    /* 6. Write limits and verify readback */
    char file_path[600];
    char value[64];
    char readback[128];

    if (cfg->mem_limit_mb > 0) {
        snprintf(file_path, sizeof(file_path), "%s/memory.max", group_path);
        long expected_bytes = cfg->mem_limit_mb * 1024L * 1024L;
        snprintf(value, sizeof(value), "%ld", expected_bytes);
        if (write_file(file_path, value) != 0) {
            log_error("failed to write memory.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        if (read_file(file_path, readback, sizeof(readback)) != 0) {
            log_error("failed to read back memory.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        long verified_val = strtol(readback, NULL, 10);
        if (verified_val != expected_bytes) {
            log_error("memory.max verification mismatch: expected %ld, got %ld",
                      expected_bytes, verified_val);
            cgroup_cleanup(cfg);
            errno = EINVAL;
            return -1;
        }
        log_info("memory limit verified: %ld MB (%ld bytes)", cfg->mem_limit_mb, expected_bytes);

        /* Best-effort: disable swap so memory.max is strictly enforced without paging to host disk */
        snprintf(file_path, sizeof(file_path), "%s/memory.swap.max", group_path);
        write_file(file_path, "0");
    }

    if (cfg->cpu_quota_pct > 0) {
        snprintf(file_path, sizeof(file_path), "%s/cpu.max", group_path);
        long expected_quota = (long)cfg->cpu_quota_pct * 1000L;
        long expected_period = 100000L;
        snprintf(value, sizeof(value), "%ld %ld", expected_quota, expected_period);
        if (write_file(file_path, value) != 0) {
            log_error("failed to write cpu.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        if (read_file(file_path, readback, sizeof(readback)) != 0) {
            log_error("failed to read back cpu.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        long read_quota = 0, read_period = 0;
        if (sscanf(readback, "%ld %ld", &read_quota, &read_period) != 2 ||
            read_quota != expected_quota || read_period != expected_period) {
            log_error("cpu.max verification mismatch: expected '%ld %ld', got '%ld %ld'",
                      expected_quota, expected_period, read_quota, read_period);
            cgroup_cleanup(cfg);
            errno = EINVAL;
            return -1;
        }
        log_info("cpu quota verified: %d%% of one core (%ld / %ld us)",
                 cfg->cpu_quota_pct, expected_quota, expected_period);
    }

    if (cfg->pids_max > 0) {
        snprintf(file_path, sizeof(file_path), "%s/pids.max", group_path);
        snprintf(value, sizeof(value), "%d", cfg->pids_max);
        if (write_file(file_path, value) != 0) {
            log_error("failed to write pids.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        if (read_file(file_path, readback, sizeof(readback)) != 0) {
            log_error("failed to read back pids.max: %s", strerror(errno));
            cgroup_cleanup(cfg);
            return -1;
        }
        int verified_pids = atoi(readback);
        if (verified_pids != cfg->pids_max) {
            log_error("pids.max verification mismatch: expected %d, got %d",
                      cfg->pids_max, verified_pids);
            cgroup_cleanup(cfg);
            errno = EINVAL;
            return -1;
        }
        log_info("pids limit verified: %d", cfg->pids_max);
    }

    return 0;
}

int cgroup_add_pid(const nanorock_config_t *cfg, pid_t pid) {
    if (cfg == NULL || cfg->cgroup_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char procs_path[600];
    char value[32];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cfg->cgroup_path);
    snprintf(value, sizeof(value), "%d", pid);

    if (write_file(procs_path, value) != 0) {
        log_error("could not move pid %d into cgroup.procs (%s): %s",
                  pid, procs_path, strerror(errno));
        return -1;
    }

    /* Verification readback: ensure pid is in cgroup.procs */
    char buf[1024];
    if (read_file(procs_path, buf, sizeof(buf)) != 0) {
        log_error("could not read back cgroup.procs: %s", strerror(errno));
        return -1;
    }

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    if (strstr(buf, pid_str) == NULL) {
        log_error("cgroup.procs verification failed: pid %d not found in %s",
                  pid, procs_path);
        errno = ESRCH;
        return -1;
    }

    return 0;
}

static void kill_remaining_processes(const char *group_path) {
    char kill_path[600];
    snprintf(kill_path, sizeof(kill_path), "%s/cgroup.kill", group_path);

    /* 1. Try atomic cgroup.kill (kernel 5.14+) */
    if (write_file(kill_path, "1") == 0) {
        return;
    }

    /* 2. Fallback: manual iteration of cgroup.procs */
    char procs_path[600];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", group_path);

    FILE *f = fopen(procs_path, "r");
    if (f == NULL) {
        return;
    }

    long pid_val;
    while (fscanf(f, "%ld", &pid_val) == 1) {
        if (pid_val > 1) {
            kill((pid_t)pid_val, SIGKILL);
        }
    }
    fclose(f);
}

void cgroup_cleanup(nanorock_config_t *cfg) {
    if (cfg == NULL || !cfg->cgroup_owned || cfg->cgroup_path[0] == '\0') {
        return;
    }

    struct stat st;
    if (stat(cfg->cgroup_path, &st) != 0) {
        cfg->cgroup_owned = false;
        cfg->cgroup_path[0] = '\0';
        return;
    }

    /* Terminate any lingering background processes/descendants */
    kill_remaining_processes(cfg->cgroup_path);

    /* Process drain loop: wait up to 1 second (50 * 20ms) for cgroup.procs to drain */
    char procs_path[600];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cfg->cgroup_path);

    for (int attempt = 0; attempt < 50; attempt++) {
        char buf[64];
        if (read_file(procs_path, buf, sizeof(buf)) == 0) {
            if (buf[0] == '\0' || buf[0] == '\n') {
                if (rmdir(cfg->cgroup_path) == 0) {
                    cfg->cgroup_owned = false;
                    cfg->cgroup_path[0] = '\0';
                    return;
                }
            }
        }
        usleep(20 * 1000);
    }

    if (rmdir(cfg->cgroup_path) == 0 || errno == ENOENT) {
        cfg->cgroup_owned = false;
        cfg->cgroup_path[0] = '\0';
        return;
    }

    log_warn("could not remove cgroup %s (%s)", cfg->cgroup_path, strerror(errno));
}
