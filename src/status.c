#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "cgroups.h"
#include "config.h"
#include "log.h"
#include "status.h"

#define NANOROCK_CGROUP_ROOT "/sys/fs/cgroup/nanorock"

static bool is_process_alive(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    if (kill(pid, 0) == 0) {
        return true;
    }
    return (errno == EPERM);
}

static int read_line_trimmed(const char *path, char *buf, size_t max) {
    if (!path || !buf || max == 0) {
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    if (!fgets(buf, (int)max, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    return 0;
}

static void parse_ip_from_fib_trie(pid_t pid, char *out_ip, size_t max_len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/net/fib_trie", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(out_ip, "unknown", max_len - 1);
        out_ip[max_len - 1] = '\0';
        return;
    }

    char line[256];
    char candidate[64] = {0};
    out_ip[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "|-- ");
        if (p) {
            p += 4;
            if (sscanf(p, "%63s", candidate) != 1) {
                candidate[0] = '\0';
            }
            continue;
        }
        if (strstr(line, "/32 host LOCAL") != NULL && candidate[0] != '\0') {
            /* Skip loopback addresses */
            if (strncmp(candidate, "127.", 4) != 0) {
                strncpy(out_ip, candidate, max_len - 1);
                out_ip[max_len - 1] = '\0';
                break;
            }
        }
    }
    fclose(f);
    if (out_ip[0] == '\0') {
        strncpy(out_ip, "unknown", max_len - 1);
        out_ip[max_len - 1] = '\0';
    }
}

static int container_info_load(const char *cgroup_entry, nanorock_container_info_t *info) {
    memset(info, 0, sizeof(*info));

    /* Parse container name and host supervisor PID from directory name: <name>-<pid> */
    const char *dash = strrchr(cgroup_entry, '-');
    if (!dash || dash == cgroup_entry) {
        return -1;
    }
    size_t name_len = (size_t)(dash - cgroup_entry);
    if (name_len >= sizeof(info->name)) {
        return -1;
    }
    strncpy(info->name, cgroup_entry, name_len);
    info->name[name_len] = '\0';

    char *endptr = NULL;
    errno = 0;
    long hpid = strtol(dash + 1, &endptr, 10);
    if (*endptr != '\0' || hpid <= 0 || errno != 0) {
        return -1;
    }
    info->host_pid = (pid_t)hpid;

    snprintf(info->cgroup_path, sizeof(info->cgroup_path), "%s/%s",
             NANOROCK_CGROUP_ROOT, cgroup_entry);

    /* Read container PID from cgroup.procs */
    char procs_path[600];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", info->cgroup_path);
    FILE *fp = fopen(procs_path, "r");
    if (!fp) {
        return -1;
    }
    long cpid = 0;
    if (fscanf(fp, "%ld", &cpid) == 1 && cpid > 0) {
        info->container_pid = (pid_t)cpid;
    }
    fclose(fp);

    /* Check liveness */
    if (info->container_pid > 0 && is_process_alive(info->container_pid)) {
        strncpy(info->state, "running", sizeof(info->state) - 1);
    } else if (info->host_pid > 0 && is_process_alive(info->host_pid)) {
        strncpy(info->state, "initializing", sizeof(info->state) - 1);
    } else {
        /* Container has exited or cgroup is unpopulated/stale */
        strncpy(info->state, "stopped", sizeof(info->state) - 1);
        return -1;
    }

    /* Query Hostname via UTS namespace */
    strncpy(info->hostname, "unknown", sizeof(info->hostname) - 1);
    if (info->container_pid > 0) {
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/uts", info->container_pid);
        int target_uts = open(ns_path, O_RDONLY | O_CLOEXEC);
        int cur_uts = open("/proc/self/ns/uts", O_RDONLY | O_CLOEXEC);
        if (target_uts >= 0 && cur_uts >= 0) {
            if (setns(target_uts, CLONE_NEWUTS) == 0) {
                struct utsname u;
                if (uname(&u) == 0) {
                    strncpy(info->hostname, u.nodename, sizeof(info->hostname) - 1);
                }
                (void)setns(cur_uts, CLONE_NEWUTS);
            }
            close(target_uts);
            close(cur_uts);
        } else {
            if (target_uts >= 0) close(target_uts);
            if (cur_uts >= 0) close(cur_uts);
        }
    }

    /* Query Networking Mode and Container IP */
    strncpy(info->net_mode, "none", sizeof(info->net_mode) - 1);
    strncpy(info->container_ip, "none", sizeof(info->container_ip) - 1);
    if (info->container_pid > 0) {
        char net_dev_path[64];
        snprintf(net_dev_path, sizeof(net_dev_path), "/proc/%d/net/dev", info->container_pid);
        FILE *ndf = fopen(net_dev_path, "r");
        if (ndf) {
            char dev_line[256];
            bool has_eth0 = false;
            while (fgets(dev_line, sizeof(dev_line), ndf)) {
                if (strstr(dev_line, "eth0:") != NULL) {
                    has_eth0 = true;
                    break;
                }
            }
            fclose(ndf);
            if (has_eth0) {
                strncpy(info->net_mode, "veth", sizeof(info->net_mode) - 1);
                parse_ip_from_fib_trie(info->container_pid, info->container_ip, sizeof(info->container_ip));
            } else {
                strncpy(info->net_mode, "none", sizeof(info->net_mode) - 1);
                strncpy(info->container_ip, "none", sizeof(info->container_ip) - 1);
            }
        }
    }

    /* Resource Observability via cgroup v2 */
    char res_path[600];
    char res_buf[128];

    /* memory.current */
    snprintf(res_path, sizeof(res_path), "%s/memory.current", info->cgroup_path);
    if (read_line_trimmed(res_path, res_buf, sizeof(res_buf)) == 0) {
        info->mem_current = atoll(res_buf);
    } else {
        info->mem_current = 0;
    }

    /* memory.max */
    snprintf(res_path, sizeof(res_path), "%s/memory.max", info->cgroup_path);
    if (read_line_trimmed(res_path, info->mem_max, sizeof(info->mem_max)) != 0) {
        strncpy(info->mem_max, "max", sizeof(info->mem_max) - 1);
    }

    /* memory.swap.max */
    snprintf(res_path, sizeof(res_path), "%s/memory.swap.max", info->cgroup_path);
    if (read_line_trimmed(res_path, info->mem_swap_max, sizeof(info->mem_swap_max)) != 0) {
        strncpy(info->mem_swap_max, "max", sizeof(info->mem_swap_max) - 1);
    }

    /* pids.current */
    snprintf(res_path, sizeof(res_path), "%s/pids.current", info->cgroup_path);
    if (read_line_trimmed(res_path, res_buf, sizeof(res_buf)) == 0) {
        info->pids_current = atoll(res_buf);
    } else {
        info->pids_current = 0;
    }

    /* pids.max */
    snprintf(res_path, sizeof(res_path), "%s/pids.max", info->cgroup_path);
    if (read_line_trimmed(res_path, info->pids_max, sizeof(info->pids_max)) != 0) {
        strncpy(info->pids_max, "max", sizeof(info->pids_max) - 1);
    }

    /* cpu.max */
    snprintf(res_path, sizeof(res_path), "%s/cpu.max", info->cgroup_path);
    if (read_line_trimmed(res_path, info->cpu_max, sizeof(info->cpu_max)) != 0) {
        strncpy(info->cpu_max, "max 100000", sizeof(info->cpu_max) - 1);
    }

    /* cpu.stat -> usage_usec */
    info->cpu_usage_usec = 0;
    snprintf(res_path, sizeof(res_path), "%s/cpu.stat", info->cgroup_path);
    FILE *csf = fopen(res_path, "r");
    if (csf) {
        char cs_line[128];
        while (fgets(cs_line, sizeof(cs_line), csf)) {
            if (strncmp(cs_line, "usage_usec ", 11) == 0) {
                info->cpu_usage_usec = atoll(cs_line + 11);
                break;
            }
        }
        fclose(csf);
    }

    return 0;
}

static void format_mem_human(const char *val_str, char *out, size_t max) {
    if (strcmp(val_str, "max") == 0) {
        strncpy(out, "max", max - 1);
        out[max - 1] = '\0';
        return;
    }
    long long bytes = atoll(val_str);
    if (bytes >= 1024 * 1024 * 1024) {
        snprintf(out, max, "%.1fGB", (double)bytes / (1024 * 1024 * 1024));
    } else if (bytes >= 1024 * 1024) {
        snprintf(out, max, "%.1fMB", (double)bytes / (1024 * 1024));
    } else if (bytes >= 1024) {
        snprintf(out, max, "%.1fKB", (double)bytes / 1024);
    } else {
        snprintf(out, max, "%lldB", bytes);
    }
}

static void format_mem_bytes_human(long long bytes, char *out, size_t max) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", bytes);
    format_mem_human(buf, out, max);
}

int cmd_status(int argc, char **argv) {
    const char *filter_name = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: nanorock status [NAME]\n\n"
                   "List running nanorock containers or show status for a specific container.\n\n"
                   "Options:\n"
                   "  -h, --help    Show this help text\n");
            return 0;
        } else if (argv[i][0] != '-') {
            filter_name = argv[i];
        } else {
            fprintf(stderr, "nanorock status: unrecognised option '%s'\n", argv[i]);
            return EXIT_USAGE_ERROR;
        }
    }

    DIR *dir = opendir(NANOROCK_CGROUP_ROOT);
    if (!dir) {
        if (filter_name) {
            fprintf(stderr, "container '%s' is not running\n", filter_name);
            return 1;
        }
        printf("No running containers found.\n");
        return 0;
    }

    struct dirent *entry;
    nanorock_container_info_t containers[64];
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (entry->d_type != DT_DIR) {
            continue;
        }

        nanorock_container_info_t info;
        if (container_info_load(entry->d_name, &info) == 0) {
            if (filter_name && strcmp(info.name, filter_name) != 0) {
                continue;
            }
            if (count < 64) {
                containers[count++] = info;
            }
        }
    }
    closedir(dir);

    if (count == 0) {
        if (filter_name) {
            fprintf(stderr, "container '%s' is not running\n", filter_name);
            return 1;
        }
        printf("No running containers found.\n");
        return 0;
    }

    printf("%-18s %-9s %-9s %-8s %-6s %-16s %-14s %s\n",
           "CONTAINER", "HOST_PID", "CONT_PID", "STATE", "NET", "MEM(CUR/MAX)", "PIDS(CUR/MAX)", "CPU_MAX");

    for (int i = 0; i < count; i++) {
        char cur_mem_str[32], max_mem_str[32], mem_display[128];
        format_mem_bytes_human(containers[i].mem_current, cur_mem_str, sizeof(cur_mem_str));
        format_mem_human(containers[i].mem_max, max_mem_str, sizeof(max_mem_str));
        snprintf(mem_display, sizeof(mem_display), "%s / %s", cur_mem_str, max_mem_str);

        char pids_display[128];
        snprintf(pids_display, sizeof(pids_display), "%lld / %s",
                 containers[i].pids_current, containers[i].pids_max);

        printf("%-18s %-9d %-9d %-8s %-6s %-16s %-14s %s\n",
               containers[i].name,
               (int)containers[i].host_pid,
               (int)containers[i].container_pid,
               containers[i].state,
               containers[i].net_mode,
               mem_display,
               pids_display,
               containers[i].cpu_max);
    }

    return 0;
}

static void json_print_escaped(FILE *out, const char *s) {
    fputc('"', out);
    for (const char *p = s; *p; p++) {
        if (*p == '"') fputs("\\\"", out);
        else if (*p == '\\') fputs("\\\\", out);
        else if (*p == '\b') fputs("\\b", out);
        else if (*p == '\f') fputs("\\f", out);
        else if (*p == '\n') fputs("\\n", out);
        else if (*p == '\r') fputs("\\r", out);
        else if (*p == '\t') fputs("\\t", out);
        else fputc(*p, out);
    }
    fputc('"', out);
}

int cmd_inspect(int argc, char **argv) {
    const char *target_name = NULL;
    bool json_output = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: nanorock inspect <NAME> [--json]\n\n"
                   "Inspect detailed state of a running nanorock container.\n\n"
                   "Options:\n"
                   "  --json        Output machine-readable JSON\n"
                   "  -h, --help    Show this help text\n");
            return 0;
        } else if (argv[i][0] != '-') {
            target_name = argv[i];
        } else {
            fprintf(stderr, "nanorock inspect: unrecognised option '%s'\n", argv[i]);
            return EXIT_USAGE_ERROR;
        }
    }

    if (!target_name) {
        fprintf(stderr, "nanorock inspect requires a container name\n"
                        "Usage: nanorock inspect <NAME> [--json]\n");
        return EXIT_USAGE_ERROR;
    }

    DIR *dir = opendir(NANOROCK_CGROUP_ROOT);
    if (!dir) {
        fprintf(stderr, "container '%s' is not running\n", target_name);
        return 1;
    }

    struct dirent *entry;
    nanorock_container_info_t info;
    bool found = false;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (entry->d_type != DT_DIR) {
            continue;
        }

        if (container_info_load(entry->d_name, &info) == 0) {
            if (strcmp(info.name, target_name) == 0) {
                found = true;
                break;
            }
        }
    }
    closedir(dir);

    if (!found) {
        fprintf(stderr, "container '%s' is not running\n", target_name);
        return 1;
    }

    if (json_output) {
        printf("{\n");
        printf("  \"name\": "); json_print_escaped(stdout, info.name); printf(",\n");
        printf("  \"state\": "); json_print_escaped(stdout, info.state); printf(",\n");
        printf("  \"host_pid\": %d,\n", (int)info.host_pid);
        printf("  \"container_pid\": %d,\n", (int)info.container_pid);
        printf("  \"cgroup_path\": "); json_print_escaped(stdout, info.cgroup_path); printf(",\n");
        printf("  \"hostname\": "); json_print_escaped(stdout, info.hostname); printf(",\n");
        printf("  \"network\": {\n");
        printf("    \"mode\": "); json_print_escaped(stdout, info.net_mode); printf(",\n");
        printf("    \"ip\": "); json_print_escaped(stdout, info.container_ip); printf("\n");
        printf("  },\n");
        printf("  \"resources\": {\n");
        printf("    \"memory_current\": %lld,\n", info.mem_current);
        printf("    \"memory_max\": "); json_print_escaped(stdout, info.mem_max); printf(",\n");
        printf("    \"memory_swap_max\": "); json_print_escaped(stdout, info.mem_swap_max); printf(",\n");
        printf("    \"cpu_max\": "); json_print_escaped(stdout, info.cpu_max); printf(",\n");
        printf("    \"cpu_usage_usec\": %lld,\n", info.cpu_usage_usec);
        printf("    \"pids_current\": %lld,\n", info.pids_current);
        printf("    \"pids_max\": "); json_print_escaped(stdout, info.pids_max); printf("\n");
        printf("  }\n");
        printf("}\n");
    } else {
        printf("Container: %s\n", info.name);
        printf("  State:         %s\n", info.state);
        printf("  Host PID:      %d\n", (int)info.host_pid);
        printf("  Container PID: %d\n", (int)info.container_pid);
        printf("  Cgroup Path:   %s\n", info.cgroup_path);
        printf("  Hostname:      %s\n", info.hostname);
        printf("  Network:\n");
        printf("    Mode:        %s\n", info.net_mode);
        printf("    IP:          %s\n", info.container_ip);
        printf("  Resources:\n");
        printf("    Memory:\n");
        printf("      current:   %lld bytes\n", info.mem_current);
        printf("      max:       %s\n", info.mem_max);
        printf("      swap_max:  %s\n", info.mem_swap_max);
        printf("    CPU:\n");
        printf("      max:       %s\n", info.cpu_max);
        printf("      usage:     %lld usec\n", info.cpu_usage_usec);
        printf("    Processes:\n");
        printf("      current:   %lld\n", info.pids_current);
        printf("      max:       %s\n", info.pids_max);
    }

    return 0;
}
