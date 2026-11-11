#ifndef NANOROCK_CONFIG_H
#define NANOROCK_CONFIG_H

#include <stdbool.h>

#define NANOROCK_VERSION "0.1.0"

/* Predictable exit code policy */
#define EXIT_WORKLOAD_DEFAULT 0
#define EXIT_USAGE_ERROR      2
#define EXIT_RUNTIME_ERROR    1

#define MAX_CMD_ARGS 64

/* Everything the rest of nanorock needs to know about the container
 * that is about to be launched. Populated once in main.c by
 * parse_args() and then treated as read-only everywhere else. */
typedef struct {
    char *rootfs;           /* required: path to the container's root filesystem   */
    char *hostname;         /* UTS namespace hostname, default "nanorock"          */
    char *container_name;   /* base name for container (default: "default")        */

    char cgroup_path[512];  /* unique path to container cgroup v2 directory        */
    bool cgroup_owned;      /* true if this process created and owns the cgroup    */

    long mem_limit_mb;      /* 0 = unlimited                                       */
    int  cpu_quota_pct;     /* 0 = unlimited, otherwise % of a single core (1-100+) */
    int  pids_max;          /* 0 = unlimited                                       */

    bool seccomp_enabled;   /* enable seccomp-BPF syscall filter                   */
    bool verbose;           /* verbose logging output                              */

    /* Network configuration (Milestone 7) */
    char *net_mode;         /* "veth" (default) or "none"                          */
    char *container_ip;     /* IPv4 address for container eth0 (default: 10.200.0.2) */
    char *host_ip;          /* IPv4 address for host veth (default: 10.200.0.1)    */
    int   net_prefix;       /* CIDR prefix length (default: 24)                    */
    char  host_veth[16];    /* generated host-side veth name, e.g. "nr-veth-<pid>" */

    char *cmd[MAX_CMD_ARGS];/* argv-style, NULL terminated, for execvp             */
    int   cmd_argc;
} nanorock_config_t;

#endif /* NANOROCK_CONFIG_H */
