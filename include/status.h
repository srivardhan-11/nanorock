#ifndef NANOROCK_STATUS_H
#define NANOROCK_STATUS_H

#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    char name[65];
    pid_t host_pid;
    pid_t container_pid;
    char state[32];
    char cgroup_path[512];
    char hostname[65];
    char net_mode[16];
    char container_ip[32];

    long long mem_current;
    char mem_max[64];
    char mem_swap_max[64];
    long long pids_current;
    char pids_max[64];
    char cpu_max[64];
    long long cpu_usage_usec;
} nanorock_container_info_t;

/* Execute 'nanorock status [NAME]' command. Returns 0 on success, 1 on error. */
int cmd_status(int argc, char **argv);

/* Execute 'nanorock inspect <NAME> [--json]' command. Returns 0 on success, 1 on error. */
int cmd_inspect(int argc, char **argv);

#endif /* NANOROCK_STATUS_H */
