#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroups.h"
#include "config.h"
#include "log.h"
#include "mount_setup.h"
#include "namespaces.h"
#include "network.h"
#include "status.h"
#include "supervision.h"

/*
 * nanorock: Minimal Linux container runtime in C.
 *
 * Architecture Overview:
 * - The host-side process serves as supervisor.
 * - The workload executes as PID 1 inside the container PID namespace.
 * - No background daemon, no database, no in-container init wrapper.
 * - Lifecycle:
 *     VALIDATE -> CGROUP_CREATE -> NAMESPACES_LAUNCH -> READY handshake ->
 *     CGROUP_ATTACH & VERIFY -> GO handshake -> WORKLOAD EXEC -> SUPERVISE -> CLEANUP
 */

static void print_version(void) {
    printf("nanorock %s\n", NANOROCK_VERSION);
}

static void print_help(const char *prog) {
    printf(
        "nanorock %s - a minimal Linux container runtime built from raw kernel primitives\n\n"
        "Usage:\n"
        "  %s [GLOBAL OPTIONS]\n"
        "  %s run [OPTIONS] -- COMMAND [ARG...]\n"
        "  %s status [NAME]\n"
        "  %s inspect <NAME> [--json]\n\n"
        "Commands:\n"
        "  run                      Run a command inside a new isolated container\n"
        "  status                   List running containers and their resource usage\n"
        "  inspect                  Show detailed inspection of a running container\n\n"
        "Global Options:\n"
        "  -h, --help               Show this help text and exit\n"
        "  -V, --version            Show version information and exit\n\n"
        "Run Options:\n"
        "  --rootfs PATH            Path to the container root filesystem (required)\n"
        "  --hostname NAME          Hostname inside the container (default: nanorock)\n"
        "  --name NAME              Container / cgroup instance name (default: default)\n"
        "  --mem MB                 Memory limit in megabytes (default: unlimited)\n"
        "  --cpu PERCENT            CPU limit as %% of one core, e.g. 50 (default: unlimited)\n"
        "  --pids-max N             Maximum number of processes in container (default: unlimited)\n"
        "  --net MODE               Network mode: 'veth' (default) or 'none' (loopback only)\n"
        "  --ip ADDR                Container IPv4 address (default: 10.200.0.2)\n"
        "  --host-ip ADDR           Host veth IPv4 address (default: 10.200.0.1)\n"
        "  --net-prefix N           CIDR subnet prefix length, e.g. 24 (default: 24)\n"
        "  -v, --verbose            Enable diagnostic runtime logging (default: disabled)\n"
        "  --no-seccomp             Disable seccomp-BPF filter (INSECURE: debug/testing only)\n"
        "  -h, --help               Show this help text and exit\n\n"
        "Exit Status Policy:\n"
        "  Workload exited:         Preserves workload exit code (0..255)\n"
        "  Workload signaled:       128 + signal number (e.g. 130 for SIGINT, 143 for SIGTERM)\n"
        "  CLI usage error:         2 (invalid option, missing argument, malformed input)\n"
        "  Runtime/setup failure:   1 (failed namespace, mount, cgroup, or supervision setup)\n\n"
        "Examples:\n"
        "  # Run an interactive shell\n"
        "  sudo %s run --rootfs ./rootfs -- /bin/sh\n\n"
        "  # Run a named container with custom hostname\n"
        "  sudo %s run --rootfs ./rootfs --name demo --hostname demo-box -- /bin/sh\n\n"
        "  # List running containers\n"
        "  sudo %s status\n\n"
        "  # Inspect running container in JSON format\n"
        "  sudo %s inspect demo --json\n",
        NANOROCK_VERSION, prog, prog, prog, prog, prog, prog, prog, prog);
}

static long parse_long_or_die(const char *s, const char *flag) {
    if (s == NULL || *s == '\0') {
        die_with_code(EXIT_USAGE_ERROR, "invalid value for %s: '' (must be a positive integer)", flag);
    }
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v <= 0) {
        die_with_code(EXIT_USAGE_ERROR, "invalid value for %s: '%s' (must be a positive integer)", flag, s);
    }
    return v;
}

static int validate_hostname(const char *hostname) {
    if (hostname == NULL || hostname[0] == '\0') {
        return -1;
    }
    size_t len = strlen(hostname);
    if (len > 64) {
        return -1;
    }
    if (hostname[0] == '-' || hostname[0] == '.' ||
        hostname[len - 1] == '-' || hostname[len - 1] == '.') {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)hostname[i];
        if (!(isalnum(c) || c == '-' || c == '.')) {
            return -1;
        }
        if (i > 0 && hostname[i] == '.' && hostname[i - 1] == '.') {
            return -1;
        }
    }
    return 0;
}

static void parse_cli(int argc, char **argv, nanorock_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->hostname = "nanorock";
    cfg->container_name = "default";
    cfg->seccomp_enabled = true;
    cfg->verbose = false;
    cfg->net_mode = "veth";
    cfg->container_ip = "10.200.0.2";
    cfg->host_ip = "10.200.0.1";
    cfg->net_prefix = 24;

    /* 'nanorock run' subcommand arguments */
    int i = 2;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            exit(0);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = true;
            log_set_verbose(1);
        } else if (strcmp(argv[i], "--no-seccomp") == 0) {
            cfg->seccomp_enabled = false;
        } else if (strcmp(argv[i], "--rootfs") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--rootfs' requires an argument");
            }
            cfg->rootfs = argv[++i];
        } else if (strcmp(argv[i], "--hostname") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--hostname' requires an argument");
            }
            cfg->hostname = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--name' requires an argument");
            }
            cfg->container_name = argv[++i];
        } else if (strcmp(argv[i], "--mem") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--mem' requires an argument");
            }
            long mem = parse_long_or_die(argv[++i], "--mem");
            if (mem > 1048576) {
                die_with_code(EXIT_USAGE_ERROR, "invalid value for --mem: '%ld' (exceeds max 1048576)", mem);
            }
            cfg->mem_limit_mb = mem;
        } else if (strcmp(argv[i], "--cpu") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--cpu' requires an argument");
            }
            long cpu = parse_long_or_die(argv[++i], "--cpu");
            if (cpu > 100000) {
                die_with_code(EXIT_USAGE_ERROR, "invalid value for --cpu: '%ld' (exceeds max 100000)", cpu);
            }
            cfg->cpu_quota_pct = (int)cpu;
        } else if (strcmp(argv[i], "--pids-max") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--pids-max' requires an argument");
            }
            long pids = parse_long_or_die(argv[++i], "--pids-max");
            if (pids > 4194304) {
                die_with_code(EXIT_USAGE_ERROR, "invalid value for --pids-max: '%ld' (exceeds max 4194304)", pids);
            }
            cfg->pids_max = (int)pids;
        } else if (strcmp(argv[i], "--net") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--net' requires an argument");
            }
            const char *mode = argv[++i];
            if (strcmp(mode, "veth") != 0 && strcmp(mode, "none") != 0) {
                die_with_code(EXIT_USAGE_ERROR, "invalid network mode: '%s' (expected 'veth' or 'none')", mode);
            }
            cfg->net_mode = (char *)mode;
        } else if (strcmp(argv[i], "--ip") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--ip' requires an argument");
            }
            const char *ip = argv[++i];
            if (network_validate_ip(ip) != 0) {
                die_with_code(EXIT_USAGE_ERROR, "invalid container IP address: '%s'", ip);
            }
            cfg->container_ip = (char *)ip;
        } else if (strcmp(argv[i], "--host-ip") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--host-ip' requires an argument");
            }
            const char *ip = argv[++i];
            if (network_validate_ip(ip) != 0) {
                die_with_code(EXIT_USAGE_ERROR, "invalid host IP address: '%s'", ip);
            }
            cfg->host_ip = (char *)ip;
        } else if (strcmp(argv[i], "--net-prefix") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                die_with_code(EXIT_USAGE_ERROR, "option '--net-prefix' requires an argument");
            }
            long p = parse_long_or_die(argv[++i], "--net-prefix");
            if (network_validate_prefix((int)p) != 0) {
                die_with_code(EXIT_USAGE_ERROR, "invalid network prefix: '%ld' (must be 1-30)", p);
            }
            cfg->net_prefix = (int)p;
        } else {
            print_help(argv[0]);
            die_with_code(EXIT_USAGE_ERROR, "unrecognised option: %s", argv[i]);
        }
    }

    if (cfg->rootfs == NULL) {
        print_help(argv[0]);
        die_with_code(EXIT_USAGE_ERROR, "--rootfs is required");
    }

    if (cgroup_validate_name(cfg->container_name) != 0) {
        die_with_code(EXIT_USAGE_ERROR,
            "invalid container name '%s' (must be 1-64 alphanumeric, '_', '-', '.')",
            cfg->container_name);
    }

    if (validate_hostname(cfg->hostname) != 0) {
        die_with_code(EXIT_USAGE_ERROR,
            "invalid hostname '%s' (must be 1-64 alphanumeric/hyphen/dot, not starting/ending with hyphen/dot)",
            cfg->hostname);
    }

    int cmd_argc = 0;
    for (; i < argc && cmd_argc < MAX_CMD_ARGS - 1; i++, cmd_argc++) {
        cfg->cmd[cmd_argc] = argv[i];
    }
    cfg->cmd[cmd_argc] = NULL;
    cfg->cmd_argc = cmd_argc;

    if (cmd_argc == 0) {
        print_help(argv[0]);
        die_with_code(EXIT_USAGE_ERROR, "no command given - put it after '--', e.g. ... -- /bin/sh");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_help(argv[0]);
        exit(EXIT_USAGE_ERROR);
    }

    /* Top-level global flags: nanorock --help, nanorock -h, nanorock --version, nanorock -V */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        exit(0);
    }
    if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0) {
        print_version();
        exit(0);
    }

    if (strcmp(argv[1], "status") == 0) {
        return cmd_status(argc - 1, argv + 1);
    }

    if (strcmp(argv[1], "inspect") == 0) {
        return cmd_inspect(argc - 1, argv + 1);
    }

    if (strcmp(argv[1], "run") != 0) {
        print_help(argv[0]);
        die_with_code(EXIT_USAGE_ERROR, "unrecognised command: '%s' (expected 'run', 'status', or 'inspect')", argv[1]);
    }

    nanorock_config_t cfg;
    parse_cli(argc, argv, &cfg);

    if (geteuid() != 0) {
        die_with_code(EXIT_RUNTIME_ERROR,
            "nanorock must run as root (it needs CAP_SYS_ADMIN to create namespaces) - try sudo");
    }

    log_info("launching container '%s' (rootfs=%s, hostname=%s)",
              cfg.container_name, cfg.rootfs, cfg.hostname);

    if (cfg.verbose) {
        log_verbose("configuration: name=%s hostname=%s rootfs=%s",
                    cfg.container_name, cfg.hostname, cfg.rootfs);
        log_verbose("resource limits: mem=%ldMB cpu=%d%% pids=%d",
                    cfg.mem_limit_mb, cfg.cpu_quota_pct, cfg.pids_max);
        log_verbose("lifecycle: configuration validated");
    }

    if (!cfg.seccomp_enabled) {
        log_warn("running in insecure mode: seccomp-BPF filter is DISABLED");
    }

    log_verbose("lifecycle: validating rootfs at '%s'", cfg.rootfs);
    nanorock_error_t rootfs_err;
    memset(&rootfs_err, 0, sizeof(rootfs_err));
    if (mount_validate_rootfs(&cfg, &rootfs_err) != 0) {
        log_error("rootfs validation failed: %s (errno: %s)",
                  rootfs_err.msg, strerror(rootfs_err.err_num));
        errno = rootfs_err.err_num;
        die_with_code(EXIT_RUNTIME_ERROR, "failed to validate rootfs");
    }
    log_verbose("lifecycle: rootfs validation succeeded");

    log_verbose("lifecycle: creating cgroup hierarchy");
    if (cgroup_create(&cfg) != 0) {
        die_with_code(EXIT_RUNTIME_ERROR, "failed to setup cgroup v2");
    }
    log_verbose("lifecycle: cgroup v2 ready at %s", cfg.cgroup_path);

    if (supervision_init() != 0) {
        cgroup_cleanup(&cfg);
        die_with_code(EXIT_RUNTIME_ERROR, "failed to initialize process supervision");
    }

    log_verbose("lifecycle: creating container namespaces");
    pid_t pid = namespaces_launch(&cfg);
    if (pid < 0) {
        int sig = supervision_get_received_signal();
        supervision_cleanup();
        cgroup_cleanup(&cfg);
        network_host_cleanup(cfg.host_veth);
        if (sig > 0) {
            log_warn("container launch aborted by signal %d (%s)", sig, strsignal(sig));
            exit(128 + sig);
        }
        die_with_code(EXIT_RUNTIME_ERROR, "failed to launch container");
    }

    log_info("container '%s' running as pid %d (cgroup: %s)",
             cfg.container_name, pid, cfg.cgroup_path);

    int status = 0;
    if (supervision_wait(pid, &status) != 0) {
        int sig = supervision_get_received_signal();
        cgroup_cleanup(&cfg);
        network_host_cleanup(cfg.host_veth);
        if (sig > 0) {
            exit(128 + sig);
        }
        die_with_code(EXIT_RUNTIME_ERROR, "supervision wait failed");
    }

    log_verbose("lifecycle: workload exited (raw status: 0x%x)", status);

    /* 1. Primary workload terminated: clean up cgroup and drain any lingering descendants */
    log_verbose("lifecycle: cleaning up cgroup hierarchy");
    cgroup_cleanup(&cfg);
    log_verbose("lifecycle: cgroup cleanup complete");

    /* 2. Clean up host-side network interface (veth) */
    log_verbose("lifecycle: cleaning up network host interfaces");
    network_host_cleanup(cfg.host_veth);
    log_verbose("lifecycle: network cleanup complete");

    /* 3. Translate workload status into container runtime exit code */
    int exit_code = supervision_translate_status(status);
    if (WIFEXITED(status)) {
        log_info("container '%s' exited with code %d", cfg.container_name, exit_code);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        log_warn("container '%s' was killed by signal %d (%s)",
                 cfg.container_name, sig, strsignal(sig));
    }

    return exit_code;
}
