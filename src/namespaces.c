#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "capabilities.h"
#include "cgroups.h"
#include "error.h"
#include "fd.h"
#include "log.h"
#include "mount_setup.h"
#include "namespaces.h"
#include "network.h"
#include "seccomp_filter.h"

#define CHILD_STACK_SIZE (1024 * 1024)

typedef struct {
    const nanorock_config_t *cfg;
    int p2c_read_fd;
    int p2c_write_fd;
    int c2p_read_fd;
    int c2p_write_fd;
} child_args_t;

/* Runs entirely inside the new namespaces.
 * Performs trusted container setup (hostname, mounts, loopback network, FD hygiene),
 * synchronizes with parent to guarantee cgroup placement before exec,
 * and replaces itself with the requested workload via execvp. */
static int child_main(void *arg) {
    child_args_t *args = (child_args_t *)arg;
    const nanorock_config_t *cfg = args->cfg;
    int p2c_fd = args->p2c_read_fd;
    int c2p_fd = args->c2p_write_fd;

    /* Immediately close parent-side pipe ends in child to prevent pipe leak or deadlock */
    close(args->p2c_write_fd);
    close(args->c2p_read_fd);

    nanorock_error_t err;
    memset(&err, 0, sizeof(err));

    /* 1. Set container hostname in new UTS namespace */
    log_verbose("lifecycle: applying container hostname '%s'", cfg->hostname);
    if (sethostname(cfg->hostname, strlen(cfg->hostname)) != 0) {
        err.phase = ERR_PHASE_HOSTNAME;
        err.err_num = errno;
        snprintf(err.msg, sizeof(err.msg), "failed to set hostname to '%s'", cfg->hostname);
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 2. Setup mount namespace: private mounts, bind rootfs, pivot_root, tmpfs /dev, /proc */
    if (mount_setup_rootfs(cfg, &err) != 0) {
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 3. Bring up loopback interface via native socket ioctl (zero external binary dependencies) */
    if (network_up_lo() != 0) {
        err.phase = ERR_PHASE_NETWORK;
        err.err_num = errno;
        snprintf(err.msg, sizeof(err.msg), "failed to bring up loopback interface");
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 3b. Milestone 7 veth network setup (if enabled) */
    if (cfg->net_mode && strcmp(cfg->net_mode, "veth") == 0) {
        /* Signal parent that child netns is created and ready for veth injection */
        char netns_ready = 'N';
        if (write(c2p_fd, &netns_ready, 1) != 1) {
            _exit(125);
        }

        /* Wait for parent to create veth pair, configure host, and inject peer */
        char net_go = 0;
        if (read(p2c_fd, &net_go, 1) != 1 || net_go != 'N') {
            _exit(125);
        }

        /* Configure container interface eth0 (IP, default route, UP verification) */
        log_verbose("lifecycle: configuring container interface eth0");
        if (network_child_setup(cfg) != 0) {
            err.phase = ERR_PHASE_NETWORK;
            err.err_num = errno;
            snprintf(err.msg, sizeof(err.msg), "failed to configure container interface eth0");
            (void)write(c2p_fd, &err, sizeof(err));
            _exit(125);
        }
    }

    /* 4. FD hygiene: close all open FDs > 2 except our synchronization pipes */
    int keep_fds[2] = { p2c_fd, c2p_fd };
    if (fd_close_except(keep_fds, 2) != 0) {
        err.phase = ERR_PHASE_FD_HYGIENE;
        err.err_num = errno;
        snprintf(err.msg, sizeof(err.msg), "failed to close inherited file descriptors");
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 5. Signal READY to parent so it attaches this PID to the cgroup */
    log_verbose("lifecycle: sending READY signal to parent");
    char ready = 'R';
    if (write(c2p_fd, &ready, 1) != 1) {
        _exit(125);
    }

    /* 6. Wait for parent GO handshake (cgroup placement confirmed) */
    char go = 0;
    if (read(p2c_fd, &go, 1) != 1 || go != 'G') {
        _exit(125);
    }
    close(p2c_fd);

    /* 7. Capability hardening: clear ambient & inheritable, strip bounding set */
    log_verbose("lifecycle: security finalization (capabilities, no_new_privs, seccomp)");
    if (capabilities_drop() != 0) {
        err.phase = ERR_PHASE_CAPABILITIES;
        err.err_num = errno;
        snprintf(err.msg, sizeof(err.msg), "failed to apply capability restrictions");
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 8. Enforce PR_SET_NO_NEW_PRIVS and verify it */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        err.phase = ERR_PHASE_NO_NEW_PRIVS;
        err.err_num = errno;
        snprintf(err.msg, sizeof(err.msg), "failed to set PR_SET_NO_NEW_PRIVS");
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        err.phase = ERR_PHASE_NO_NEW_PRIVS;
        err.err_num = EPERM;
        snprintf(err.msg, sizeof(err.msg), "PR_GET_NO_NEW_PRIVS verification failed");
        (void)write(c2p_fd, &err, sizeof(err));
        _exit(125);
    }

    /* 9. Install raw seccomp-BPF filter (if enabled) */
    if (cfg->seccomp_enabled) {
        if (seccomp_install_filter() != 0) {
            err.phase = ERR_PHASE_SECCOMP;
            err.err_num = errno;
            snprintf(err.msg, sizeof(err.msg), "failed to install seccomp-BPF filter");
            (void)write(c2p_fd, &err, sizeof(err));
            _exit(125);
        }
    }

    /* 10. Request SIGKILL from kernel if host parent terminates prematurely */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
        log_warn("could not set PR_SET_PDEATHSIG: %s", strerror(errno));
    }

    /* 11. Exec user workload.
     * Note: c2p_fd has O_CLOEXEC, so it automatically closes on successful execve. */
    log_verbose("lifecycle: executing workload '%s'", cfg->cmd[0]);
    execvp(cfg->cmd[0], cfg->cmd);

    /* execvp only returns on failure */
    err.phase = ERR_PHASE_EXEC;
    err.err_num = errno;
    snprintf(err.msg, sizeof(err.msg), "failed to exec '%s'", cfg->cmd[0]);
    (void)write(c2p_fd, &err, sizeof(err));
    close(c2p_fd);
    _exit(errno == ENOENT ? 127 : 126);
}

static void cleanup_child(pid_t pid) {
    if (pid <= 0) {
        return;
    }
    kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        /* safely reap child zombie even if interrupted by a signal */
    }
}

pid_t namespaces_launch(const nanorock_config_t *cfg) {
    nanorock_error_t err;
    memset(&err, 0, sizeof(err));

    /* Pre-validate rootfs on host before creating any namespaces or processes */
    if (mount_validate_rootfs(cfg, &err) != 0) {
        log_error("rootfs validation failed: %s (errno: %s)", err.msg, strerror(err.err_num));
        return -1;
    }

    /* Bidirectional synchronization pipes with O_CLOEXEC */
    int p2c[2];
    int c2p[2];
    if (pipe2(p2c, O_CLOEXEC) != 0) {
        log_error("pipe2(p2c) failed: %s", strerror(errno));
        return -1;
    }
    if (pipe2(c2p, O_CLOEXEC) != 0) {
        log_error("pipe2(c2p) failed: %s", strerror(errno));
        close(p2c[0]);
        close(p2c[1]);
        return -1;
    }

    /* Allocate dynamic child stack via mmap with an inaccessible guard page at the bottom */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t total_stack = CHILD_STACK_SIZE + page_size;
    void *stack_base = mmap(NULL, total_stack, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack_base == MAP_FAILED) {
        log_error("mmap child stack failed: %s", strerror(errno));
        close(p2c[0]); close(p2c[1]);
        close(c2p[0]); close(c2p[1]);
        return -1;
    }
    if (mprotect(stack_base, page_size, PROT_NONE) != 0) {
        log_error("mprotect guard page failed: %s", strerror(errno));
        munmap(stack_base, total_stack);
        close(p2c[0]); close(p2c[1]);
        close(c2p[0]); close(c2p[1]);
        return -1;
    }
    void *stack_top = (char *)stack_base + total_stack;

    child_args_t cargs = {
        .cfg = cfg,
        .p2c_read_fd = p2c[0],
        .p2c_write_fd = p2c[1],
        .c2p_read_fd = c2p[0],
        .c2p_write_fd = c2p[1]
    };

    int flags = CLONE_NEWUTS
              | CLONE_NEWPID
              | CLONE_NEWNS
              | CLONE_NEWNET
              | CLONE_NEWIPC
              | SIGCHLD;

    log_verbose("lifecycle: namespace creation (CLONE_NEWUTS|NEWPID|NEWNS|NEWNET|NEWIPC)");
    pid_t pid = clone(child_main, stack_top, flags, (void *)&cargs);
    if (pid < 0) {
        log_error("clone() failed: %s - nanorock needs CAP_SYS_ADMIN (run as root)", strerror(errno));
        munmap(stack_base, total_stack);
        close(p2c[0]); close(p2c[1]);
        close(c2p[0]); close(c2p[1]);
        return -1;
    }

    /* Parent closes ends used by child */
    close(p2c[0]);
    close(c2p[1]);

    /* If veth networking is enabled, handle netns synchronization */
    if (cfg->net_mode && strcmp(cfg->net_mode, "veth") == 0) {
        char net_buf[sizeof(nanorock_error_t)];
        memset(net_buf, 0, sizeof(net_buf));
        ssize_t net_n = read(c2p[0], net_buf, sizeof(net_buf));
        if (net_n <= 0) {
            log_error("container initialization aborted unexpectedly before netns ready");
            network_host_cleanup(cfg->host_veth);
            close(p2c[1]);
            close(c2p[0]);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }

        if (net_n != 1 || net_buf[0] != 'N') {
            /* Child sent a structured error during rootfs or loopback setup */
            nanorock_error_t *child_err = (nanorock_error_t *)net_buf;
            log_error("container initialization failed at phase [%s]: %s (errno: %s)",
                      nanorock_phase_str(child_err->phase),
                      child_err->msg, strerror(child_err->err_num));
            network_host_cleanup(cfg->host_veth);
            close(p2c[1]);
            close(c2p[0]);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }

        /* Child netns is ready; perform host-side network setup */
        log_verbose("lifecycle: network setup (host veth injection for pid %d)", pid);
        if (network_host_setup(pid, (nanorock_config_t *)cfg) != 0) {
            log_error("host network setup failed for container");
            network_host_cleanup(cfg->host_veth);
            close(p2c[1]);
            close(c2p[0]);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }

        /* Signal child that veth peer has been injected into its netns */
        char net_go = 'N';
        if (write(p2c[1], &net_go, 1) != 1) {
            log_error("failed to send network GO handshake to child");
            network_host_cleanup(cfg->host_veth);
            close(p2c[1]);
            close(c2p[0]);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }
    }

    /* Parent waits for child READY signal or error payload */
    char buf[sizeof(nanorock_error_t)];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(c2p[0], buf, sizeof(buf));
    if (n <= 0) {
        log_error("container initialization aborted unexpectedly before ready");
        network_host_cleanup(cfg->host_veth);
        close(p2c[1]);
        close(c2p[0]);
        munmap(stack_base, total_stack);
        cleanup_child(pid);
        return -1;
    }

    if (n == 1 && buf[0] == 'R') {
        log_verbose("lifecycle: container READY signal received");

        /* Child is ready! Attach child PID to cgroup */
        log_verbose("lifecycle: cgroup placement pid %d into %s", pid, cfg->cgroup_path);
        if (cgroup_add_pid(cfg, pid) != 0) {
            log_error("failed to attach container pid to cgroup");
            network_host_cleanup(cfg->host_veth);
            close(p2c[1]);
            close(c2p[0]);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }
        log_verbose("lifecycle: cgroup verification succeeded");

        /* Send GO signal to child */
        log_verbose("lifecycle: GO signal sent to container");
        char go = 'G';
        if (write(p2c[1], &go, 1) != 1) {
            log_error("failed to send GO handshake to child");
        }
        close(p2c[1]);

        /* Wait for execve completion (indicated by c2p closing via O_CLOEXEC) */
        nanorock_error_t exec_err;
        memset(&exec_err, 0, sizeof(exec_err));
        ssize_t exec_n = read(c2p[0], &exec_err, sizeof(exec_err));
        close(c2p[0]);

        if (exec_n > 0) {
            /* execvp failed in child */
            log_error("container failed at phase [%s]: %s (errno: %s)",
                      nanorock_phase_str(exec_err.phase),
                      exec_err.msg, strerror(exec_err.err_num));
            network_host_cleanup(cfg->host_veth);
            munmap(stack_base, total_stack);
            cleanup_child(pid);
            return -1;
        }

        /* execvp succeeded: child VM address space replaced; unmap clone stack */
        log_verbose("lifecycle: workload exec succeeded");
        munmap(stack_base, total_stack);
        return pid;
    }

    /* Child sent a structured error during setup */
    nanorock_error_t *child_err = (nanorock_error_t *)buf;
    log_error("container initialization failed at phase [%s]: %s (errno: %s)",
              nanorock_phase_str(child_err->phase),
              child_err->msg, strerror(child_err->err_num));

    network_host_cleanup(cfg->host_veth);
    close(p2c[1]);
    close(c2p[0]);
    munmap(stack_base, total_stack);
    cleanup_child(pid);
    return -1;
}
