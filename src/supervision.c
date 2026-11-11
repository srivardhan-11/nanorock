#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "supervision.h"

/* Atomic flags recording pending forwardable signals.
 * Handled with 100% async-signal-safety (no heap, no syscalls, no I/O). */
static volatile sig_atomic_t g_pending_sigint = 0;
static volatile sig_atomic_t g_pending_sigterm = 0;
static volatile sig_atomic_t g_pending_sighup = 0;
static volatile sig_atomic_t g_pending_sigquit = 0;

/* Saved original host signal handlers */
static struct sigaction g_orig_sigint;
static struct sigaction g_orig_sigterm;
static struct sigaction g_orig_sighup;
static struct sigaction g_orig_sigquit;
static int g_handlers_installed = 0;

/* Pure async-signal-safe handler: sets atomic flag only */
static void supervisor_signal_handler(int signo) {
    switch (signo) {
    case SIGINT:  g_pending_sigint = 1;  break;
    case SIGTERM: g_pending_sigterm = 1; break;
    case SIGHUP:  g_pending_sighup = 1;  break;
    case SIGQUIT: g_pending_sigquit = 1; break;
    default: break;
    }
}

int supervision_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal_handler;
    sigemptyset(&sa.sa_mask);
    /* Crucial: do NOT specify SA_RESTART so that blocking syscalls (waitpid)
     * are interrupted and return -1 with EINTR, allowing the supervision loop
     * to immediately forward the signal. */
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, &g_orig_sigint) != 0 ||
        sigaction(SIGTERM, &sa, &g_orig_sigterm) != 0 ||
        sigaction(SIGHUP, &sa, &g_orig_sighup) != 0 ||
        sigaction(SIGQUIT, &sa, &g_orig_sigquit) != 0) {
        log_error("failed to install supervision signal handlers: %s", strerror(errno));
        return -1;
    }

    g_handlers_installed = 1;
    return 0;
}

void supervision_cleanup(void) {
    if (!g_handlers_installed) {
        return;
    }
    sigaction(SIGINT, &g_orig_sigint, NULL);
    sigaction(SIGTERM, &g_orig_sigterm, NULL);
    sigaction(SIGHUP, &g_orig_sighup, NULL);
    sigaction(SIGQUIT, &g_orig_sigquit, NULL);
    g_handlers_installed = 0;
}

/* Forwards any captured pending signals to child_pid */
static void forward_pending_signals(pid_t child_pid) {
    if (g_pending_sigterm) {
        g_pending_sigterm = 0;
        log_info("forwarding SIGTERM to container pid %d", child_pid);
        if (kill(child_pid, SIGTERM) != 0 && errno != ESRCH) {
            log_warn("failed to forward SIGTERM to pid %d: %s", child_pid, strerror(errno));
        }
    }
    if (g_pending_sigint) {
        g_pending_sigint = 0;
        log_info("forwarding SIGINT to container pid %d", child_pid);
        if (kill(child_pid, SIGINT) != 0 && errno != ESRCH) {
            log_warn("failed to forward SIGINT to pid %d: %s", child_pid, strerror(errno));
        }
    }
    if (g_pending_sighup) {
        g_pending_sighup = 0;
        log_info("forwarding SIGHUP to container pid %d", child_pid);
        if (kill(child_pid, SIGHUP) != 0 && errno != ESRCH) {
            log_warn("failed to forward SIGHUP to pid %d: %s", child_pid, strerror(errno));
        }
    }
    if (g_pending_sigquit) {
        g_pending_sigquit = 0;
        log_info("forwarding SIGQUIT to container pid %d", child_pid);
        if (kill(child_pid, SIGQUIT) != 0 && errno != ESRCH) {
            log_warn("failed to forward SIGQUIT to pid %d: %s", child_pid, strerror(errno));
        }
    }
}

int supervision_wait(pid_t child_pid, int *out_status) {
    int status = 0;

    while (1) {
        /* Check and forward any signals that arrived before waitpid() was entered */
        forward_pending_signals(child_pid);

        pid_t w = waitpid(child_pid, &status, 0);
        if (w == child_pid) {
            /* Container workload PID 1 terminated */
            *out_status = status;
            supervision_cleanup();
            return 0;
        }

        if (w < 0) {
            if (errno == EINTR) {
                /* waitpid was interrupted by a forwarded signal handler.
                 * Forward the pending signals and resume waiting. */
                forward_pending_signals(child_pid);
                continue;
            }

            /* Unexpected waitpid error */
            log_error("waitpid failed for pid %d: %s", child_pid, strerror(errno));
            supervision_cleanup();
            return -1;
        }
    }
}

int supervision_translate_status(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 0;
}

int supervision_get_received_signal(void) {
    if (g_pending_sigterm) return SIGTERM;
    if (g_pending_sigint) return SIGINT;
    if (g_pending_sighup) return SIGHUP;
    if (g_pending_sigquit) return SIGQUIT;
    return 0;
}
