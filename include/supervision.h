#ifndef NANOROCK_SUPERVISION_H
#define NANOROCK_SUPERVISION_H

#include <sys/types.h>

/* Installs async-signal-safe handlers for forwardable signals:
 * SIGINT, SIGTERM, SIGHUP, SIGQUIT.
 * Uses sa_flags = 0 (no SA_RESTART) so waitpid() is interrupted with EINTR.
 * Returns 0 on success, -1 on failure. */
int supervision_init(void);

/* Supervises container child process:
 * Loops waitpid() handling EINTR safely and forwarding any intercepted
 * signals to child_pid.
 * Populates out_status with the child's waitpid termination status.
 * Restores original signal handlers upon return.
 * Returns 0 on success, -1 on unexpected waitpid error. */
int supervision_wait(pid_t child_pid, int *out_status);

/* Restores original host signal handlers if installed. */
void supervision_cleanup(void);

/* Translates waitpid status into the standard shell exit code:
 * - WIFEXITED(status): returns WEXITSTATUS(status)
 * - WIFSIGNALED(status): returns 128 + WTERMSIG(status)
 * - Otherwise: returns 0 */
int supervision_translate_status(int status);

/* Returns the signal number if a forwardable signal was captured, or 0 if none */
int supervision_get_received_signal(void);

#endif /* NANOROCK_SUPERVISION_H */
