#ifndef NANOROCK_NAMESPACES_H
#define NANOROCK_NAMESPACES_H

#include <sys/types.h>

#include "config.h"

/* Clones a new process directly into fresh UTS, PID, mount, network and
 * IPC namespaces and runs the container's init sequence inside it
 * (hostname, rootfs, capability drop, then execve of cfg->cmd).
 *
 * Returns the child's pid as seen from the *caller's* PID namespace
 * (needed to add it to a cgroup and waitpid() on it), or -1 on error. */
pid_t namespaces_launch(const nanorock_config_t *cfg);

#endif /* NANOROCK_NAMESPACES_H */
