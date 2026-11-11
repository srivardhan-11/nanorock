#ifndef NANOROCK_CGROUPS_H
#define NANOROCK_CGROUPS_H

#include <sys/types.h>

#include "config.h"

/* Validates that a container name conforms to the strict naming grammar:
 * [a-zA-Z0-9_.-], length between 1 and 64, cannot be "." or "..",
 * cannot start with '-' or '.', cannot contain path separators ('/', '\').
 * Returns 0 if valid, -1 if invalid (errno set to EINVAL or ENAMETOOLONG). */
int cgroup_validate_name(const char *name);

/* Creates a uniquely named cgroup directory (/sys/fs/cgroup/nanorock/<name>-<pid>),
 * enables required controllers, writes requested limits, and verifies
 * all limits by reading them back. Fails closed if any requested controller
 * or limit cannot be established.
 * Sets cfg->cgroup_path and cfg->cgroup_owned on success.
 * Returns 0 on success, -1 on error. */
int cgroup_create(nanorock_config_t *cfg);

/* Moves the given pid into the container's cgroup and verifies membership
 * by reading cgroup.procs back.
 * Returns 0 on success, -1 on error. */
int cgroup_add_pid(const nanorock_config_t *cfg, pid_t pid);

/* Terminates any remaining container processes using cgroup.kill (or fallback SIGKILL),
 * drains the cgroup, and removes the cgroup directory if owned by this invocation. */
void cgroup_cleanup(nanorock_config_t *cfg);

#endif /* NANOROCK_CGROUPS_H */
