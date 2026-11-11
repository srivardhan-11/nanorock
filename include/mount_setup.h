#ifndef NANOROCK_MOUNT_SETUP_H
#define NANOROCK_MOUNT_SETUP_H

#include "config.h"
#include "error.h"

/* Validates cfg->rootfs before any mutation.
 * Checks path resolution, forbids host root / or critical mounts,
 * verifies directory type and accessibility.
 * Returns 0 if valid, -1 on error (with err populated). */
int mount_validate_rootfs(const nanorock_config_t *cfg, nanorock_error_t *err);

/* Makes the mount namespace private, bind-mounts rootfs, pivot_roots into cfg->rootfs,
 * detaches old root (failing closed on error), mounts a fresh /proc, and seeds
 * a minimal /dev on a private in-memory tmpfs.
 * Must be called from inside the new mount + PID namespace.
 * Returns 0 on success, -1 on error (with err populated). */
int mount_setup_rootfs(const nanorock_config_t *cfg, nanorock_error_t *err);

#endif /* NANOROCK_MOUNT_SETUP_H */
